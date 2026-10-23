"""Tiny real Thumb payloads used to exercise the Qiling target in tests."""

from __future__ import annotations

import struct
from uuid import UUID

from .hardware import GPIO_P0_IN


TEST_APPLICATION_SERVICE_UUID = "5a1c2001-7c5d-4c8d-942c-a786c1d58b6d"
TEST_APPLICATION_VALUE_UUID = "5a1c2002-7c5d-4c8d-942c-a786c1d58b6d"


def _thumb_ldr_literal(register: int, instruction_address: int, literal_address: int) -> int:
    pc = (instruction_address + 4) & ~3
    displacement = literal_address - pc
    if not 0 <= register <= 7 or displacement < 0 or displacement % 4:
        raise ValueError("invalid Thumb literal load")
    word_offset = displacement // 4
    if word_offset > 0xFF:
        raise ValueError("payload is too large for a Thumb literal load")
    return 0x4800 | (register << 8) | word_offset


def _vendor_base_and_short_uuids(service_uuid: str, value_uuid: str) -> tuple[bytes, int, int]:
    service = bytearray(reversed(UUID(service_uuid).bytes))
    value = bytearray(reversed(UUID(value_uuid).bytes))
    service_short = int.from_bytes(service[12:14], "little")
    value_short = int.from_bytes(value[12:14], "little")
    service[12:14] = b"\x00\x00"
    value[12:14] = b"\x00\x00"
    if service != value:
        raise ValueError("service and value UUIDs must share one vendor base")
    return bytes(service), service_short, value_short


def make_gpio_gatt_payload(
    bytes_to_read: int,
    *,
    application_base: int = 0x0001_B000,
    initial_sp: int = 0x2000_8000,
    service_uuid: str = TEST_APPLICATION_SERVICE_UUID,
    value_uuid: str = TEST_APPLICATION_VALUE_UUID,
) -> bytes:
    """Build Thumb firmware that exposes GPIO bytes in its own read-only GATT value.

    The image is freestanding and calls the Nordic S130 ABI directly. It first
    copies words from ``P0.IN`` into SRAM, then invokes vendor UUID, primary
    service, and characteristic registration SVCs. No host-defined output UUID
    or UART bridge is involved.
    """

    if bytes_to_read <= 0 or bytes_to_read % 4:
        raise ValueError("bytes_to_read must be a positive multiple of four")
    words = bytes_to_read // 4
    if words > 0xFF or bytes_to_read > 512:
        raise ValueError("bytes_to_read exceeds the compact payload limit")

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
    instructions.extend((0x2200 | words, 0x6803, 0x600B, 0x3104, 0x3A01, 0xD1FA))
    literal(0, "base_uuid")
    literal(1, "uuid_type_output")
    instructions.append(0xDF63)  # svc #0x63: sd_ble_uuid_vs_add
    instructions.append(0x2001)  # movs r0, #BLE_GATTS_SRVC_TYPE_PRIMARY
    literal(1, "service_uuid")
    literal(2, "service_handle_output")
    instructions.append(0xDFA0)  # svc #0xa0: sd_ble_gatts_service_add
    literal(0, "service_handle_output")
    instructions.append(0x8800)  # ldrh r0, [r0]
    literal(1, "char_md")
    literal(2, "attribute")
    literal(3, "characteristic_handles_output")
    instructions.extend((0xDFA2, 0xE7FE))  # characteristic_add; b .

    code = bytearray(struct.pack(f"<{len(instructions)}H", *instructions))
    while len(code) % 4:
        code.extend(b"\x00")
    literal_pool_offset = code_offset + len(code)

    literal_labels = [
        "gpio",
        "flag_buffer",
        "base_uuid",
        "uuid_type_output",
        "service_uuid",
        "service_handle_output",
        "char_md",
        "attribute",
        "characteristic_handles_output",
    ]
    literal_offsets = {
        label: literal_pool_offset + index * 4
        for index, label in enumerate(literal_labels)
    }
    data_offset = literal_pool_offset + 4 * len(literal_labels)
    base_uuid, service_short, value_short = _vendor_base_and_short_uuids(
        service_uuid, value_uuid
    )

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
    for label in literal_labels:
        code.extend(struct.pack("<I", addresses[label]))
    for index, register, label in literal_uses:
        instruction_address = code_address + index * 2
        literal_address = application_base + literal_offsets[label]
        struct.pack_into(
            "<H",
            code,
            index * 2,
            _thumb_ldr_literal(register, instruction_address, literal_address),
        )

    data = bytearray(base_uuid)
    data.extend(struct.pack("<HBx", service_short, 2))
    data.extend(struct.pack("<HBx", value_short, 2))
    data.extend(b"\x02\x00\x00\x00")  # char metadata: read property
    data.extend(b"\x01\x00\x00\x00")  # open read, no write, no authorization
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

    vector_table = struct.pack("<II", initial_sp, code_address + 1)
    image = (
        vector_table
        + b"\xff" * (code_offset - len(vector_table))
        + bytes(code)
        + bytes(data)
    )
    return image + b"\xff" * (-len(image) % 4)


def make_gpio_probe_payload(
    application_base: int = 0x0001_B000,
    initial_sp: int = 0x2000_8000,
) -> bytes:
    """Compatibility helper for a one-word GATT-exporting payload."""

    return make_gpio_gatt_payload(
        4, application_base=application_base, initial_sp=initial_sp
    )


def make_gpio_dump_payload(
    bytes_to_read: int,
    *,
    application_base: int = 0x0001_B000,
    initial_sp: int = 0x2000_8000,
) -> bytes:
    """Compatibility helper for a multi-word GATT-exporting payload."""

    return make_gpio_gatt_payload(
        bytes_to_read,
        application_base=application_base,
        initial_sp=initial_sp,
    )
