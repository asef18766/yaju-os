"""Tiny real Thumb payloads used to exercise the Qiling target in tests."""

from __future__ import annotations

import struct

from .hardware import GPIO_P0_IN, UART0_TXD


def make_gpio_probe_payload(
    application_base: int = 0x0001_B000,
    initial_sp: int = 0x2000_8000,
) -> bytes:
    """Return a Thumb image that reads P0.IN then writes the word to UART0.TXD.

    The instructions are deliberately small and standalone, rather than relying
    on a compiler/toolchain in the test environment:

    * `ldr r0, =GPIO_P0_IN`
    * `ldr r1, [r0]`
    * `ldr r0, =UART0_TXD`
    * `str r1, [r0]`
    * loop forever
    """

    code_offset = 0x100
    reset_handler = application_base + code_offset + 1  # Cortex-M Thumb bit
    vector_table = struct.pack("<II", initial_sp, reset_handler)
    padding = b"\xff" * (code_offset - len(vector_table))

    # Literal references land at code + 0x0c and code + 0x10 respectively.
    instructions = struct.pack("<5H", 0x4802, 0x6801, 0x4802, 0x6001, 0xE7FE)
    literal_pool = struct.pack("<HII", 0xBF00, GPIO_P0_IN, UART0_TXD)
    return vector_table + padding + instructions + literal_pool


def make_gpio_dump_payload(
    bytes_to_read: int,
    *,
    application_base: int = 0x0001_B000,
    initial_sp: int = 0x2000_8000,
) -> bytes:
    """Return Thumb firmware that copies consecutive P0.IN words to UART0.

    ``P0.IN`` is deliberately modelled as a byte stream by this CTF board, so
    a payload can make several reads and exfiltrate an entire flag.  The code
    is unrolled to remain toolchain-free and easy to inspect in tests.
    """

    if bytes_to_read <= 0 or bytes_to_read % 4:
        raise ValueError("bytes_to_read must be a positive multiple of four")

    code_offset = 0x100
    reset_handler = application_base + code_offset + 1
    vector_table = struct.pack("<II", initial_sp, reset_handler)
    padding = b"\xff" * (code_offset - len(vector_table))
    words = bytes_to_read // 4

    # The first two literal loads are patched after the code size is known.
    instructions = [0x4800, 0x4A00]
    for _ in range(words):
        instructions.extend((0x6801, 0x6011))  # ldr r1,[r0]; str r1,[r2]
    instructions.append(0xE7FE)  # b .

    encoded_instructions = struct.pack(f"<{len(instructions)}H", *instructions)
    literal_padding = b"\x00\x00" if len(encoded_instructions) % 4 else b""
    literal_address = application_base + code_offset + len(encoded_instructions) + len(literal_padding)
    pc_base = application_base + code_offset + 4
    gpio_literal_offset = (literal_address - pc_base) // 4
    uart_literal_offset = (literal_address + 4 - pc_base) // 4
    if gpio_literal_offset > 0xFF or uart_literal_offset > 0xFF:
        raise ValueError("payload is too large for Thumb literal loads")
    instructions[0] |= gpio_literal_offset
    instructions[1] |= uart_literal_offset
    encoded_instructions = struct.pack(f"<{len(instructions)}H", *instructions)

    return (
        vector_table
        + padding
        + encoded_instructions
        + literal_padding
        + struct.pack("<II", GPIO_P0_IN, UART0_TXD)
    )
