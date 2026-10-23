"""Checksums used by the legacy Nordic DFU init packet."""


def crc16_ccitt(data: bytes, initial: int = 0xFFFF) -> int:
    """Return the non-reflected CRC-16-CCITT value used by the legacy SDK.

    Nordic's legacy init packet uses polynomial 0x1021 and an initial value of
    0xFFFF. This is integrity only, intentionally not authenticity.
    """

    crc = initial & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc
