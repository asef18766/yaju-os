"""A small reference controller used by integration tests and challenge admin tooling."""

from __future__ import annotations

import struct

from .bridge import LegacyDfuGattBridge
from .protocol import (
    DfuImageType,
    DfuNotification,
    DfuOpcode,
    DfuResponse,
    LegacyInitPacket,
)


class DfuClientError(RuntimeError):
    """The target did not accept an expected legacy DFU operation."""


class LegacyDfuClient:
    """Reference uploader for the application-only legacy DFU target."""

    def __init__(self, bridge: LegacyDfuGattBridge, packet_size: int = 20) -> None:
        if packet_size <= 0:
            raise ValueError("packet_size must be positive")
        self.bridge = bridge
        self.packet_size = packet_size
        self.notifications: list[DfuNotification] = []

    def upload(self, image: bytes, init_packet: bytes | None = None, *, prn: int = 0) -> None:
        if not image:
            raise ValueError("an application image must not be empty")
        if init_packet is None:
            init_packet = LegacyInitPacket.for_image(image).encode()

        self.bridge.connect()
        self.bridge.set_status_notifications(True)

        self._record(self.bridge.write_control_point(bytes((DfuOpcode.START_DFU, DfuImageType.APPLICATION))))
        self._expect_success(
            DfuOpcode.START_DFU,
            self.bridge.write_packet(struct.pack("<III", 0, 0, len(image))),
        )

        self._record(self.bridge.write_control_point(bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 0))))
        self._write_chunks(init_packet)
        self._expect_success(
            DfuOpcode.INITIALIZE_DFU_PARAMETERS,
            self.bridge.write_control_point(bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 1))),
        )

        if prn:
            self._record(
                self.bridge.write_control_point(
                    bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST,)) + struct.pack("<H", prn)
                )
            )

        self._record(self.bridge.write_control_point(bytes((DfuOpcode.RECEIVE_FIRMWARE_IMAGE,))))
        self._write_chunks(image)
        self._expect_success(
            DfuOpcode.VALIDATE_FIRMWARE,
            self.bridge.write_control_point(bytes((DfuOpcode.VALIDATE_FIRMWARE,))),
        )
        self._record(self.bridge.write_control_point(bytes((DfuOpcode.ACTIVATE_AND_RESET,))))

    def _write_chunks(self, data: bytes) -> None:
        for offset in range(0, len(data), self.packet_size):
            self._record(self.bridge.write_packet(data[offset : offset + self.packet_size]))

    def _record(self, notifications: list[DfuNotification]) -> None:
        self.notifications.extend(notifications)

    def _expect_success(self, operation: DfuOpcode, notifications: list[DfuNotification]) -> None:
        self._record(notifications)
        expected = bytes((DfuOpcode.RESPONSE_CODE, operation, DfuResponse.SUCCESS))
        if not any(notification.payload == expected for notification in notifications):
            received = ", ".join(notification.payload.hex() for notification in notifications) or "no notification"
            raise DfuClientError(f"operation {operation.name} was not accepted: {received}")
