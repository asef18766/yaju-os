"""A GATT-boundary bridge for the legacy DFU target.

The future Rootcanal device-side HCI host should call this object after it has
decoded ATT/GATT operations. Keeping this boundary explicit prevents treating
Rootcanal's H4 TCP stream as a fictional DFU TCP protocol.
"""

from __future__ import annotations

from dataclasses import dataclass

from .bootloader import LegacyDfuBootloader
from .gatt_ids import CONTROL_POINT_UUID, PACKET_UUID, REVISION_UUID, SERVICE_UUID
from .protocol import STATUS_REPORT_UUID, DfuNotification


class GattStateError(RuntimeError):
    """A client attempted an operation that BLE/GATT would reject."""


@dataclass(frozen=True)
class LegacyDfuGattProfile:
    service_uuid: str = SERVICE_UUID
    control_point_uuid: str = CONTROL_POINT_UUID
    packet_uuid: str = PACKET_UUID
    status_report_uuid: str = STATUS_REPORT_UUID
    revision_uuid: str = REVISION_UUID


class LegacyDfuGattBridge:
    """Maps GATT characteristic writes onto the bootloader state machine."""

    profile = LegacyDfuGattProfile()

    def __init__(self, bootloader: LegacyDfuBootloader) -> None:
        self.bootloader = bootloader
        self.connected = False
        self.status_notifications_enabled = False

    def connect(self) -> LegacyDfuGattProfile:
        self.connected = True
        self.status_notifications_enabled = False
        return self.profile

    def disconnect(self) -> None:
        self.connected = False
        self.status_notifications_enabled = False

    def set_status_notifications(self, enabled: bool) -> None:
        self._require_connected()
        self.status_notifications_enabled = enabled

    def write_control_point(self, payload: bytes) -> list[DfuNotification]:
        self._require_connected()
        # Nordic's legacy service requires the status report CCCD to be enabled
        # before the controller starts an operation that can emit a response.
        if not self.status_notifications_enabled:
            raise GattStateError("status-report notifications are not enabled")
        return self.bootloader.control_point_write(payload)

    def write_packet(self, payload: bytes) -> list[DfuNotification]:
        self._require_connected()
        return self.bootloader.packet_write(payload)

    def _require_connected(self) -> None:
        if not self.connected:
            raise GattStateError("no active BLE connection")
