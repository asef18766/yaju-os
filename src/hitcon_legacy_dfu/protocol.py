"""Wire-level constants and init-packet helpers for Nordic legacy BLE DFU."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
import struct

from .crc import crc16_ccitt
from .gatt_ids import (
    CONTROL_POINT_UUID,
    INMU_KING_FRAME_UUID,
    INMU_KING_SERVICE_UUID,
    LEGACY_DFU_BASE_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_INFO_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    REVISION_UUID,
    SERVICE_UUID,
    STATUS_REPORT_UUID,
    DfuOpcode,
)


class DfuImageType(IntEnum):
    SOFTDEVICE = 0x01
    BOOTLOADER = 0x02
    SOFTDEVICE_AND_BOOTLOADER = 0x03
    APPLICATION = 0x04


class DfuResponse(IntEnum):
    SUCCESS = 0x01
    INVALID_STATE = 0x02
    NOT_SUPPORTED = 0x03
    DATA_SIZE_EXCEEDS_LIMIT = 0x04
    CRC_ERROR = 0x05
    OPERATION_FAILED = 0x06


class DfuState(str, Enum):
    IDLE = "idle"
    EXPECT_IMAGE_SIZE = "expect-image-size"
    EXPECT_INIT = "expect-init"
    RECEIVING_INIT = "receiving-init"
    INIT_ACCEPTED = "init-accepted"
    RECEIVING_FIRMWARE = "receiving-firmware"
    VALIDATED = "validated"
    APPLICATION_RUNNING = "application-running"


class InitPacketError(ValueError):
    """The legacy init packet is malformed."""


@dataclass(frozen=True)
class LegacyInitPacket:
    """The safety-checking portion of a legacy application init packet.

    The legacy format has no signature. The trailing alignment bytes seen in
    Nordic-generated packets are accepted and ignored. Older legacy targets
    also accept a two-byte CRC-only packet, which this model supports.
    """

    device_type: int
    device_revision: int
    application_version: int
    softdevice_ids: tuple[int, ...]
    image_crc16: int
    crc_only: bool = False

    @classmethod
    def parse(cls, payload: bytes) -> "LegacyInitPacket":
        # Very old Nordic legacy DFU deployments may accept a two-byte CRC
        # alone.  Treat it as wildcard device/SoftDevice metadata rather than
        # making a special case leak into the bootloader state machine.
        if len(payload) == 2:
            return cls(
                device_type=0xFFFF,
                device_revision=0xFFFF,
                application_version=0,
                softdevice_ids=(0xFFFE,),
                image_crc16=struct.unpack("<H", payload)[0],
                crc_only=True,
            )
        if len(payload) < 12:
            raise InitPacketError("legacy init packet is shorter than its fixed header")

        device_type, device_revision, application_version, count = struct.unpack_from("<HHIH", payload)
        ids_end = 10 + count * 2
        crc_end = ids_end + 2
        if len(payload) < crc_end:
            raise InitPacketError("legacy init packet truncates the SoftDevice list or image CRC")

        softdevice_ids = struct.unpack_from(f"<{count}H", payload, 10) if count else ()
        image_crc16 = struct.unpack_from("<H", payload, ids_end)[0]
        return cls(
            device_type=device_type,
            device_revision=device_revision,
            application_version=application_version,
            softdevice_ids=tuple(softdevice_ids),
            image_crc16=image_crc16,
        )

    @classmethod
    def for_image(
        cls,
        image: bytes,
        *,
        device_type: int = 0xFFFF,
        device_revision: int = 0xFFFF,
        application_version: int = 0,
        softdevice_ids: tuple[int, ...] = (0xFFFE,),
        crc_only: bool = False,
    ) -> "LegacyInitPacket":
        return cls(
            device_type=device_type,
            device_revision=device_revision,
            application_version=application_version,
            softdevice_ids=softdevice_ids,
            image_crc16=crc16_ccitt(image),
            crc_only=crc_only,
        )

    def encode(self, *, add_alignment: bool = True) -> bytes:
        if self.crc_only:
            return struct.pack("<H", self.image_crc16)
        if len(self.softdevice_ids) > 0xFFFF:
            raise InitPacketError("too many SoftDevice IDs")

        header = struct.pack(
            "<HHIH",
            self.device_type,
            self.device_revision,
            self.application_version,
            len(self.softdevice_ids),
        )
        ids = struct.pack(f"<{len(self.softdevice_ids)}H", *self.softdevice_ids) if self.softdevice_ids else b""
        payload = header + ids + struct.pack("<H", self.image_crc16)
        return payload + (b"\x00\x00" if add_alignment else b"")


@dataclass(frozen=True)
class DfuNotification:
    """A notification emitted on the legacy DFU status-report characteristic."""

    payload: bytes
    characteristic_uuid: str = STATUS_REPORT_UUID


def response_for(operation: int, status: DfuResponse) -> DfuNotification:
    return DfuNotification(bytes((DfuOpcode.RESPONSE_CODE, operation, status)))


def packet_receipt_notification(bytes_received: int) -> DfuNotification:
    return DfuNotification(bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION,)) + struct.pack("<I", bytes_received))
