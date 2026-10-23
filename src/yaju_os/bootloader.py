"""Application-only Nordic legacy DFU bootloader model.

This module intentionally models the legacy security property: an image with a
matching CRC and compatible metadata is accepted without a signature.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Protocol, runtime_checkable

from .crc import crc16_ccitt
from .protocol import (
    DfuImageType,
    DfuNotification,
    DfuOpcode,
    DfuResponse,
    DfuState,
    InitPacketError,
    LegacyInitPacket,
    packet_receipt_notification,
    response_for,
)


@runtime_checkable
class FirmwareRuntime(Protocol):
    """A post-reset firmware runner, e.g. the Qiling Cortex-M adapter."""

    def run_application(self, image: bytes, application_base: int) -> object: ...


@runtime_checkable
class FirmwareValidationBackend(Protocol):
    """Optional authority for the real bootloader's image-validation hooks."""

    def prevalidate_init_packet(self, init_packet: bytes) -> int: ...

    def postvalidate_image(self, image: bytes) -> int: ...


@dataclass(frozen=True)
class BootloaderConfig:
    """Memory layout and protocol constraints for a challenge target."""

    flash_base: int = 0x0000_0000
    flash_size: int = 0x0008_0000  # 512 KiB
    application_base: int = 0x0001_B000
    bootloader_base: int = 0x0007_8000
    sram_base: int = 0x2000_0000
    sram_size: int = 0x0001_0000  # 64 KiB
    device_type: int = 0xFFFF
    device_revision: int = 0xFFFF
    softdevice_id: int = 0x0079
    max_init_packet_size: int = 512
    allow_crc_only_init_packet: bool = True
    max_application_size: int | None = None
    require_word_aligned_image: bool = False

    @property
    def application_capacity(self) -> int:
        return self.bootloader_base - self.application_base

    @property
    def update_capacity(self) -> int:
        """Largest application image accepted by this bootloader's update path.

        A dual-bank bootloader cannot use all free application flash for one
        incoming image: it needs one half as the staging bank.  Keeping this
        separate from :attr:`application_capacity` makes that hardware limit
        explicit without changing the simple flash model used after activate.
        """

        if self.max_application_size is None:
            return self.application_capacity
        return min(self.application_capacity, self.max_application_size)

    @classmethod
    def nrf51_sdk11_pca10028_s130(cls) -> "BootloaderConfig":
        """Return the memory/device profile of the compiled Nordic reference.

        This matches nRF5 SDK 11's ``dual_bank_ble_s130`` legacy bootloader
        for PCA10028 / nRF51422_xxAC: 256 KiB flash, 32 KiB SRAM, S130 2.0.0,
        application code at ``0x1b000`` and bootloader code at ``0x3c000``.
        The real SDK 11 template requires the structured init packet, so its
        CRC-only predecessor mode is deliberately disabled for this profile.
        """

        return cls(
            flash_size=0x0004_0000,
            application_base=0x0001_B000,
            bootloader_base=0x0003_C000,
            sram_size=0x0000_8000,
            softdevice_id=0x0080,
            # SDK 11's dual-bank target stages an application in the second
            # half of the 0x21000-byte region before swapping it into bank 0.
            max_application_size=0x0001_0800,
            max_init_packet_size=128,
            allow_crc_only_init_packet=False,
            require_word_aligned_image=True,
        )


class LegacyDfuBootloader:
    """Stateful implementation of the legacy BLE DFU application update path."""

    def __init__(
        self,
        config: BootloaderConfig | None = None,
        runtime: FirmwareRuntime | None = None,
        validation_backend: FirmwareValidationBackend | None = None,
    ) -> None:
        self.config = config or BootloaderConfig()
        if not (self.config.flash_base <= self.config.application_base < self.config.bootloader_base):
            raise ValueError("application and bootloader addresses are inconsistent")
        if self.config.bootloader_base > self.config.flash_base + self.config.flash_size:
            raise ValueError("bootloader lies outside emulated flash")
        if self.config.max_application_size is not None and self.config.max_application_size <= 0:
            raise ValueError("max_application_size must be positive when configured")

        self.runtime = runtime
        self.validation_backend = validation_backend
        self.flash = bytearray(b"\xff" * self.config.flash_size)
        self.active_image: bytes | None = None
        self.last_execution: object | None = None
        self.reset_transfer()

    def reset_transfer(self) -> None:
        """Discard an unfinished update while preserving the active application."""

        self.state = DfuState.IDLE
        self.image_type: DfuImageType | None = None
        self.expected_image_size: int | None = None
        self.init_data = bytearray()
        self.init_packet: LegacyInitPacket | None = None
        self.received_image = bytearray()
        self.packet_receipt_interval = 0
        self._packets_since_receipt = 0

    def control_point_write(self, payload: bytes) -> list[DfuNotification]:
        """Handle a write to the legacy DFU control point."""

        if not payload:
            return [response_for(0, DfuResponse.OPERATION_FAILED)]

        opcode = payload[0]
        try:
            operation = DfuOpcode(opcode)
        except ValueError:
            return [response_for(opcode, DfuResponse.NOT_SUPPORTED)]

        if operation is DfuOpcode.START_DFU:
            return self._start_dfu(payload)
        if operation is DfuOpcode.INITIALIZE_DFU_PARAMETERS:
            return self._initialize_parameters(payload)
        if operation is DfuOpcode.RECEIVE_FIRMWARE_IMAGE:
            return self._receive_firmware(payload)
        if operation is DfuOpcode.VALIDATE_FIRMWARE:
            return self._validate_firmware(payload)
        if operation is DfuOpcode.ACTIVATE_AND_RESET:
            return self._activate_and_reset(payload)
        if operation is DfuOpcode.SYSTEM_RESET:
            return self._system_reset(payload)
        if operation is DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST:
            return self._set_packet_receipt_interval(payload)
        return [response_for(opcode, DfuResponse.NOT_SUPPORTED)]

    def packet_write(self, payload: bytes) -> list[DfuNotification]:
        """Handle a write-without-response to the legacy DFU packet characteristic."""

        if self.state is DfuState.EXPECT_IMAGE_SIZE:
            return self._set_image_sizes(payload)

        if self.state is DfuState.RECEIVING_INIT:
            if len(self.init_data) + len(payload) > self.config.max_init_packet_size:
                return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)]
            self.init_data.extend(payload)
            return []

        if self.state is DfuState.RECEIVING_FIRMWARE:
            assert self.expected_image_size is not None
            if len(self.received_image) + len(payload) > self.expected_image_size:
                return [response_for(DfuOpcode.RECEIVE_FIRMWARE_IMAGE, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)]

            self.received_image.extend(payload)
            self._packets_since_receipt += 1
            if self.packet_receipt_interval and self._packets_since_receipt >= self.packet_receipt_interval:
                self._packets_since_receipt = 0
                return [packet_receipt_notification(len(self.received_image))]
            return []

        return [response_for(DfuOpcode.RECEIVE_FIRMWARE_IMAGE, DfuResponse.INVALID_STATE)]

    def _start_dfu(self, payload: bytes) -> list[DfuNotification]:
        if self.state not in {DfuState.IDLE, DfuState.APPLICATION_RUNNING}:
            return [response_for(DfuOpcode.START_DFU, DfuResponse.INVALID_STATE)]
        if len(payload) != 2:
            return [response_for(DfuOpcode.START_DFU, DfuResponse.OPERATION_FAILED)]

        try:
            image_type = DfuImageType(payload[1])
        except ValueError:
            return [response_for(DfuOpcode.START_DFU, DfuResponse.NOT_SUPPORTED)]
        if image_type is not DfuImageType.APPLICATION:
            return [response_for(DfuOpcode.START_DFU, DfuResponse.NOT_SUPPORTED)]

        self.reset_transfer()
        self.image_type = image_type
        self.state = DfuState.EXPECT_IMAGE_SIZE
        return []

    def _set_image_sizes(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 12:
            return [response_for(DfuOpcode.START_DFU, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)]

        softdevice_size, bootloader_size, application_size = struct.unpack("<III", payload)
        if (
            softdevice_size
            or bootloader_size
            or not application_size
            or application_size > self.config.update_capacity
            or (self.config.require_word_aligned_image and application_size % 4)
        ):
            self.reset_transfer()
            return [response_for(DfuOpcode.START_DFU, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)]

        self.expected_image_size = application_size
        self.state = DfuState.EXPECT_INIT
        return [response_for(DfuOpcode.START_DFU, DfuResponse.SUCCESS)]

    def _initialize_parameters(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 2:
            return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.OPERATION_FAILED)]

        mode = payload[1]
        if mode == 0:
            if self.state is not DfuState.EXPECT_INIT:
                return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.INVALID_STATE)]
            self.init_data.clear()
            self.state = DfuState.RECEIVING_INIT
            return []

        if mode == 1:
            if self.state is not DfuState.RECEIVING_INIT:
                return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.INVALID_STATE)]
            try:
                init_packet = LegacyInitPacket.parse(bytes(self.init_data))
                self._check_init_packet_compatibility(init_packet)
                if self.validation_backend is not None:
                    validation_result = self.validation_backend.prevalidate_init_packet(bytes(self.init_data))
                    if validation_result != 0:
                        raise InitPacketError("reference bootloader rejected the init packet")
            except InitPacketError:
                self.state = DfuState.EXPECT_INIT
                return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.OPERATION_FAILED)]
            except Exception:
                self.state = DfuState.EXPECT_INIT
                return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.OPERATION_FAILED)]

            self.init_packet = init_packet
            self.state = DfuState.INIT_ACCEPTED
            return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.SUCCESS)]

        return [response_for(DfuOpcode.INITIALIZE_DFU_PARAMETERS, DfuResponse.NOT_SUPPORTED)]

    def _check_init_packet_compatibility(self, init_packet: LegacyInitPacket) -> None:
        if init_packet.crc_only and not self.config.allow_crc_only_init_packet:
            raise InitPacketError("this bootloader requires a full legacy init packet")
        if self.config.device_type != 0xFFFF and init_packet.device_type != self.config.device_type:
            raise InitPacketError("unexpected device type")
        if self.config.device_revision != 0xFFFF and init_packet.device_revision != self.config.device_revision:
            raise InitPacketError("unexpected device revision")
        if self.config.softdevice_id not in init_packet.softdevice_ids and 0xFFFE not in init_packet.softdevice_ids:
            raise InitPacketError("application does not support this SoftDevice")

    def _receive_firmware(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 1:
            return [response_for(DfuOpcode.RECEIVE_FIRMWARE_IMAGE, DfuResponse.OPERATION_FAILED)]
        if self.state is not DfuState.INIT_ACCEPTED:
            return [response_for(DfuOpcode.RECEIVE_FIRMWARE_IMAGE, DfuResponse.INVALID_STATE)]
        self.received_image.clear()
        self._packets_since_receipt = 0
        self.state = DfuState.RECEIVING_FIRMWARE
        return []

    def _validate_firmware(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 1:
            return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.OPERATION_FAILED)]
        if self.state is not DfuState.RECEIVING_FIRMWARE:
            return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.INVALID_STATE)]
        if len(self.received_image) != self.expected_image_size:
            return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)]

        assert self.init_packet is not None
        if self.validation_backend is not None:
            try:
                validation_result = self.validation_backend.postvalidate_image(bytes(self.received_image))
            except Exception:
                return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.OPERATION_FAILED)]
            if validation_result != 0:
                return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.CRC_ERROR)]
        if crc16_ccitt(bytes(self.received_image)) != self.init_packet.image_crc16:
            return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.CRC_ERROR)]
        if not self._has_runnable_vector_table(bytes(self.received_image)):
            return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.OPERATION_FAILED)]

        self.state = DfuState.VALIDATED
        return [response_for(DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.SUCCESS)]

    def _has_runnable_vector_table(self, image: bytes) -> bool:
        if len(image) < 8:
            return False
        initial_sp, reset_handler = struct.unpack_from("<II", image)
        sram_end = self.config.sram_base + self.config.sram_size
        if initial_sp % 4 or not (self.config.sram_base <= initial_sp <= sram_end):
            return False
        if not reset_handler & 1:
            return False
        handler = reset_handler & ~1
        return self.config.application_base + 8 <= handler < self.config.application_base + len(image)

    def _activate_and_reset(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 1:
            return [response_for(DfuOpcode.ACTIVATE_AND_RESET, DfuResponse.OPERATION_FAILED)]
        if self.state is not DfuState.VALIDATED:
            return [response_for(DfuOpcode.ACTIVATE_AND_RESET, DfuResponse.INVALID_STATE)]

        image = bytes(self.received_image)
        flash_offset = self.config.application_base - self.config.flash_base
        erase_end = self.config.bootloader_base - self.config.flash_base
        self.flash[flash_offset:erase_end] = b"\xff" * (erase_end - flash_offset)
        self.flash[flash_offset : flash_offset + len(image)] = image
        self.active_image = image
        self.state = DfuState.APPLICATION_RUNNING

        if self.runtime is not None:
            self.last_execution = self.runtime.run_application(image, self.config.application_base)

        # The actual target resets/disconnects at this point; it does not wait for
        # a response notification to the activation command.
        return []

    def _system_reset(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 1:
            return [response_for(DfuOpcode.SYSTEM_RESET, DfuResponse.OPERATION_FAILED)]
        if self.active_image is None:
            self.state = DfuState.IDLE
            return []

        self.state = DfuState.APPLICATION_RUNNING
        if self.runtime is not None:
            self.last_execution = self.runtime.run_application(self.active_image, self.config.application_base)
        return []

    def _set_packet_receipt_interval(self, payload: bytes) -> list[DfuNotification]:
        if len(payload) != 3:
            return [response_for(DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST, DfuResponse.OPERATION_FAILED)]
        self.packet_receipt_interval = struct.unpack_from("<H", payload, 1)[0]
        self._packets_since_receipt = 0
        return []
