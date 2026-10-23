from __future__ import annotations

import struct
import unittest

from field_node.bootloader import BootloaderConfig, LegacyDfuBootloader
from field_node.bridge import GattStateError, LegacyDfuGattBridge
from field_node.client import DfuClientError, LegacyDfuClient
from field_node.crc import crc16_ccitt
from field_node.payloads import make_gpio_probe_payload
from field_node.protocol import (
    CONTROL_POINT_UUID,
    PACKET_UUID,
    SERVICE_UUID,
    STATUS_REPORT_UUID,
    DfuImageType,
    DfuOpcode,
    DfuResponse,
    DfuState,
    LegacyInitPacket,
)


class RecordingRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, int]] = []

    def run_application(self, image: bytes, application_base: int) -> dict[str, int]:
        self.calls.append((image, application_base))
        return {"image_size": len(image), "application_base": application_base}


class RecordingValidationBackend:
    def __init__(self) -> None:
        self.init_packets: list[bytes] = []
        self.images: list[bytes] = []

    def prevalidate_init_packet(self, init_packet: bytes) -> int:
        self.init_packets.append(init_packet)
        return 0

    def postvalidate_image(self, image: bytes) -> int:
        self.images.append(image)
        return 0


class LegacyDfuBootloaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = RecordingRuntime()
        self.bootloader = LegacyDfuBootloader(runtime=self.runtime)
        self.bridge = LegacyDfuGattBridge(self.bootloader)
        self.client = LegacyDfuClient(self.bridge)
        self.image = make_gpio_probe_payload()

    def test_crc16_ccitt_reference_value(self) -> None:
        self.assertEqual(crc16_ccitt(b"123456789"), 0x29B1)

    def test_nrf51_sdk11_profile_matches_the_compiled_reference_layout(self) -> None:
        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()

        self.assertEqual(config.flash_size, 0x40000)
        self.assertEqual(config.sram_size, 0x8000)
        self.assertEqual(config.application_base, 0x1B000)
        self.assertEqual(config.bootloader_base, 0x3C000)
        self.assertEqual(config.application_capacity, 0x21000)
        self.assertEqual(config.update_capacity, 0x10800)
        self.assertEqual(config.softdevice_id, 0x0080)
        self.assertEqual(config.max_init_packet_size, 128)
        self.assertFalse(config.allow_crc_only_init_packet)
        self.assertTrue(config.require_word_aligned_image)

    def test_nrf51_sdk11_profile_enforces_dual_bank_size_and_word_alignment(self) -> None:
        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()

        for application_size in (config.update_capacity + 4, len(self.image) - 1):
            with self.subTest(application_size=application_size):
                bootloader = LegacyDfuBootloader(config=config)
                self.assertEqual(
                    bootloader.control_point_write(bytes((DfuOpcode.START_DFU, DfuImageType.APPLICATION))),
                    [],
                )
                notifications = bootloader.packet_write(struct.pack("<III", 0, 0, application_size))
                self.assertEqual(
                    notifications[0].payload,
                    bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.START_DFU, DfuResponse.DATA_SIZE_EXCEEDS_LIMIT)),
                )

    def test_gatt_profile_uses_legacy_uuid_family(self) -> None:
        profile = self.bridge.connect()
        self.assertEqual(profile.service_uuid, SERVICE_UUID)
        self.assertEqual(profile.control_point_uuid, CONTROL_POINT_UUID)
        self.assertEqual(profile.packet_uuid, PACKET_UUID)
        self.assertEqual(profile.status_report_uuid, STATUS_REPORT_UUID)

    def test_control_point_requires_status_cccd(self) -> None:
        self.bridge.connect()
        with self.assertRaises(GattStateError):
            self.bridge.write_control_point(bytes((DfuOpcode.START_DFU, 4)))

    def test_legacy_upload_programs_flash_and_runs_uploaded_image(self) -> None:
        self.client.upload(self.image, prn=2)

        self.assertEqual(self.bootloader.state, DfuState.APPLICATION_RUNNING)
        self.assertEqual(self.bootloader.active_image, self.image)
        self.assertEqual(len(self.runtime.calls), 1)
        self.assertEqual(self.runtime.calls[0][0], self.image)
        flash_offset = self.bootloader.config.application_base - self.bootloader.config.flash_base
        self.assertEqual(self.bootloader.flash[flash_offset : flash_offset + len(self.image)], self.image)
        self.assertTrue(
            any(notification.payload[0] == DfuOpcode.PACKET_RECEIPT_NOTIFICATION for notification in self.client.notifications)
        )

    def test_crc_only_legacy_init_packet_is_accepted(self) -> None:
        init_packet = LegacyInitPacket.for_image(self.image, crc_only=True).encode()
        self.assertEqual(len(init_packet), 2)

        self.client.upload(self.image, init_packet)

        self.assertEqual(self.bootloader.active_image, self.image)

    def test_crc_only_init_packet_can_be_disabled(self) -> None:
        bootloader = LegacyDfuBootloader(
            config=BootloaderConfig.nrf51_sdk11_pca10028_s130(),
            runtime=self.runtime,
        )
        client = LegacyDfuClient(LegacyDfuGattBridge(bootloader))

        with self.assertRaises(DfuClientError):
            client.upload(self.image, LegacyInitPacket.for_image(self.image, crc_only=True).encode())

        self.assertIsNone(bootloader.active_image)

    def test_validation_backend_receives_the_raw_init_packet_and_image(self) -> None:
        backend = RecordingValidationBackend()
        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
        bootloader = LegacyDfuBootloader(
            config=config,
            runtime=self.runtime,
            validation_backend=backend,
        )
        client = LegacyDfuClient(LegacyDfuGattBridge(bootloader))
        init_packet = LegacyInitPacket.for_image(self.image).encode()

        client.upload(self.image, init_packet)

        self.assertEqual(backend.init_packets, [init_packet])
        self.assertEqual(backend.images, [self.image])
        self.assertEqual(bootloader.active_image, self.image)

    def test_bad_crc_cannot_activate_image(self) -> None:
        correct_init = LegacyInitPacket.for_image(self.image).encode()
        corrupted = bytearray(self.image)
        corrupted[-1] ^= 0x01

        with self.assertRaises(DfuClientError):
            self.client.upload(bytes(corrupted), correct_init)

        self.assertIsNone(self.bootloader.active_image)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.bootloader.state, DfuState.RECEIVING_FIRMWARE)

    def test_application_only_target_rejects_non_application_update(self) -> None:
        self.bridge.connect()
        self.bridge.set_status_notifications(True)
        notifications = self.bridge.write_control_point(bytes((DfuOpcode.START_DFU, 1)))
        self.assertEqual(
            notifications[0].payload,
            bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.START_DFU, DfuResponse.NOT_SUPPORTED)),
        )

    def test_packet_receipt_notification_contains_received_length(self) -> None:
        self.bridge.connect()
        self.bridge.set_status_notifications(True)
        self.bridge.write_control_point(bytes((DfuOpcode.START_DFU, 4)))
        self.bridge.write_packet(struct.pack("<III", 0, 0, len(self.image)))
        self.bridge.write_control_point(bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 0)))
        self.bridge.write_packet(LegacyInitPacket.for_image(self.image).encode())
        self.bridge.write_control_point(bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 1)))
        self.bridge.write_control_point(bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST, 2, 0)))
        self.bridge.write_control_point(bytes((DfuOpcode.RECEIVE_FIRMWARE_IMAGE,)))

        self.assertEqual(self.bridge.write_packet(self.image[:7]), [])
        notifications = self.bridge.write_packet(self.image[7:14])
        self.assertEqual(notifications[0].payload, bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION,)) + struct.pack("<I", 14))


if __name__ == "__main__":
    unittest.main()
