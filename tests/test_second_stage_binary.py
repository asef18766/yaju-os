from __future__ import annotations

import importlib.util
import struct
import unittest

from yaju_os.bootloader import BootloaderConfig, LegacyDfuBootloader
from yaju_os.bridge import LegacyDfuGattBridge
from yaju_os.client import LegacyDfuClient
from yaju_os.second_stage_runtime import (
    NRF_SUCCESS,
    SecondStageFirmwareRuntime,
)
from yaju_os.payloads import make_gpio_probe_payload
from yaju_os.protocol import (
    CONTROL_POINT_UUID,
    PACKET_UUID,
    REVISION_UUID,
    SERVICE_UUID,
    LegacyInitPacket,
)


REFERENCE_ELF = SecondStageFirmwareRuntime.repository_board_runtime()


@unittest.skipUnless(
    importlib.util.find_spec("qiling") is not None and REFERENCE_ELF.exists(),
    "Qiling or the built nRF51 SDK 11 reference ELF is unavailable",
)
class SecondStageBinaryTests(unittest.TestCase):
    def test_compiled_bootloader_reaches_its_dfu_advertising_event_loop(self) -> None:
        with SecondStageFirmwareRuntime(REFERENCE_ELF) as runtime:
            result = runtime.boot()

        self.assertTrue(result.reached_event_wait)
        self.assertTrue(result.advertising_started)
        self.assertEqual(result.services_added, 1)
        self.assertGreaterEqual(result.characteristics_added, 3)
        self.assertIn(0x60, result.svc_calls)  # sd_ble_enable
        self.assertIn(0x73, result.svc_calls)  # sd_ble_gap_adv_start
        self.assertIn(0xA0, result.svc_calls)  # sd_ble_gatts_service_add
        self.assertIn(0xA2, result.svc_calls)  # sd_ble_gatts_characteristic_add

    def test_compiled_crc_template_accepts_an_unsigned_image(self) -> None:
        # The bytes do not contain a signature or a valid vector table.  This
        # directly exercises Nordic's compiled dfu_init_template.c gates; the
        # outer challenge model separately requires a runnable application.
        image = b"arbitrary unsigned firmware bytes!!"
        init_packet = LegacyInitPacket.for_image(image).encode()

        with SecondStageFirmwareRuntime(REFERENCE_ELF) as runtime:
            self.assertEqual(runtime.prevalidate_init_packet(init_packet), NRF_SUCCESS)
            self.assertEqual(runtime.postvalidate_image(image), NRF_SUCCESS)
            self.assertNotEqual(runtime.postvalidate_image(image[:-1]), NRF_SUCCESS)

    def test_challenge_model_can_delegate_validation_to_the_compiled_elf(self) -> None:
        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
        image = make_gpio_probe_payload(application_base=config.application_base)

        with SecondStageFirmwareRuntime(REFERENCE_ELF) as reference_runtime:
            bootloader = LegacyDfuBootloader(
                config=config,
                validation_backend=reference_runtime,
            )
            LegacyDfuClient(LegacyDfuGattBridge(bootloader)).upload(image)

        self.assertEqual(bootloader.active_image, image)

    def test_compiled_elf_processes_legacy_ble_events_and_dual_bank_activation(self) -> None:
        """Exercise the actual GATT callback, pstorage queue, and flash copy.

        This does not call the public direct pre/post-validation helpers: each
        transition enters the compiled ``ble_evt_dispatch`` via a synthesized
        S130 event, exactly as the Rootcanal/Bumble adapter does.
        """

        image = b"compiled-sdk11-dfu!!"
        init_packet = LegacyInitPacket.for_image(image).encode()

        with SecondStageFirmwareRuntime(REFERENCE_ELF) as runtime:
            # The host publishes the attribute table the compiled image
            # registered, so every identifier and every handle below comes
            # from the firmware rather than from a Python constant.
            service = runtime.gatt_service
            self.assertEqual(service.uuid, SERVICE_UUID)
            self.assertTrue(service.primary)
            packet, control_point, revision = service.characteristics
            self.assertEqual(
                [packet.uuid, control_point.uuid, revision.uuid],
                [PACKET_UUID, CONTROL_POINT_UUID, REVISION_UUID],
            )
            self.assertEqual(revision.initial_value, b"\x08\x00")
            handles = runtime.service_handles
            self.assertEqual(handles.packet_value, packet.firmware_value_handle)
            self.assertEqual(
                handles.control_point_value, control_point.firmware_value_handle
            )
            self.assertEqual(
                len(
                    {
                        handles.packet_value,
                        handles.control_point_value,
                        handles.control_point_cccd,
                    }
                ),
                3,
            )
            runtime.connect()
            runtime.set_control_point_notifications(True)

            runtime.write_control_point(b"\x01\x04")
            result = runtime.write_packet(struct.pack("<III", 0, 0, len(image)))
            self.assertEqual(result.notifications, (b"\x10\x01\x01",))

            runtime.write_control_point(b"\x02\x00")
            runtime.write_packet(init_packet)
            result = runtime.write_control_point(b"\x02\x01")
            self.assertEqual(result.notifications, (b"\x10\x02\x01",))

            runtime.write_control_point(b"\x08\x01\x00")
            runtime.write_control_point(b"\x03")
            result = runtime.write_packet(image)
            self.assertEqual(result.notifications, (b"\x10\x03\x01",))

            result = runtime.write_control_point(b"\x04")
            self.assertEqual(result.notifications, (b"\x10\x04\x01",))
            result = runtime.write_control_point(b"\x05")

        self.assertTrue(result.disconnect_requested)
        self.assertEqual(result.activated_image, image)


if __name__ == "__main__":
    unittest.main()
