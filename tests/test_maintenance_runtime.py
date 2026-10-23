from __future__ import annotations

import importlib.util
import unittest

from yaju_os.board_runtime import BoardRuntimeArtifact
from yaju_os.inmu_king_art import INMU_KING_DANCE_FRAMES
from yaju_os.maintenance_runtime import MaintenanceFirmwareRuntime
from yaju_os.gatt_ids import INMU_KING_FRAME_UUID, INMU_KING_SERVICE_UUID


REFERENCE_ELF = MaintenanceFirmwareRuntime.repository_board_runtime()
# Deliberately only a test fixture: players receive the binary artifact and
# derive this normal maintenance request by reversing its Thumb handler.
VALID_MAINTENANCE_REQUEST = bytes.fromhex("11451419198100")


@unittest.skipUnless(
    importlib.util.find_spec("qiling") is not None and REFERENCE_ELF.exists(),
    "Qiling or the built maintenance application ELF is unavailable",
)
class MaintenanceFirmwareRuntimeTests(unittest.TestCase):
    def test_board_flash_contains_animation_gatts_calls_and_art(self) -> None:
        image = BoardRuntimeArtifact.load(REFERENCE_ELF).flash
        # S130 stores the shared vendor base little-endian and receives the
        # service/characteristic 16-bit portions through its GATTS structs.
        self.assertIn(bytes.fromhex("6d8bd5c186a72c948d4c5d7c00001c5a"), image)
        self.assertIn(b"\x63\xdf", image)  # sd_ble_uuid_vs_add
        self.assertIn(b"\xa0\xdf", image)  # sd_ble_gatts_service_add
        self.assertIn(b"\xa2\xdf", image)  # sd_ble_gatts_characteristic_add
        self.assertIn(b"\xa8\xdf", image)  # sd_ble_gatts_rw_authorize_reply
        self.assertIn(b"<o>", image)
        self.assertIn(b"b/|\\d", image)

    def test_compiled_application_authorizes_only_its_maintenance_request(self) -> None:
        with MaintenanceFirmwareRuntime(REFERENCE_ELF) as runtime:
            result = runtime.boot()
            self.assertGreaterEqual(result.entry_point & ~1, 0x1B000)
            self.assertGreaterEqual(result.command_handler, 0x1B000)
            self.assertEqual(result.svc_calls, (0x63, 0xA0, 0xA2))
            self.assertEqual(len(result.gatt_services), 1)
            service = result.gatt_services[0]
            self.assertEqual(service.uuid, INMU_KING_SERVICE_UUID)
            self.assertTrue(service.primary)
            self.assertEqual(len(service.characteristics), 1)
            frame = service.characteristics[0]
            self.assertEqual(frame.uuid, INMU_KING_FRAME_UUID)
            self.assertEqual(frame.properties, 0x02)
            self.assertEqual(frame.max_length, 125)
            self.assertEqual(frame.initial_value, INMU_KING_DANCE_FRAMES[0])
            self.assertTrue(frame.readable)
            self.assertFalse(frame.writable)
            self.assertTrue(frame.read_authorized)
            self.assertFalse(runtime.request_bootloader(b"\x00" * len(VALID_MAINTENANCE_REQUEST)))
            self.assertFalse(runtime.request_bootloader(VALID_MAINTENANCE_REQUEST[:-1]))
            self.assertTrue(runtime.request_bootloader(VALID_MAINTENANCE_REQUEST))
            # GPREGRET is cleared before every invocation, so a rejected later
            # request cannot inherit an earlier successful boot reason.
            self.assertFalse(runtime.request_bootloader(b"\xff" * len(VALID_MAINTENANCE_REQUEST)))

    def test_compiled_application_owns_animation_frames_and_cursor(self) -> None:
        with MaintenanceFirmwareRuntime(REFERENCE_ELF) as runtime:
            frame = runtime.boot().gatt_services[0].characteristics[0]
            runtime.connect(7)
            actual = tuple(
                runtime.authorize_read(frame.firmware_value_handle).value
                for _ in range(len(INMU_KING_DANCE_FRAMES) + 8)
            )
            self.assertEqual(
                actual,
                INMU_KING_DANCE_FRAMES + INMU_KING_DANCE_FRAMES[:8],
            )
            # A non-zero S130 read offset returns the firmware snapshot without
            # ticking playback; the next offset-zero request advances once.
            self.assertEqual(
                runtime.authorize_read(frame.firmware_value_handle, offset=22).value,
                INMU_KING_DANCE_FRAMES[7],
            )
            self.assertEqual(
                runtime.authorize_read(frame.firmware_value_handle).value,
                INMU_KING_DANCE_FRAMES[8],
            )
            runtime.disconnect()
            runtime.connect(8)
            self.assertEqual(
                runtime.authorize_read(frame.firmware_value_handle).value,
                INMU_KING_DANCE_FRAMES[0],
            )


if __name__ == "__main__":
    unittest.main()
