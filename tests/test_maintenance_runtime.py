from __future__ import annotations

import importlib.util
import unittest

from hitcon_legacy_dfu.maintenance_runtime import MaintenanceFirmwareRuntime


REFERENCE_ELF = MaintenanceFirmwareRuntime.repository_reference_elf()
# Deliberately only a test fixture: players receive the binary artifact and
# derive this normal maintenance request by reversing its Thumb handler.
VALID_MAINTENANCE_REQUEST = bytes.fromhex("51118ecade42097126d4b05f")


@unittest.skipUnless(
    importlib.util.find_spec("qiling") is not None and REFERENCE_ELF.is_file(),
    "Qiling or the built maintenance application ELF is unavailable",
)
class MaintenanceFirmwareRuntimeTests(unittest.TestCase):
    def test_compiled_application_authorizes_only_its_maintenance_request(self) -> None:
        with MaintenanceFirmwareRuntime(REFERENCE_ELF) as runtime:
            result = runtime.boot()
            self.assertGreaterEqual(result.entry_point & ~1, 0x1B000)
            self.assertGreaterEqual(result.command_handler, 0x1B000)
            self.assertFalse(runtime.request_bootloader(b"\x00" * len(VALID_MAINTENANCE_REQUEST)))
            self.assertFalse(runtime.request_bootloader(VALID_MAINTENANCE_REQUEST[:-1]))
            self.assertTrue(runtime.request_bootloader(VALID_MAINTENANCE_REQUEST))
            # GPREGRET is cleared before every invocation, so a rejected later
            # request cannot inherit an earlier successful boot reason.
            self.assertFalse(runtime.request_bootloader(b"\xff" * len(VALID_MAINTENANCE_REQUEST)))


if __name__ == "__main__":
    unittest.main()
