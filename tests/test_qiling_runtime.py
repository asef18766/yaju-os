from __future__ import annotations

import importlib.util
import unittest

from yaju_os.bootloader import BootloaderConfig, LegacyDfuBootloader
from yaju_os.bridge import LegacyDfuGattBridge
from yaju_os.client import LegacyDfuClient
from yaju_os.payloads import (
    TEST_APPLICATION_SERVICE_UUID,
    TEST_APPLICATION_VALUE_UUID,
    make_gpio_dump_payload,
    make_gpio_probe_payload,
)


@unittest.skipUnless(importlib.util.find_spec("qiling") is not None, "optional Qiling dependency is not installed")
class QilingRuntimeTests(unittest.TestCase):
    def test_uploaded_thumb_payload_reads_gpio_and_registers_gatt(self) -> None:
        from yaju_os.qiling_runtime import QilingRuntime

        secret = b"CTF{legacy_dfu_gpio}"
        runtime = QilingRuntime(secret, instruction_budget=100)
        bootloader = LegacyDfuBootloader(runtime=runtime)
        client = LegacyDfuClient(LegacyDfuGattBridge(bootloader))

        client.upload(make_gpio_probe_payload())

        self.assertIsNotNone(runtime.last_result)
        assert runtime.last_result is not None
        self.assertEqual(runtime.last_result.svc_calls, (0x63, 0xA0, 0xA2))
        service = runtime.last_result.gatt_services[0]
        self.assertEqual(service.uuid, TEST_APPLICATION_SERVICE_UUID)
        self.assertEqual(service.characteristics[0].uuid, TEST_APPLICATION_VALUE_UUID)
        self.assertEqual(service.characteristics[0].initial_value, secret[:4])
        self.assertTrue(service.characteristics[0].readable)
        self.assertFalse(service.characteristics[0].writable)
        self.assertEqual(runtime.last_result.gpio_reads, 1)
        self.assertIsNone(runtime.last_result.fault)

    def test_uploaded_thumb_payload_can_publish_multiple_gpio_words(self) -> None:
        from yaju_os.qiling_runtime import QilingRuntime

        secret = b"CTF{gpio_dump_read_32_bytes!!!!}"
        runtime = QilingRuntime(secret, instruction_budget=100)
        bootloader = LegacyDfuBootloader(runtime=runtime)
        client = LegacyDfuClient(LegacyDfuGattBridge(bootloader))

        client.upload(make_gpio_dump_payload(len(secret)))

        self.assertIsNotNone(runtime.last_result)
        assert runtime.last_result is not None
        self.assertEqual(
            runtime.last_result.gatt_services[0].characteristics[0].initial_value,
            secret,
        )
        self.assertEqual(runtime.last_result.gpio_reads, len(secret) // 4)
        self.assertIsNone(runtime.last_result.fault)

    def test_nrf51_sdk11_profile_runs_a_word_aligned_uploaded_payload(self) -> None:
        from yaju_os.qiling_runtime import QilingRuntime

        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
        secret = b"0123456789abcdef0123456789abcdef"
        runtime = QilingRuntime(
            secret,
            flash_size=config.flash_size,
            sram_base=config.sram_base,
            sram_size=config.sram_size,
            instruction_budget=100,
        )
        bootloader = LegacyDfuBootloader(config=config, runtime=runtime)
        client = LegacyDfuClient(LegacyDfuGattBridge(bootloader))
        image = make_gpio_dump_payload(len(secret), application_base=config.application_base)

        client.upload(image)

        self.assertEqual(bootloader.active_image, image)
        self.assertIsNotNone(runtime.last_result)
        assert runtime.last_result is not None
        self.assertEqual(
            runtime.last_result.gatt_services[0].characteristics[0].initial_value,
            secret,
        )
        self.assertEqual(runtime.last_result.gpio_reads, len(secret) // 4)
        self.assertIsNone(runtime.last_result.fault)


if __name__ == "__main__":
    unittest.main()
