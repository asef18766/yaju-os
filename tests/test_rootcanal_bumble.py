from __future__ import annotations

import asyncio
from contextlib import suppress
import importlib.util
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from hitcon_legacy_dfu.bootloader import BootloaderConfig, LegacyDfuBootloader
from hitcon_legacy_dfu.bridge import LegacyDfuGattBridge
from hitcon_legacy_dfu.bumble_adapter import LegacyDfuBumblePeripheral
from hitcon_legacy_dfu.maintenance_runtime import MaintenanceFirmwareRuntime
from hitcon_legacy_dfu.payloads import make_gpio_dump_payload, make_gpio_probe_payload
from hitcon_legacy_dfu.protocol import (
    CONSOLE_OUTPUT_UUID,
    CONSOLE_SERVICE_UUID,
    CONTROL_POINT_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    SERVICE_UUID,
    STATUS_REPORT_UUID,
    DfuImageType,
    DfuOpcode,
    DfuResponse,
    LegacyInitPacket,
)


MAINTENANCE_REFERENCE_ELF = MaintenanceFirmwareRuntime.repository_reference_elf()
VALID_MAINTENANCE_REQUEST = bytes.fromhex("51118ecade42097126d4b05f")


class RecordingRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, int]] = []

    def run_application(self, image: bytes, application_base: int) -> None:
        self.calls.append((image, application_base))


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def _wait_for_rootcanal(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Rootcanal exited early with status {process.returncode}")
        if await asyncio.to_thread(_tcp_port_is_open, port):
            return
        else:
            await asyncio.sleep(0.05)
    raise TimeoutError("Rootcanal did not open its HCI TCP port")


def _tcp_port_is_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except OSError:
        return False


@unittest.skipUnless(
    importlib.util.find_spec("bumble") is not None
    and importlib.util.find_spec("rootcanal") is not None,
    "optional Bumble and Rootcanal dependencies are not installed",
)
class RootcanalBumbleIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Bumble's first import and native Rootcanal process startup may take a
        # little over asyncio debug mode's 100 ms diagnostic threshold.  The
        # test deliberately exercises a real native emulator, so this is not
        # an event-loop responsiveness assertion.
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_real_hci_gatt_legacy_dfu_upload_activates_firmware(self) -> None:
        image = make_gpio_probe_payload()
        runtime = RecordingRuntime()
        bootloader = await self._upload_image_over_rootcanal(image, runtime)

        self.assertEqual(bootloader.active_image, image)
        self.assertEqual(runtime.calls, [(image, bootloader.config.application_base)])

    @unittest.skipUnless(
        importlib.util.find_spec("qiling") is not None,
        "optional Qiling dependency is not installed",
    )
    async def test_real_hci_gatt_upload_reaches_qiling_gpio_peripheral(self) -> None:
        from hitcon_legacy_dfu.nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime
        from hitcon_legacy_dfu.qiling_runtime import QilingRuntime

        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
        reference_elf = Nrf51Sdk11BootloaderRuntime.repository_reference_elf()
        if not reference_elf.is_file():
            self.skipTest("built nRF51 SDK 11 reference ELF is unavailable")
        secret = b"CTF{gpio_dump_read_32_bytes!!!!}"
        image = make_gpio_dump_payload(len(secret), application_base=config.application_base)
        runtime = QilingRuntime(
            secret,
            flash_size=config.flash_size,
            sram_base=config.sram_base,
            sram_size=config.sram_size,
            instruction_budget=32,
        )
        with Nrf51Sdk11BootloaderRuntime(reference_elf) as reference_runtime:
            bootloader = await self._upload_image_over_rootcanal(
                image,
                runtime,
                config=config,
                validation_backend=reference_runtime,
                expected_console_output=secret,
            )

        self.assertEqual(bootloader.active_image, image)
        self.assertIsNotNone(runtime.last_result)
        assert runtime.last_result is not None
        self.assertEqual(runtime.last_result.uart_output, secret)
        self.assertEqual(runtime.last_result.gpio_reads, len(secret) // 4)
        self.assertIsNone(runtime.last_result.fault)

    @unittest.skipUnless(
        importlib.util.find_spec("qiling") is not None,
        "optional Qiling dependency is not installed",
    )
    async def test_real_hci_gatt_drives_compiled_sdk11_dfu_under_qiling(self) -> None:
        """Run Rootcanal ATT writes through the real SDK 11 event dispatcher."""

        from hitcon_legacy_dfu.nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime
        from hitcon_legacy_dfu.qiling_runtime import QilingRuntime

        config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
        reference_elf = Nrf51Sdk11BootloaderRuntime.repository_reference_elf()
        if not reference_elf.is_file():
            self.skipTest("built nRF51 SDK 11 reference ELF is unavailable")
        secret = b"CTF{gpio_dump_read_32_bytes!!!!}"
        image = make_gpio_dump_payload(len(secret), application_base=config.application_base)
        runtime = QilingRuntime(
            secret,
            flash_size=config.flash_size,
            sram_base=config.sram_base,
            sram_size=config.sram_size,
            instruction_budget=32,
        )
        with Nrf51Sdk11BootloaderRuntime(reference_elf) as compiled_runtime:
            result = await self._upload_image_over_rootcanal(
                image,
                runtime,
                config=config,
                compiled_bootloader_runtime=compiled_runtime,
                expected_console_output=secret,
            )
            self.assertIs(result, compiled_runtime)
            self.assertEqual(compiled_runtime.activated_image, image)

        self.assertIsNotNone(runtime.last_result)
        assert runtime.last_result is not None
        self.assertEqual(runtime.last_result.uart_output, secret)
        self.assertEqual(runtime.last_result.gpio_reads, len(secret) // 4)
        self.assertIsNone(runtime.last_result.fault)

    @unittest.skipUnless(
        importlib.util.find_spec("qiling") is not None and MAINTENANCE_REFERENCE_ELF.is_file(),
        "Qiling or the built maintenance application ELF is unavailable",
    )
    async def test_normal_application_hides_dfu_until_its_firmware_requests_boot_mode(self) -> None:
        """The player must traverse the ordinary application before seeing 1530."""

        from bumble.core import UUID
        from bumble.device import Device, Peer
        from bumble.hci import Address
        from bumble.transport import open_transport
        from hitcon_legacy_dfu.nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime
        from hitcon_legacy_dfu.qiling_rootcanal import LayeredNrf51BumblePeripheral
        from hitcon_legacy_dfu.qiling_runtime import QilingRuntime
        from rootcanal.binaries import get_package_binary_resource_path

        reference_elf = Nrf51Sdk11BootloaderRuntime.repository_reference_elf()
        if not reference_elf.is_file():
            self.skipTest("built nRF51 SDK 11 reference ELF is unavailable")
        hci_port, test_port, link_port, link_ble_port = (_unused_tcp_port() for _ in range(4))
        rootcanal_binary = Path(get_package_binary_resource_path("rootcanal"))
        if not rootcanal_binary.is_file():
            self.skipTest(f"Rootcanal binary is unavailable at {rootcanal_binary}")

        with tempfile.TemporaryFile() as rootcanal_log:
            rootcanal = await asyncio.to_thread(
                subprocess.Popen,
                [
                    str(rootcanal_binary),
                    f"--hci_port={hci_port}",
                    f"--test_port={test_port}",
                    f"--link_port={link_port}",
                    f"--link_ble_port={link_ble_port}",
                    "--enable_log_color=false",
                ],
                stdout=rootcanal_log,
                stderr=subprocess.STDOUT,
            )
            target = None
            maintenance_runtime = None
            compiled_runtime = None
            client_transport = None
            client = None
            initial_connection = None
            dfu_connection = None
            try:
                await _wait_for_rootcanal(rootcanal, hci_port)
                config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
                maintenance_runtime = MaintenanceFirmwareRuntime(MAINTENANCE_REFERENCE_ELF)
                compiled_runtime = Nrf51Sdk11BootloaderRuntime(reference_elf)
                target = LayeredNrf51BumblePeripheral(
                    maintenance_runtime,
                    compiled_runtime,
                    QilingRuntime(
                        b"CTF{initial_application_phase_test}",
                        flash_size=config.flash_size,
                        sram_base=config.sram_base,
                        sram_size=config.sram_size,
                    ),
                    application_base=config.application_base,
                )
                await target.start(f"tcp-client:127.0.0.1:{hci_port}")

                client_transport = await open_transport(f"tcp-client:127.0.0.1:{hci_port}")
                client = Device.with_hci(
                    "maintenance-phase-client",
                    Address("F0:F1:F2:F3:F4:F5"),
                    client_transport.source,
                    client_transport.sink,
                )
                await client.power_on()
                assert target.device is not None
                initial_connection = await client.connect(target.device.random_address, timeout=5)
                initial_disconnect = asyncio.Event()
                initial_connection.on(
                    initial_connection.EVENT_DISCONNECTION,
                    lambda *_args: initial_disconnect.set(),
                )
                initial_peer = Peer(initial_connection)
                self.assertEqual(
                    len(await initial_peer.discover_service(UUID(SERVICE_UUID))),
                    0,
                )
                maintenance_services = await initial_peer.discover_service(
                    UUID(MAINTENANCE_SERVICE_UUID)
                )
                self.assertEqual(len(maintenance_services), 1)
                maintenance_service = maintenance_services[0]
                await initial_peer.discover_characteristics(service=maintenance_service)
                control = initial_peer.get_characteristics_by_uuid(
                    UUID(MAINTENANCE_CONTROL_UUID), maintenance_service
                )[0]
                await initial_peer.write_value(control, VALID_MAINTENANCE_REQUEST, with_response=True)
                await asyncio.wait_for(initial_disconnect.wait(), timeout=5)
                await target.wait_for_dfu_advertising(timeout=15)
                self.assertEqual(target.phase, "dfu")

                assert target.device is not None
                dfu_connection = await self._connect_after_reset(
                    client,
                    target.device.random_address,
                )
                dfu_peer = Peer(dfu_connection)
                self.assertEqual(len(await dfu_peer.discover_service(UUID(SERVICE_UUID))), 1)
            finally:
                if dfu_connection is not None:
                    with suppress(Exception):
                        await dfu_connection.disconnect()
                if initial_connection is not None:
                    with suppress(Exception):
                        await initial_connection.disconnect()
                if client is not None:
                    with suppress(Exception):
                        await client.power_off()
                if client_transport is not None:
                    await client_transport.close()
                if target is not None:
                    await target.stop()
                if maintenance_runtime is not None:
                    maintenance_runtime.close()
                if compiled_runtime is not None:
                    compiled_runtime.close()
                rootcanal.terminate()
                try:
                    await asyncio.wait_for(asyncio.to_thread(rootcanal.wait), timeout=3)
                except TimeoutError:
                    rootcanal.kill()
                    await asyncio.to_thread(rootcanal.wait)

    async def _upload_image_over_rootcanal(
        self,
        image: bytes,
        runtime: object,
        *,
        config: BootloaderConfig | None = None,
        validation_backend: object | None = None,
        compiled_bootloader_runtime: object | None = None,
        expected_console_output: bytes | None = None,
    ) -> object:
        from bumble.core import UUID
        from bumble.device import Device, Peer
        from bumble.hci import Address
        from bumble.transport import open_transport
        from rootcanal.binaries import get_package_binary_resource_path

        hci_port, test_port, link_port, link_ble_port = (_unused_tcp_port() for _ in range(4))
        rootcanal_binary = Path(get_package_binary_resource_path("rootcanal"))
        if not rootcanal_binary.is_file():
            self.skipTest(f"Rootcanal binary is unavailable at {rootcanal_binary}")

        with tempfile.TemporaryFile() as rootcanal_log:
            rootcanal = await asyncio.to_thread(
                subprocess.Popen,
                [
                    str(rootcanal_binary),
                    f"--hci_port={hci_port}",
                    f"--test_port={test_port}",
                    f"--link_port={link_port}",
                    f"--link_ble_port={link_ble_port}",
                    "--enable_log_color=false",
                ],
                stdout=rootcanal_log,
                stderr=subprocess.STDOUT,
            )
            peripheral: object | None = None
            client_transport = None
            client: Device | None = None
            client_connection = None
            application_connection = None
            disconnected: asyncio.Event | None = None
            try:
                await _wait_for_rootcanal(rootcanal, hci_port)

                if compiled_bootloader_runtime is None:
                    bootloader: object = LegacyDfuBootloader(
                        config=config,
                        runtime=runtime,
                        validation_backend=validation_backend,
                    )
                    peripheral = LegacyDfuBumblePeripheral(LegacyDfuGattBridge(bootloader))
                else:
                    from hitcon_legacy_dfu.qiling_rootcanal import Nrf51Sdk11BumblePeripheral

                    target_config = config or BootloaderConfig.nrf51_sdk11_pca10028_s130()
                    bootloader = compiled_bootloader_runtime
                    peripheral = Nrf51Sdk11BumblePeripheral(
                        compiled_bootloader_runtime,
                        runtime,
                        application_base=target_config.application_base,
                    )
                await peripheral.start(f"tcp-client:127.0.0.1:{hci_port}")

                client_transport = await open_transport(f"tcp-client:127.0.0.1:{hci_port}")
                client = Device.with_hci(
                    "integration-client",
                    Address("F0:F1:F2:F3:F4:F5"),
                    client_transport.source,
                    client_transport.sink,
                )
                await client.power_on()
                assert peripheral.device is not None
                client_connection = await client.connect(peripheral.device.random_address, timeout=5)
                disconnected = asyncio.Event()
                client_connection.on(
                    client_connection.EVENT_DISCONNECTION,
                    lambda *_args: disconnected.set(),
                )

                peer = Peer(client_connection)
                services = await peer.discover_service(UUID(SERVICE_UUID))
                self.assertEqual(len(services), 1)
                service = services[0]
                await peer.discover_characteristics(service=service)
                control_point = peer.get_characteristics_by_uuid(UUID(CONTROL_POINT_UUID), service)[0]
                packet = peer.get_characteristics_by_uuid(UUID(PACKET_UUID), service)[0]
                notification_characteristic = control_point
                if compiled_bootloader_runtime is None:
                    notification_characteristic = peer.get_characteristics_by_uuid(
                        UUID(STATUS_REPORT_UUID), service
                    )[0]

                notifications: asyncio.Queue[bytes] = asyncio.Queue()
                await peer.subscribe(notification_characteristic, notifications.put_nowait)
                init_packet = LegacyInitPacket.for_image(image).encode()

                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.START_DFU, DfuImageType.APPLICATION)),
                    with_response=True,
                )
                await peer.write_value(packet, struct.pack("<III", 0, 0, len(image)))
                await self._expect_notification(
                    notifications,
                    bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.START_DFU, DfuResponse.SUCCESS)),
                )

                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 0)),
                    with_response=True,
                )
                await peer.write_value(packet, init_packet)
                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.INITIALIZE_DFU_PARAMETERS, 1)),
                    with_response=True,
                )
                await self._expect_notification(
                    notifications,
                    bytes(
                        (
                            DfuOpcode.RESPONSE_CODE,
                            DfuOpcode.INITIALIZE_DFU_PARAMETERS,
                            DfuResponse.SUCCESS,
                        )
                    ),
                )

                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION_REQUEST, 1, 0)),
                    with_response=True,
                )
                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.RECEIVE_FIRMWARE_IMAGE,)),
                    with_response=True,
                )
                bytes_sent = 0
                for offset in range(0, len(image), 20):
                    chunk = image[offset : offset + 20]
                    bytes_sent += len(chunk)
                    await peer.write_value(packet, chunk)
                    if compiled_bootloader_runtime is None:
                        await self._expect_notification(
                            notifications,
                            bytes((DfuOpcode.PACKET_RECEIPT_NOTIFICATION,))
                            + struct.pack("<I", bytes_sent),
                        )

                if compiled_bootloader_runtime is not None:
                    # SDK 11 acknowledges RECEIVE_FIRMWARE_IMAGE from its
                    # first packet callback; packet receipt reports can be
                    # interleaved with it depending on the scheduler timing.
                    await self._expect_notification(
                        notifications,
                        bytes(
                            (
                                DfuOpcode.RESPONSE_CODE,
                                DfuOpcode.RECEIVE_FIRMWARE_IMAGE,
                                DfuResponse.SUCCESS,
                            )
                        ),
                        allow_unrelated=True,
                    )

                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.VALIDATE_FIRMWARE,)),
                    with_response=True,
                )
                await self._expect_notification(
                    notifications,
                    bytes((DfuOpcode.RESPONSE_CODE, DfuOpcode.VALIDATE_FIRMWARE, DfuResponse.SUCCESS)),
                    allow_unrelated=compiled_bootloader_runtime is not None,
                )
                await peer.write_value(
                    control_point,
                    bytes((DfuOpcode.ACTIVATE_AND_RESET,)),
                    with_response=True,
                )
                await asyncio.wait_for(disconnected.wait(), timeout=5)
                await peripheral.wait_for_application_advertising(timeout=5)

                if expected_console_output is not None:
                    assert peripheral.device is not None
                    application_connection = await self._connect_after_reset(
                        client,
                        peripheral.device.random_address,
                    )
                    application_peer = Peer(application_connection)
                    console_services = await application_peer.discover_service(UUID(CONSOLE_SERVICE_UUID))
                    self.assertEqual(len(console_services), 1)
                    console_service = console_services[0]
                    await application_peer.discover_characteristics(service=console_service)
                    console_output = application_peer.get_characteristics_by_uuid(
                        UUID(CONSOLE_OUTPUT_UUID),
                        console_service,
                    )[0]
                    self.assertEqual(
                        await application_peer.read_value(console_output),
                        expected_console_output,
                    )
                return bootloader
            finally:
                if application_connection is not None:
                    try:
                        await application_connection.disconnect()
                    except Exception:
                        pass
                if client_connection is not None and (disconnected is None or not disconnected.is_set()):
                    try:
                        await client_connection.disconnect()
                    except Exception:
                        pass
                if client is not None:
                    await client.power_off()
                if client_transport is not None:
                    await client_transport.close()
                if peripheral is not None:
                    await peripheral.stop()
                rootcanal.terminate()
                try:
                    await asyncio.wait_for(asyncio.to_thread(rootcanal.wait), timeout=3)
                except TimeoutError:
                    rootcanal.kill()
                    await asyncio.to_thread(rootcanal.wait)

    async def _expect_notification(
        self,
        notifications: asyncio.Queue[bytes],
        expected: bytes,
        *,
        allow_unrelated: bool = False,
    ) -> None:
        deadline = time.monotonic() + 3
        while True:
            received = await asyncio.wait_for(
                notifications.get(),
                timeout=max(0.01, deadline - time.monotonic()),
            )
            if received == expected:
                return
            if not allow_unrelated:
                self.assertEqual(received, expected)

    async def _connect_after_reset(self, client, address):
        deadline = time.monotonic() + 5
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return await client.connect(address, timeout=0.5)
            except Exception as error:
                last_error = error
                await asyncio.sleep(0.05)
        if last_error is not None:
            raise last_error
        raise TimeoutError("target did not resume advertising after reset")


if __name__ == "__main__":
    unittest.main()
