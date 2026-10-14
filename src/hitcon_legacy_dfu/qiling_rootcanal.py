"""Rootcanal/Bumble peripheral backed by the compiled Nordic SDK 11 ELF.

The transport boundary is deliberately small and explicit:

* Bumble owns a real HCI controller connection and ATT/GATT server.
* :class:`Nrf51Sdk11BootloaderRuntime` turns those callbacks into S130 BLE
  events for the compiled bootloader running under Qiling.
* S130's radio implementation is still represented by the runtime's narrow
  ABI shim; this module does not claim to emulate the proprietary SoftDevice.

Consequently, the legacy DFU state machine, init-packet checks, CRC,
``pstorage_raw`` flash queue, and dual-bank image copy are all ARM code from
the official SDK ELF rather than a second Python transfer implementation.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import struct
from typing import TYPE_CHECKING, Protocol

from .bumble_adapter import BumbleUnavailable
from .nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime, Nrf51Sdk11RuntimeError
from .protocol import (
    CONSOLE_OUTPUT_UUID,
    CONSOLE_SERVICE_UUID,
    CONTROL_POINT_UUID,
    PACKET_UUID,
    REVISION_UUID,
    SERVICE_UUID,
    DfuOpcode,
)

if TYPE_CHECKING:
    from bumble.device import Connection, Device
    from bumble.gatt import Characteristic
    from bumble.transport.common import Transport


class ApplicationRuntime(Protocol):
    """The post-reset execution boundary used by the CTF board."""

    def run_application(self, image: bytes, application_base: int) -> object: ...


class Nrf51Sdk11BumblePeripheral:
    """Expose a real SDK 11 legacy DFU bootloader over Rootcanal HCI.

    This is intentionally separate from :class:`LegacyDfuBumblePeripheral`:
    the latter is useful as a compact challenge model, while this class has no
    Python legacy-DFU state machine at all.  Every DFU command is delivered to
    the reference ELF through Qiling.
    """

    def __init__(
        self,
        bootloader_runtime: Nrf51Sdk11BootloaderRuntime,
        application_runtime: ApplicationRuntime,
        *,
        application_base: int = 0x1B000,
        name: str = "HITCON Legacy DFU",
        address: str = "F6:F7:F8:F9:FA:FB",
        revision: int = 8,
    ) -> None:
        encoded_name = name.encode("utf-8")
        if not encoded_name or len(encoded_name) > 29:
            raise ValueError("BLE local name must be between 1 and 29 UTF-8 bytes")
        if not 0 <= revision <= 0xFFFF:
            raise ValueError("revision must fit in uint16")
        if not 0 <= application_base <= 0xFFFF_FFFF:
            raise ValueError("application_base must fit in uint32")

        self.bootloader_runtime = bootloader_runtime
        self.application_runtime = application_runtime
        self.application_base = application_base
        self.name = name
        self.address = address
        self.revision = revision
        self.device: Device | None = None
        self._transport: Transport | None = None
        self._connection: Connection | None = None
        self._control_point: Characteristic[bytes] | None = None
        self._packet: Characteristic[bytes] | None = None
        self._console_output: Characteristic[bytes] | None = None
        self._write_lock: asyncio.Lock | None = None
        self._advertising_data: bytes | None = None
        self._scan_response_data: bytes | None = None
        self._application_reset_task: asyncio.Task[None] | None = None
        self._application_advertising_ready: asyncio.Event | None = None
        self._phase = "dfu"
        self._console_bytes = b""
        self._application_fault: str | None = None

    @property
    def connected(self) -> bool:
        """Whether a central currently owns the target connection."""

        return self._connection is not None

    @property
    def application_fault(self) -> str | None:
        """A malformed player image must not terminate the BLE target process."""

        return self._application_fault

    async def start(self, hci_transport: str) -> None:
        """Boot the ELF, attach target HCI, and begin real BLE advertising."""

        if self.device is not None:
            raise RuntimeError("peripheral is already running")

        try:
            from bumble import att
            from bumble.core import AdvertisingData, UUID
            from bumble.device import Device
            from bumble.gatt import Characteristic, CharacteristicValue, Service
            from bumble.hci import Address
            from bumble.transport import open_transport
        except ModuleNotFoundError as exc:
            raise BumbleUnavailable(
                "Bumble is optional; install the project with the 'transport' extra"
            ) from exc

        # Run Reset_Handler and construct the SDK service before accepting an
        # ATT connection.  Subsequent per-write calls go through a lock and a
        # worker thread, so the Rootcanal HCI pump remains responsive while
        # pstorage processes a page erase or application copy.
        await asyncio.to_thread(self.bootloader_runtime.boot)
        _ = self.bootloader_runtime.dfu_handles
        self._att_unlikely_error = att.ATT_UNLIKELY_ERROR_ERROR
        self._write_lock = asyncio.Lock()
        self._application_advertising_ready = asyncio.Event()
        transport = await open_transport(hci_transport)
        try:
            device = Device.with_hci(
                self.name,
                Address(self.address),
                transport.source,
                transport.sink,
            )

            # SDK 11 has the response notification on the control point
            # itself (1531), not the model-only 1533 status characteristic.
            control_point = Characteristic(
                CONTROL_POINT_UUID,
                Characteristic.Properties.WRITE | Characteristic.Properties.NOTIFY,
                Characteristic.WRITEABLE,
                CharacteristicValue(write=self._on_control_point_write),
            )
            packet = Characteristic(
                PACKET_UUID,
                Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
                Characteristic.WRITEABLE,
                CharacteristicValue(write=self._on_packet_write),
            )
            revision = Characteristic(
                REVISION_UUID,
                Characteristic.Properties.READ,
                Characteristic.READABLE,
                struct.pack("<H", self.revision),
            )
            console_output = Characteristic(
                CONSOLE_OUTPUT_UUID,
                Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
                Characteristic.READABLE,
                CharacteristicValue(read=self._read_console_output),
            )
            control_point.on(Characteristic.EVENT_SUBSCRIPTION, self._on_control_point_subscription)
            # Put packet first to match the service construction order in the
            # official target.  External ATT handles need not equal the
            # SoftDevice handles: callbacks below map each GATT operation to
            # the actual handle allocated inside the ELF.
            device.add_service(Service(SERVICE_UUID, [packet, control_point, revision]))
            device.add_service(Service(CONSOLE_SERVICE_UUID, [console_output]))
            device.on(device.EVENT_CONNECTION, self._on_connection)

            advertising_data = bytes(
                AdvertisingData(
                    [
                        (AdvertisingData.FLAGS, bytes((0x06,))),
                        (
                            AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                            UUID(SERVICE_UUID).to_bytes(force_128=True),
                        ),
                    ]
                )
            )
            scan_response_data = bytes(
                AdvertisingData(
                    [(AdvertisingData.COMPLETE_LOCAL_NAME, self.name.encode("utf-8"))]
                )
            )

            self.device = device
            self._transport = transport
            self._control_point = control_point
            self._packet = packet
            self._console_output = console_output
            self._advertising_data = advertising_data
            self._scan_response_data = scan_response_data
            await device.power_on()
            await device.start_advertising(
                auto_restart=False,
                advertising_data=advertising_data,
                scan_response_data=scan_response_data,
            )
        except BaseException:
            await transport.close()
            self._clear_runtime_state()
            raise

    async def stop(self) -> None:
        """Stop advertising and release the target-side HCI controller."""

        reset_task = self._application_reset_task
        if reset_task is not None:
            reset_task.cancel()
            with suppress(asyncio.CancelledError):
                await reset_task
        if self.bootloader_runtime.connected:
            with suppress(Exception):
                await asyncio.to_thread(self.bootloader_runtime.disconnect)
        device = self.device
        transport = self._transport
        self._clear_runtime_state()
        if device is not None:
            with suppress(Exception):
                await device.stop_advertising()
            with suppress(Exception):
                await device.power_off()
        if transport is not None:
            await transport.close()

    async def __aenter__(self) -> "Nrf51Sdk11BumblePeripheral":
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.stop()

    async def wait_for_application_advertising(self, timeout: float | None = None) -> None:
        """Wait until activation reset has exposed the application console."""

        ready = self._application_advertising_ready
        if ready is None:
            raise RuntimeError("peripheral is not running")
        if timeout is None:
            await ready.wait()
        else:
            await asyncio.wait_for(ready.wait(), timeout)

    def _clear_runtime_state(self) -> None:
        self._connection = None
        self._control_point = None
        self._packet = None
        self._console_output = None
        self._write_lock = None
        self._advertising_data = None
        self._scan_response_data = None
        self._application_reset_task = None
        self._application_advertising_ready = None
        self.device = None
        self._transport = None

    def _on_connection(self, connection: Connection) -> None:
        if self._connection is not None and self._connection is not connection:
            asyncio.create_task(connection.disconnect())
            return
        if self._connection is connection:
            return

        self._connection = connection
        if self._phase == "dfu":
            try:
                # The reference ELF was booted during start(), so this simply
                # calls its compiled BLE dispatcher for BLE_GAP_EVT_CONNECTED.
                # Preserve the actual HCI connection handle so every later
                # synthesized GATT event belongs to the same S130 peer.
                self.bootloader_runtime.connect(int(connection.handle))
            except Exception:
                self._connection = None
                asyncio.create_task(connection.disconnect())
                return
        connection.on(
            connection.EVENT_DISCONNECTION,
            lambda *_args: self._on_disconnection(connection),
        )

    def _on_disconnection(self, connection: Connection) -> None:
        if self._connection is not connection:
            return
        self._connection = None
        # Even after a successful activation the physical BLE disconnect is a
        # real GAP event from the bootloader's perspective.  Keeping its host
        # mirror in sync prevents a stale connection from accepting later
        # DFU writes through the still-present challenge console GATT server.
        if self.bootloader_runtime.connected:
            with suppress(Exception):
                self.bootloader_runtime.disconnect()

    def _on_control_point_subscription(
        self,
        connection: Connection,
        notify_enabled: bool,
        _indicate_enabled: bool,
    ) -> None:
        if self._connection is None:
            self._on_connection(connection)
        if self._connection is connection and self._phase == "dfu":
            self.bootloader_runtime.set_control_point_notifications(notify_enabled)

    async def _on_control_point_write(self, connection: Connection, payload: bytes) -> None:
        await self._write_from_gatt(connection, payload, control_point=True)

    async def _on_packet_write(self, connection: Connection, payload: bytes) -> None:
        await self._write_from_gatt(connection, payload, control_point=False)

    async def _write_from_gatt(
        self,
        connection: Connection,
        payload: bytes,
        *,
        control_point: bool,
    ) -> None:
        lock = self._write_lock
        if lock is None:
            raise RuntimeError("peripheral is not running")

        async with lock:
            if self._connection is None:
                self._on_connection(connection)
            if self._connection is not connection or self._phase != "dfu":
                self._raise_att_error()

            try:
                result = await asyncio.to_thread(
                    self.bootloader_runtime.write_control_point
                    if control_point
                    else self.bootloader_runtime.write_packet,
                    bytes(payload),
                )
            except (Nrf51Sdk11RuntimeError, ValueError):
                self._raise_att_error()
                return

            await self._send_notifications(result.notifications)

            if control_point and payload[:1] == bytes((DfuOpcode.ACTIVATE_AND_RESET,)):
                image = result.activated_image
                if image is not None:
                    await self._run_application(image)
                    self._phase = "application"

            if result.disconnect_requested:
                if self._application_advertising_ready is not None:
                    self._application_advertising_ready.clear()
                self._application_reset_task = asyncio.create_task(
                    self._disconnect_and_restart(connection, self._phase == "application")
                )

    def _raise_att_error(self) -> None:
        from bumble.att import ATT_Error

        raise ATT_Error(error_code=self._att_unlikely_error)

    async def _send_notifications(self, notifications: tuple[bytes, ...]) -> None:
        if not notifications:
            return
        device = self.device
        control_point = self._control_point
        if device is None or control_point is None:
            return
        for payload in notifications:
            await device.notify_subscribers(control_point, payload)

    async def _run_application(self, image: bytes) -> None:
        try:
            execution = await asyncio.to_thread(
                self.application_runtime.run_application,
                image,
                self.application_base,
            )
        except Exception as exc:
            self._application_fault = f"{type(exc).__name__}: {exc}"
            self._console_bytes = b""
            return

        output = getattr(execution, "uart_output", b"")
        self._console_bytes = bytes(output) if isinstance(output, (bytes, bytearray)) else b""
        self._application_fault = getattr(execution, "fault", None)
        await self._publish_console_output()

    def _read_console_output(self, _connection: Connection) -> bytes:
        return self._console_bytes

    async def _publish_console_output(self) -> None:
        device = self.device
        console_output = self._console_output
        if device is not None and console_output is not None and self._console_bytes:
            await device.notify_subscribers(console_output, self._console_bytes)

    async def _disconnect_and_restart(self, connection: Connection, application: bool) -> None:
        await asyncio.sleep(0)
        try:
            if self._connection is connection:
                with suppress(Exception):
                    await connection.disconnect()

            device = self.device
            if (
                device is not None
                and self._advertising_data is not None
                and self._scan_response_data is not None
            ):
                with suppress(Exception):
                    await device.start_advertising(
                        auto_restart=False,
                        advertising_data=self._advertising_data,
                        scan_response_data=self._scan_response_data,
                    )
                if application and self._application_advertising_ready is not None:
                    self._application_advertising_ready.set()
        finally:
            if self._application_reset_task is asyncio.current_task():
                self._application_reset_task = None
