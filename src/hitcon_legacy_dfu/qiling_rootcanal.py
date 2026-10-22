"""Rootcanal/Bumble peripheral backed by the compiled Nordic SDK 11 ELF.

The transport boundary is deliberately small and explicit:

* Bumble owns the HCI/ATT transport that represents the proprietary S130.
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

from .gatt_ids import (
    CONTROL_POINT_UUID,
    MAINTENANCE_CONTROL_UUID,
    MAINTENANCE_INFO_UUID,
    MAINTENANCE_SERVICE_UUID,
    PACKET_UUID,
    REVISION_UUID,
    SERVICE_UUID,
    DfuOpcode,
)
from .maintenance_runtime import FirmwareGattService, MaintenanceFirmwareRuntime
from .nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime, Nrf51Sdk11RuntimeError

if TYPE_CHECKING:
    from bumble.device import Connection, Device
    from bumble.gatt import Characteristic
    from bumble.transport.common import Transport

    from .s130_gatt import S130GattServer


# Rootcanal consumes an HCI TCP EOF on its own event loop.  Reopening the same
# static random address before that EOF is processed can leave the central
# matched to the retiring controller.  A board reset therefore includes a
# short controller-detach interval before the replacement begins advertising.
_CONTROLLER_REPLACEMENT_DELAY = 0.1

# S130 2.0.0 on nRF51 is a Bluetooth 4.1 stack: its ATT MTU is fixed at 23, so
# the real target answers every Exchange MTU Request with 23 and never accepts
# a DFU packet longer than twenty value bytes.  Bumble's server would otherwise
# negotiate up to its own 517-byte maximum, which lets a standards-compliant
# central (nRF Connect for Android requests 517 before a legacy DFU upload)
# send writes the compiled bootloader rejects.
_S130_ATT_MTU = 23


def _fix_att_mtu_to_s130(device: "Device") -> None:
    """Negotiate the single ATT MTU that the modelled SoftDevice supports."""

    device.gatt_server.max_mtu = _S130_ATT_MTU


class BumbleUnavailable(RuntimeError):
    """The optional Bumble/Rootcanal transport dependencies are unavailable."""


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
        self._hci_transport: str | None = None
        self._connection: Connection | None = None
        self._control_point: Characteristic[bytes] | None = None
        self._packet: Characteristic[bytes] | None = None
        self._write_lock: asyncio.Lock | None = None
        self._advertising_data: bytes | None = None
        self._scan_response_data: bytes | None = None
        self._application_reset_task: asyncio.Task[None] | None = None
        self._application_advertising_ready: asyncio.Event | None = None
        self._phase = "dfu"
        self._application_services: tuple[FirmwareGattService, ...] = ()
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
        self._hci_transport = hci_transport
        self._phase = "dfu"
        self._application_services = ()
        self._application_fault = None
        transport = await open_transport(hci_transport)
        try:
            device = Device.with_hci(
                self.name,
                Address(self.address),
                transport.source,
                transport.sink,
            )
            _fix_att_mtu_to_s130(device)

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
            control_point.on(Characteristic.EVENT_SUBSCRIPTION, self._on_control_point_subscription)
            # Put packet first to match the service construction order in the
            # official target.  External ATT handles need not equal the
            # SoftDevice handles: callbacks below map each GATT operation to
            # the actual handle allocated inside the ELF.
            device.add_service(Service(SERVICE_UUID, [packet, control_point, revision]))
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
        """Wait until reset has exposed the uploaded firmware's GATT table."""

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
        self._write_lock = None
        self._advertising_data = None
        self._scan_response_data = None
        self._application_reset_task = None
        self._application_advertising_ready = None
        self.device = None
        self._transport = None
        self._hci_transport = None

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
        # A successful activation still delivers a real GAP disconnect to the
        # compiled bootloader before its controller is replaced.
        if self.bootloader_runtime.connected:
            with suppress(Exception):
                self.bootloader_runtime.disconnect()
        if self._application_reset_task is None:
            # A reset owns advertising itself; any other disconnect is the
            # ordinary one the board survives.
            self._restart_advertising()

    def _restart_advertising(self) -> None:
        """Advertise again after a disconnect, exactly as the board does.

        Both the SDK 11 bootloader and an ordinary nRF51 application call
        ``advertising_start`` from their ``BLE_GAP_EVT_DISCONNECTED`` handler,
        so a central may connect, drop the link, and come back.  Centrals rely
        on it: nRF Connect for Android closes its own GATT connection before
        handing the device to its DFU service.
        """

        device = self.device
        advertising_data = self._advertising_data
        scan_response_data = self._scan_response_data
        if device is None or advertising_data is None or scan_response_data is None:
            return

        async def restart() -> None:
            with suppress(Exception):
                await device.start_advertising(
                    auto_restart=False,
                    advertising_data=advertising_data,
                    scan_response_data=scan_response_data,
                )

        asyncio.create_task(restart())

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
            self._application_services = ()
            return

        try:
            services = getattr(execution, "gatt_services", ())
            normalized = tuple(services) if services is not None else ()
            self._validate_application_services(normalized)
        except Exception as exc:
            self._application_services = ()
            self._application_fault = f"{type(exc).__name__}: {exc}"
            return
        self._application_services = normalized
        self._application_fault = getattr(execution, "fault", None)

    @staticmethod
    def _validate_application_services(
        services: tuple[FirmwareGattService, ...],
    ) -> None:
        from uuid import UUID

        for service in services:
            UUID(service.uuid)
            if not service.primary:
                raise ValueError("uploaded firmware registered a secondary service")
            for characteristic in service.characteristics:
                UUID(characteristic.uuid)
                if (
                    characteristic.properties != 0x02
                    or not characteristic.readable
                    or characteristic.writable
                    or characteristic.read_authorized
                ):
                    raise ValueError(
                        "uploaded application GATT characteristics must be static read-only"
                    )
                if len(characteristic.initial_value) > characteristic.max_length:
                    raise ValueError("uploaded characteristic exceeds its maximum length")

    async def _disconnect_and_restart(self, connection: Connection, application: bool) -> None:
        await asyncio.sleep(0)
        try:
            if self._connection is connection:
                with suppress(Exception):
                    await connection.disconnect()

            if application:
                await self._replace_with_application_device()
                if self._application_advertising_ready is not None:
                    self._application_advertising_ready.set()
            else:
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
        finally:
            if self._application_reset_task is asyncio.current_task():
                self._application_reset_task = None

    async def _replace_with_application_device(self) -> None:
        """Model reset by replacing the DFU controller and attribute table."""

        try:
            from bumble.core import AdvertisingData, UUID
            from bumble.device import Device
            from bumble.gatt import Characteristic, Service
            from bumble.hci import Address
            from bumble.transport import open_transport
        except ModuleNotFoundError as exc:  # pragma: no cover - checked by start()
            raise BumbleUnavailable(
                "Bumble is optional; install the project with the 'transport' extra"
            ) from exc

        old_device = self.device
        old_transport = self._transport
        hci_transport = self._hci_transport
        if hci_transport is None:
            raise RuntimeError("peripheral has no HCI transport to reset")

        self.device = None
        self._transport = None
        self._control_point = None
        self._packet = None
        self._advertising_data = None
        self._scan_response_data = None
        if old_device is not None:
            with suppress(Exception):
                await old_device.stop_advertising()
            with suppress(Exception):
                await old_device.power_off()
        if old_transport is not None:
            await old_transport.close()
            await asyncio.sleep(_CONTROLLER_REPLACEMENT_DELAY)

        transport = await open_transport(hci_transport)
        try:
            device = Device.with_hci(
                self.name,
                Address(self.address),
                transport.source,
                transport.sink,
            )
            _fix_att_mtu_to_s130(device)
            installed_service_uuids: list[str] = []
            for definition in self._application_services:
                characteristics: list[Characteristic[bytes]] = []
                for characteristic in definition.characteristics:
                    characteristics.append(
                        Characteristic(
                            characteristic.uuid,
                            Characteristic.Properties.READ,
                            Characteristic.READABLE,
                            characteristic.initial_value,
                        )
                    )
                if characteristics:
                    device.add_service(Service(definition.uuid, characteristics))
                    installed_service_uuids.append(definition.uuid)
            device.on(device.EVENT_CONNECTION, self._on_connection)

            fields: list[tuple[int, bytes]] = [
                (AdvertisingData.FLAGS, bytes((0x06,)))
            ]
            if installed_service_uuids:
                fields.append(
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                        UUID(installed_service_uuids[0]).to_bytes(force_128=True),
                    )
                )
            advertising_data = bytes(AdvertisingData(fields))
            scan_response_data = bytes(
                AdvertisingData(
                    [(AdvertisingData.COMPLETE_LOCAL_NAME, self.name.encode("utf-8"))]
                )
            )
            self.device = device
            self._transport = transport
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
            self.device = None
            self._transport = None
            raise


class MaintenanceApplicationBumblePeripheral:
    """Initial non-DFU board service backed by a compiled Thumb application.

    This service intentionally has no Nordic DFU UUID.  Its only writable
    characteristic asks the normal application to enter maintenance boot
    mode.  The authorization routine itself is executed in Qiling by
    :class:`MaintenanceFirmwareRuntime`; this class only owns HCI/GATT and the
    physical disconnect that a reset would cause. The compiled application
    registers and handles its read-only ASCII service through S130 calls;
    Bumble is only the emulated SoftDevice/ATT transport.
    """

    def __init__(
        self,
        runtime: MaintenanceFirmwareRuntime,
        *,
        name: str = "HITCON Field Node",
        address: str = "F6:F7:F8:F9:FA:FB",
    ) -> None:
        encoded_name = name.encode("utf-8")
        if not encoded_name or len(encoded_name) > 29:
            raise ValueError("BLE local name must be between 1 and 29 UTF-8 bytes")
        self.runtime = runtime
        self.name = name
        self.address = address
        self.device: Device | None = None
        self._transport: Transport | None = None
        self._connection: Connection | None = None
        self._control: Characteristic[bytes] | None = None
        self._firmware_gatt_server: S130GattServer | None = None
        self._advertising_data: bytes | None = None
        self._scan_response_data: bytes | None = None
        self._write_lock: asyncio.Lock | None = None
        self._bootloader_requested: asyncio.Event | None = None
        self._handoff_ready: asyncio.Event | None = None
        self._disconnect_task: asyncio.Task[None] | None = None
        self._att_unlikely_error: int | None = None

    @property
    def connected(self) -> bool:
        return self._connection is not None

    async def start(self, hci_transport: str) -> None:
        """Attach the ordinary application service to its HCI controller."""

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

        from .s130_gatt import S130GattServer

        # Fail before exposing a radio if the intended player handout cannot
        # be loaded or has lost the firmware entry point.
        await asyncio.to_thread(self.runtime.boot)
        self._att_unlikely_error = att.ATT_UNLIKELY_ERROR_ERROR
        self._write_lock = asyncio.Lock()
        self._bootloader_requested = asyncio.Event()
        self._handoff_ready = asyncio.Event()
        transport = await open_transport(hci_transport)
        try:
            device = Device.with_hci(
                self.name,
                Address(self.address),
                transport.source,
                transport.sink,
            )
            _fix_att_mtu_to_s130(device)
            control = Characteristic(
                MAINTENANCE_CONTROL_UUID,
                Characteristic.Properties.WRITE,
                Characteristic.WRITEABLE,
                CharacteristicValue(write=self._on_control_write),
            )
            info = Characteristic(
                MAINTENANCE_INFO_UUID,
                Characteristic.Properties.READ,
                Characteristic.READABLE,
                b"FN2\x01",
            )
            device.add_service(Service(MAINTENANCE_SERVICE_UUID, [control, info]))
            firmware_gatt_server = S130GattServer.install(device, self.runtime)
            device.on(device.EVENT_CONNECTION, self._on_connection)
            advertising_data = bytes(
                AdvertisingData(
                    [
                        (AdvertisingData.FLAGS, bytes((0x06,))),
                        (
                            # Both vendor UUIDs do not fit in a legacy 31-byte
                            # advertisement. Discover the animation over GATT.
                            AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                            UUID(MAINTENANCE_SERVICE_UUID).to_bytes(force_128=True),
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
            self._control = control
            self._firmware_gatt_server = firmware_gatt_server
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
        """Stop the normal application target before its bootloader replaces it."""

        disconnect_task = self._disconnect_task
        if disconnect_task is not None and disconnect_task is not asyncio.current_task():
            disconnect_task.cancel()
            with suppress(asyncio.CancelledError):
                await disconnect_task
        if self.runtime.connected:
            with suppress(Exception):
                await asyncio.to_thread(self.runtime.disconnect)
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

    async def wait_for_bootloader_request(self, timeout: float | None = None) -> None:
        event = self._bootloader_requested
        if event is None:
            raise RuntimeError("peripheral is not running")
        if timeout is None:
            await event.wait()
        else:
            await asyncio.wait_for(event.wait(), timeout)

    async def wait_for_handoff(self, timeout: float | None = None) -> None:
        """Wait until the accepted write has had a chance to return over ATT."""

        event = self._handoff_ready
        if event is None:
            raise RuntimeError("peripheral is not running")
        if timeout is None:
            await event.wait()
        else:
            await asyncio.wait_for(event.wait(), timeout)

    def _clear_runtime_state(self) -> None:
        self._connection = None
        self._control = None
        self._firmware_gatt_server = None
        self._write_lock = None
        self._bootloader_requested = None
        self._handoff_ready = None
        self._disconnect_task = None
        self._att_unlikely_error = None
        self._advertising_data = None
        self._scan_response_data = None
        self.device = None
        self._transport = None

    def _on_connection(self, connection: Connection) -> None:
        if self._connection is not None and self._connection is not connection:
            asyncio.create_task(connection.disconnect())
            return
        if self._connection is connection:
            return
        self._connection = connection
        firmware_gatt_server = self._firmware_gatt_server
        if firmware_gatt_server is not None:
            try:
                firmware_gatt_server.connect_connection(
                    connection, int(connection.handle)
                )
            except Exception:
                self._connection = None
                asyncio.create_task(connection.disconnect())
                return
        connection.on(
            connection.EVENT_DISCONNECTION,
            lambda *_args: self._on_disconnection(connection),
        )

    def _on_disconnection(self, connection: Connection) -> None:
        if self._connection is connection:
            firmware_gatt_server = self._firmware_gatt_server
            if firmware_gatt_server is not None:
                with suppress(Exception):
                    firmware_gatt_server.disconnect_connection(connection)
            self._connection = None
            requested = self._bootloader_requested
            if requested is None or not requested.is_set():
                # Only an accepted maintenance request retires this controller;
                # a plain disconnect leaves the application advertising.
                self._restart_advertising()

    def _restart_advertising(self) -> None:
        """Advertise again after a disconnect the application survives."""

        device = self.device
        advertising_data = self._advertising_data
        scan_response_data = self._scan_response_data
        if device is None or advertising_data is None or scan_response_data is None:
            return

        async def restart() -> None:
            with suppress(Exception):
                await device.start_advertising(
                    auto_restart=False,
                    advertising_data=advertising_data,
                    scan_response_data=scan_response_data,
                )

        asyncio.create_task(restart())

    async def _on_control_write(self, connection: Connection, payload: bytes) -> None:
        lock = self._write_lock
        if lock is None:
            raise RuntimeError("peripheral is not running")
        async with lock:
            if self._connection is None:
                self._on_connection(connection)
            if self._connection is not connection:
                self._raise_att_error()

            accepted = await asyncio.to_thread(self.runtime.request_bootloader, bytes(payload))
            if not accepted:
                self._raise_att_error()
            event = self._bootloader_requested
            if event is None:
                raise RuntimeError("peripheral is not running")
            event.set()
            if self._disconnect_task is None:
                self._disconnect_task = asyncio.create_task(
                    self._disconnect_after_boot_request(connection)
                )

    def _raise_att_error(self) -> None:
        from bumble.att import ATT_Error

        assert self._att_unlikely_error is not None
        raise ATT_Error(error_code=self._att_unlikely_error)

    async def _disconnect_after_boot_request(self, connection: Connection) -> None:
        # Returning to the event loop first lets Bumble emit the successful
        # ATT Write Response before the reset's physical disconnect.
        await asyncio.sleep(0)
        try:
            if self._connection is connection:
                with suppress(Exception):
                    await connection.disconnect()
        finally:
            handoff = self._handoff_ready
            if handoff is not None:
                handoff.set()
            if self._disconnect_task is asyncio.current_task():
                self._disconnect_task = None


class LayeredNrf51BumblePeripheral:
    """Expose an ordinary application first, then the real legacy DFU target.

    A successful app-controlled GPREGRET request tears down its target-side
    HCI controller and starts a fresh controller with the same BLE address.
    This gives a player the normal disconnect/reconnect boundary of a board
    reset and prevents discovery of Nordic's ``1530`` service beforehand.
    """

    def __init__(
        self,
        maintenance_runtime: MaintenanceFirmwareRuntime,
        bootloader_runtime: Nrf51Sdk11BootloaderRuntime,
        application_runtime: ApplicationRuntime,
        *,
        application_base: int = 0x1B000,
        name: str = "HITCON Field Node",
        address: str = "F6:F7:F8:F9:FA:FB",
        revision: int = 8,
    ) -> None:
        self.maintenance_runtime = maintenance_runtime
        self.bootloader_runtime = bootloader_runtime
        self.application_runtime = application_runtime
        self.application_base = application_base
        self.name = name
        self.address = address
        self.revision = revision
        self._maintenance = MaintenanceApplicationBumblePeripheral(
            maintenance_runtime,
            name=name,
            address=address,
        )
        self._dfu: Nrf51Sdk11BumblePeripheral | None = None
        self._hci_transport: str | None = None
        self._handoff_task: asyncio.Task[None] | None = None
        self._dfu_advertising_ready: asyncio.Event | None = None
        self._stopping = False
        self._phase = "maintenance"
        self._handoff_error: Exception | None = None

    @property
    def device(self) -> Device | None:
        if self._dfu is not None:
            return self._dfu.device
        return self._maintenance.device

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def handoff_error(self) -> Exception | None:
        return self._handoff_error

    async def start(self, hci_transport: str) -> None:
        if self._hci_transport is not None:
            raise RuntimeError("peripheral is already running")
        self._stopping = False
        self._phase = "maintenance"
        self._handoff_error = None
        self._dfu_advertising_ready = asyncio.Event()
        self._hci_transport = hci_transport
        try:
            await self._maintenance.start(hci_transport)
            self._handoff_task = asyncio.create_task(self._handoff_to_legacy_dfu())
        except BaseException:
            self._hci_transport = None
            self._dfu_advertising_ready = None
            raise

    async def stop(self) -> None:
        self._stopping = True
        handoff_task = self._handoff_task
        if handoff_task is not None and handoff_task is not asyncio.current_task():
            handoff_task.cancel()
            with suppress(asyncio.CancelledError):
                await handoff_task
        self._handoff_task = None
        if self._dfu is not None:
            await self._dfu.stop()
            self._dfu = None
        await self._maintenance.stop()
        self._hci_transport = None
        self._dfu_advertising_ready = None

    async def wait_for_dfu_advertising(self, timeout: float | None = None) -> None:
        """Wait for the post-reset legacy DFU service to be advertised."""

        event = self._dfu_advertising_ready
        if event is None:
            raise RuntimeError("peripheral is not running")
        if timeout is None:
            await event.wait()
        else:
            await asyncio.wait_for(event.wait(), timeout)
        if self._handoff_error is not None:
            raise RuntimeError("maintenance-to-DFU handoff failed") from self._handoff_error

    async def _handoff_to_legacy_dfu(self) -> None:
        try:
            await self._maintenance.wait_for_bootloader_request()
            await self._maintenance.wait_for_handoff()
            if self._stopping:
                return
            await self._maintenance.stop()
            await asyncio.sleep(_CONTROLLER_REPLACEMENT_DELAY)
            if self._stopping:
                return
            hci_transport = self._hci_transport
            if hci_transport is None:
                return
            dfu = Nrf51Sdk11BumblePeripheral(
                self.bootloader_runtime,
                self.application_runtime,
                application_base=self.application_base,
                name=self.name,
                address=self.address,
                revision=self.revision,
            )
            self._dfu = dfu
            await dfu.start(hci_transport)
            self._phase = "dfu"
            ready = self._dfu_advertising_ready
            if ready is not None:
                ready.set()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._handoff_error = exc
            self._phase = "handoff-failed"
            ready = self._dfu_advertising_ready
            if ready is not None:
                ready.set()
        finally:
            if self._handoff_task is asyncio.current_task():
                self._handoff_task = None
