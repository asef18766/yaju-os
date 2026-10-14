"""Real BLE GATT peripheral for the legacy DFU state machine.

``Rootcanal`` speaks H4 over TCP, not GATT.  Bumble owns the device-side HCI
controller connection and translates actual ATT/GATT traffic into the narrow
``LegacyDfuGattBridge`` boundary used by the bootloader model.

The imports for Bumble intentionally happen only when the peripheral is
started.  This keeps the protocol and Qiling-only tests usable without a BLE
emulator installed.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import struct
from typing import TYPE_CHECKING

from .bridge import GattStateError, LegacyDfuGattBridge
from .protocol import (
    CONSOLE_OUTPUT_UUID,
    CONSOLE_SERVICE_UUID,
    CONTROL_POINT_UUID,
    PACKET_UUID,
    REVISION_UUID,
    SERVICE_UUID,
    STATUS_REPORT_UUID,
    DfuNotification,
    DfuOpcode,
    DfuState,
)

if TYPE_CHECKING:
    from bumble.device import Connection, Device
    from bumble.gatt import Characteristic
    from bumble.transport.common import Transport


class BumbleUnavailable(RuntimeError):
    """The optional Bumble/Rootcanal transport dependencies are unavailable."""


class LegacyDfuBumblePeripheral:
    """Expose a :class:`LegacyDfuGattBridge` as a real BLE peripheral.

    ``hci_transport`` uses Bumble's transport syntax.  For a Rootcanal HCI
    server it is normally ``tcp-client:127.0.0.1:6402``.  A player attaches a
    *separate* H4 connection to that same Rootcanal HCI port, so it gets its
    own virtual controller rather than access to this target's controller.

    One DFU session is accepted at a time.  That matches the deliberately
    small challenge target and avoids mixing packet streams from two players.
    """

    def __init__(
        self,
        bridge: LegacyDfuGattBridge,
        *,
        name: str = "HITCON Legacy DFU",
        address: str = "F6:F7:F8:F9:FA:FB",
        revision: int = 1,
    ) -> None:
        encoded_name = name.encode("utf-8")
        if not encoded_name or len(encoded_name) > 29:
            raise ValueError("BLE local name must be between 1 and 29 UTF-8 bytes")
        if not 0 <= revision <= 0xFFFF:
            raise ValueError("revision must fit in uint16")

        self.bridge = bridge
        self.name = name
        self.address = address
        self.revision = revision
        self.device: Device | None = None
        self._transport: Transport | None = None
        self._connection: Connection | None = None
        self._control_point: Characteristic[bytes] | None = None
        self._packet: Characteristic[bytes] | None = None
        self._status_report: Characteristic[bytes] | None = None
        self._console_output: Characteristic[bytes] | None = None
        self._write_lock: asyncio.Lock | None = None
        self._advertising_data: bytes | None = None
        self._scan_response_data: bytes | None = None
        self._application_reset_task: asyncio.Task[None] | None = None
        self._application_advertising_ready: asyncio.Event | None = None

    @property
    def connected(self) -> bool:
        """Whether a player currently owns this peripheral's DFU session."""

        return self._connection is not None

    async def start(self, hci_transport: str) -> None:
        """Connect the target controller to HCI and begin advertising."""

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

        # Retain ATT's generic server error code without making Bumble a module
        # import dependency.  It is used only inside actual ATT callbacks.
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

            control_point = Characteristic(
                CONTROL_POINT_UUID,
                Characteristic.Properties.WRITE,
                Characteristic.WRITEABLE,
                CharacteristicValue(write=self._on_control_point_write),
            )
            packet = Characteristic(
                PACKET_UUID,
                Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
                Characteristic.WRITEABLE,
                CharacteristicValue(write=self._on_packet_write),
            )
            status_report = Characteristic(
                STATUS_REPORT_UUID,
                Characteristic.Properties.NOTIFY,
                Characteristic.READABLE,
                b"",
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
            status_report.on(
                Characteristic.EVENT_SUBSCRIPTION,
                self._on_status_subscription,
            )
            device.add_service(
                Service(
                    SERVICE_UUID,
                    [control_point, packet, status_report, revision],
                )
            )
            device.add_service(Service(CONSOLE_SERVICE_UUID, [console_output]))
            device.on(device.EVENT_CONNECTION, self._on_connection)

            # Keep the service UUID in advertising data; the human-friendly
            # name is placed in scan response to stay within the 31-byte limit.
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
            self._status_report = status_report
            self._console_output = console_output
            self._advertising_data = advertising_data
            self._scan_response_data = scan_response_data
            await device.power_on()
            await device.start_advertising(
                # Activation resets into the newly uploaded application rather
                # than back into the bootloader's DFU advertising loop.
                auto_restart=False,
                advertising_data=advertising_data,
                scan_response_data=scan_response_data,
            )
        except BaseException:
            await transport.close()
            self._clear_runtime_state()
            raise

    async def stop(self) -> None:
        """Stop advertising and release the HCI TCP connection."""

        reset_task = self._application_reset_task
        if reset_task is not None:
            reset_task.cancel()
            with suppress(asyncio.CancelledError):
                await reset_task
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

    async def __aenter__(self) -> "LegacyDfuBumblePeripheral":
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.stop()

    async def wait_for_application_advertising(self, timeout: float | None = None) -> None:
        """Wait until the post-reset target has resumed advertising.

        A successful legacy activation intentionally disconnects the central;
        this gives a harness or player client a deterministic point at which it
        can reconnect and read UART output from the uploaded application.
        """

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
        self._status_report = None
        self._console_output = None
        self._write_lock = None
        self._advertising_data = None
        self._scan_response_data = None
        self._application_reset_task = None
        self._application_advertising_ready = None
        self.device = None
        self._transport = None
        if self.bridge.connected:
            self.bridge.disconnect()

    def _on_connection(self, connection: Connection) -> None:
        if self._connection is not None and self._connection is not connection:
            # A second central cannot be allowed to inject into the same state
            # machine.  Disconnect it without disturbing the owner.
            asyncio.create_task(connection.disconnect())
            return

        self._accept_connection(connection)

    def _accept_connection(self, connection: Connection) -> None:
        if self._connection is connection:
            return
        self._connection = connection
        self.bridge.connect()
        connection.on(
            connection.EVENT_DISCONNECTION,
            lambda *_args: self._on_disconnection(connection),
        )

    def _on_disconnection(self, connection: Connection) -> None:
        if self._connection is connection:
            self._connection = None
            self.bridge.disconnect()

    def _on_status_subscription(
        self,
        connection: Connection,
        notify_enabled: bool,
        _indicate_enabled: bool,
    ) -> None:
        # The characteristic subscription may arrive immediately after the
        # connection event.  Accepting it here makes the ordering robust across
        # Rootcanal/Bumble versions while retaining the CCCD requirement.
        if self._connection is None:
            self._accept_connection(connection)
        if self._connection is connection:
            self.bridge.set_status_notifications(notify_enabled)

    async def _on_control_point_write(
        self,
        connection: Connection,
        payload: bytes,
    ) -> None:
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
                self._accept_connection(connection)
            if self._connection is not connection:
                self._raise_att_error()

            try:
                if (
                    control_point
                    and payload
                    and payload[0] in (DfuOpcode.ACTIVATE_AND_RESET, DfuOpcode.SYSTEM_RESET)
                ):
                    # The reset operation invokes Qiling and lets arbitrary
                    # player firmware consume its bounded instruction budget.
                    # Keep the asyncio BLE/HCI pump responsive while that
                    # host-side emulation is running.
                    notifications = await asyncio.to_thread(self.bridge.write_control_point, payload)
                else:
                    notifications = (
                        self.bridge.write_control_point(payload)
                        if control_point
                        else self.bridge.write_packet(payload)
                    )
            except GattStateError:
                self._raise_att_error()
                return  # Makes static type checkers understand _raise_att_error never returns.

            await self._send_notifications(notifications)

            # Activation reaches the post-reset Qiling runtime synchronously in
            # the bootloader.  Actual Nordic legacy targets then drop the BLE
            # link; do it on the next loop turn so the ATT write response can
            # leave first.
            if (
                control_point
                and payload
                and payload[0]
                in (DfuOpcode.ACTIVATE_AND_RESET, DfuOpcode.SYSTEM_RESET)
                and self.bridge.bootloader.state is DfuState.APPLICATION_RUNNING
            ):
                await self._publish_console_output()
                if self._application_advertising_ready is not None:
                    self._application_advertising_ready.clear()
                self._application_reset_task = asyncio.create_task(
                    self._disconnect_and_advertise_application(connection)
                )

    def _raise_att_error(self) -> None:
        # Imported lazily in start(); this method is never reachable before
        # then because it is invoked by an ATT callback.
        from bumble.att import ATT_Error

        raise ATT_Error(error_code=self._att_unlikely_error)

    async def _send_notifications(self, notifications: list[DfuNotification]) -> None:
        if not notifications:
            return
        device = self.device
        status_report = self._status_report
        if device is None or status_report is None:
            return
        for notification in notifications:
            await device.notify_subscribers(status_report, notification.payload)

    def _read_console_output(self, _connection: Connection) -> bytes:
        execution = self.bridge.bootloader.last_execution
        output = getattr(execution, "uart_output", b"")
        return bytes(output) if isinstance(output, (bytes, bytearray)) else b""

    async def _publish_console_output(self) -> None:
        device = self.device
        console_output = self._console_output
        output = self._read_console_output(self._connection) if self._connection else b""
        if device is not None and console_output is not None and output:
            await device.notify_subscribers(console_output, output)

    async def _disconnect_and_advertise_application(self, connection: Connection) -> None:
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
                # Expose the application-phase UART output to a reconnecting
                # player.  The DFU service remains present for repeatable CTF
                # runs; no new vulnerability is introduced by this output wire.
                with suppress(Exception):
                    await device.start_advertising(
                        auto_restart=False,
                        advertising_data=self._advertising_data,
                        scan_response_data=self._scan_response_data,
                    )
                if self._application_advertising_ready is not None:
                    self._application_advertising_ready.set()
        finally:
            if self._application_reset_task is asyncio.current_task():
                self._application_reset_task = None
