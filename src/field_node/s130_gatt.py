"""Bumble transport adapter for GATT services registered by S130 firmware.

Compiled firmware owns service definitions and authorized-read behavior. This
module performs the part a physical S130 SoftDevice would: materialize the
registered attribute table, translate ATT reads to ``ble_evt_t`` callbacks,
and retain an attribute snapshot while ATT Read Blob fragments are transferred.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from bumble import att, utils
from bumble.device import Device
from bumble.gatt import Characteristic, Service
from bumble.gatt_server import Server

from .maintenance_runtime import (
    FirmwareGattCharacteristic,
    FirmwareGattReadReply,
    FirmwareGattService,
)


class S130GattFirmware(Protocol):
    """Generic firmware operations required by the emulated SoftDevice."""

    @property
    def gatt_services(self) -> tuple[FirmwareGattService, ...]: ...

    def connect(self, connection_handle: int = 0) -> None: ...

    def disconnect(self) -> None: ...

    def authorize_read(
        self, firmware_value_handle: int, *, offset: int = 0
    ) -> FirmwareGattReadReply: ...


class S130GattServer(Server):
    """ATT server backed by firmware-created S130 GATTS registrations."""

    def __init__(self, device: Device, firmware: S130GattFirmware) -> None:
        super().__init__(device)
        self._firmware = firmware
        self._bindings: dict[
            int, tuple[FirmwareGattCharacteristic, Characteristic[bytes]]
        ] = {}
        self._snapshots: dict[tuple[att.Bearer, int], bytes] = {}
        self._connected_bearers: set[att.Bearer] = set()

    @classmethod
    def install(cls, device: Device, firmware: S130GattFirmware) -> "S130GattServer":
        """Install firmware registrations before power-on, preserving services."""

        if device.powered_on or device.config.eatt_enabled:
            raise ValueError("install firmware GATT before power-on, with EATT disabled")
        previous = device.gatt_server
        server = cls(device, firmware)
        server.max_mtu = previous.max_mtu
        for service in previous.services:
            server.add_service(service)
        for definition in firmware.gatt_services:
            server._add_firmware_service(definition)
        device.gatt_server = server
        utils.setup_event_forwarding(server, device, "characteristic_subscription")
        return server

    def connect_connection(self, bearer: att.Bearer, connection_handle: int) -> None:
        """Deliver the GAP connection event and initialize its attribute cache."""

        if bearer in self._connected_bearers:
            return
        if self._connected_bearers:
            raise RuntimeError("the emulated S130 application supports one central")
        self._firmware.connect(connection_handle)
        self._connected_bearers.add(bearer)
        for att_handle, (definition, _characteristic) in self._bindings.items():
            self._snapshots[(bearer, att_handle)] = definition.initial_value

    def disconnect_connection(self, bearer: att.Bearer) -> None:
        """Deliver the GAP disconnection event once and discard ATT snapshots."""

        if bearer in self._connected_bearers:
            try:
                self._firmware.disconnect()
            finally:
                self._connected_bearers.remove(bearer)
        for key in [key for key in self._snapshots if key[0] is bearer]:
            self._snapshots.pop(key, None)

    def characteristic_by_uuid(self, uuid: str) -> Characteristic[bytes]:
        """Return the sole firmware characteristic with the requested UUID."""

        matches = [
            characteristic
            for definition, characteristic in self._bindings.values()
            if definition.uuid == uuid
        ]
        if len(matches) != 1:
            raise KeyError(f"expected one firmware characteristic for {uuid}, got {len(matches)}")
        return matches[0]

    def _add_firmware_service(self, definition: FirmwareGattService) -> None:
        if not definition.primary:
            raise ValueError("the S130/Bumble bridge currently supports primary services only")
        characteristics: list[Characteristic[bytes]] = []
        pending: list[tuple[FirmwareGattCharacteristic, Characteristic[bytes]]] = []
        for characteristic_definition in definition.characteristics:
            if characteristic_definition.writable:
                raise ValueError(
                    "the firmware GATT bridge currently supports read-only characteristics"
                )
            permissions = 0
            if characteristic_definition.readable:
                permissions |= Characteristic.READABLE
            characteristic = Characteristic(
                characteristic_definition.uuid,
                Characteristic.Properties(characteristic_definition.properties),
                permissions,
                att.AttributeValueV2(
                    read=lambda bearer, item=characteristic_definition: self._snapshot(
                        bearer, item
                    ),
                    write=self._reject_write,
                ),
            )
            characteristics.append(characteristic)
            pending.append((characteristic_definition, characteristic))
        self.add_service(Service(definition.uuid, characteristics))
        for characteristic_definition, characteristic in pending:
            self._bindings[characteristic.handle] = (
                characteristic_definition,
                characteristic,
            )

    def _snapshot(
        self, bearer: att.Bearer, definition: FirmwareGattCharacteristic
    ) -> bytes:
        for att_handle, (candidate, _characteristic) in self._bindings.items():
            if candidate is definition:
                return self._snapshots.get(
                    (bearer, att_handle), definition.initial_value
                )
        raise RuntimeError("firmware characteristic was not installed")

    @staticmethod
    def _reject_write(_bearer: att.Bearer, _value: bytes) -> None:
        raise att.ATT_Error(error_code=att.ATT_WRITE_NOT_PERMITTED_ERROR)

    @staticmethod
    def _att_error_for_status(gatt_status: int) -> int:
        if 0x0100 <= gatt_status <= 0x01FF:
            return gatt_status & 0xFF
        return att.ATT_UNLIKELY_ERROR_ERROR

    def _apply_read_reply(
        self,
        bearer: att.Bearer,
        att_handle: int,
        definition: FirmwareGattCharacteristic,
        reply: FirmwareGattReadReply,
    ) -> bytes:
        if reply.gatt_status != 0:
            raise att.ATT_Error(error_code=self._att_error_for_status(reply.gatt_status))
        current = self._snapshots.get((bearer, att_handle), definition.initial_value)
        if reply.update:
            end = reply.offset + len(reply.value)
            if reply.offset > len(current) or end > definition.max_length:
                raise att.ATT_Error(error_code=att.ATT_UNLIKELY_ERROR_ERROR)
            updated = bytearray(current)
            updated[reply.offset:end] = reply.value
            current = bytes(updated)
            self._snapshots[(bearer, att_handle)] = current
        return current

    def _send_error(
        self, bearer: att.Bearer, request: att.ATT_PDU, error_code: int
    ) -> None:
        self.send_response(
            bearer,
            att.ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.attribute_handle,
                error_code=error_code,
            ),
        )

    @utils.AsyncRunner.run_in_task()
    async def on_att_read_request(
        self, bearer: att.Bearer, request: att.ATT_Read_Request
    ) -> None:
        binding = self._bindings.get(request.attribute_handle)
        if binding is None:
            super().on_att_read_request(bearer, request)
            return
        definition, _characteristic = binding
        if not definition.readable:
            self._send_error(bearer, request, att.ATT_READ_NOT_PERMITTED_ERROR)
            return
        try:
            if definition.read_authorized:
                reply = await asyncio.to_thread(
                    self._firmware.authorize_read,
                    definition.firmware_value_handle,
                    offset=0,
                )
                value = self._apply_read_reply(
                    bearer, request.attribute_handle, definition, reply
                )
            else:
                value = self._snapshots.get(
                    (bearer, request.attribute_handle), definition.initial_value
                )
        except att.ATT_Error as error:
            self._send_error(bearer, request, error.error_code)
            return
        except Exception:
            self._send_error(bearer, request, att.ATT_UNLIKELY_ERROR_ERROR)
            return
        self.send_response(
            bearer, att.ATT_Read_Response(attribute_value=value[: bearer.att_mtu - 1])
        )

    def on_att_read_blob_request(
        self, bearer: att.Bearer, request: att.ATT_Read_Blob_Request
    ) -> None:
        binding = self._bindings.get(request.attribute_handle)
        if binding is None:
            super().on_att_read_blob_request(bearer, request)
            return
        definition, _characteristic = binding
        value = self._snapshots.get(
            (bearer, request.attribute_handle), definition.initial_value
        )
        if request.value_offset > len(value):
            error = att.ATT_INVALID_OFFSET_ERROR
        elif len(value) <= bearer.att_mtu - 1:
            error = att.ATT_ATTRIBUTE_NOT_LONG_ERROR
        else:
            self.send_response(
                bearer,
                att.ATT_Read_Blob_Response(
                    part_attribute_value=value[
                        request.value_offset : request.value_offset + bearer.att_mtu - 1
                    ]
                ),
            )
            return
        self._send_error(bearer, request, error)

    def on_att_prepare_write_request(
        self, bearer: att.Bearer, request: att.ATT_Prepare_Write_Request
    ) -> None:
        if request.attribute_handle not in self._bindings:
            super().on_att_prepare_write_request(bearer, request)
            return
        self._send_error(bearer, request, att.ATT_WRITE_NOT_PERMITTED_ERROR)

    def on_att_write_command(
        self, bearer: att.Bearer, request: att.ATT_Write_Command
    ) -> None:
        if request.attribute_handle not in self._bindings:
            super().on_att_write_command(bearer, request)

    def on_disconnection(self, bearer: att.Bearer) -> None:
        try:
            self.disconnect_connection(bearer)
        finally:
            super().on_disconnection(bearer)
