"""One model of the S130 GATT-server ABI, shared by every firmware phase.

All three Thumb images the board runs - the normal application, the
second-stage firmware, and whatever a player uploads - build their attribute
table the same way: ``sd_ble_uuid_vs_add`` registers a vendor base,
``sd_ble_gatts_service_add`` opens a service, and
``sd_ble_gatts_characteristic_add`` fills it.  Decoding those three calls once
keeps the SoftDevice struct layouts in a single place and, more importantly,
means the host learns every service and characteristic identifier from the
firmware that registers it instead of carrying its own copy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Protocol
from uuid import UUID


NRF_SUCCESS = 0
NRF_ERROR_INVALID_PARAM = 7
NRF_ERROR_INVALID_STATE = 8

SVC_BLE_UUID_VS_ADD = 0x63
SVC_BLE_GATTS_SERVICE_ADD = 0xA0
SVC_BLE_GATTS_CHARACTERISTIC_ADD = 0xA2

BLE_GATTS_SRVC_TYPE_PRIMARY = 1
BLE_GATTS_SRVC_TYPE_SECONDARY = 2
BLE_GATT_HANDLE_INVALID = 0
MAX_ATTRIBUTE_LENGTH = 512

_BLE_UUID_TYPE_BLE = 1
_BLE_UUID_TYPE_VENDOR_BEGIN = 2
_CHARACTERISTIC_NOTIFY_OR_INDICATE = 0x30


class S130AbiError(RuntimeError):
    """Compiled firmware violated the modelled S130 GATT-server ABI."""


class GuestMemory(Protocol):
    """The slice of Qiling's ``ql.mem`` this module needs."""

    def read(self, address: int, size: int) -> bytes: ...

    def write(self, address: int, data: bytes) -> None: ...


class GuestReader:
    """Little-endian scalar reads from one guest address space."""

    def __init__(self, memory: GuestMemory) -> None:
        self.memory = memory

    def u8(self, address: int) -> int:
        return self.memory.read(address, 1)[0]

    def u16(self, address: int) -> int:
        return struct.unpack("<H", bytes(self.memory.read(address, 2)))[0]

    def u32(self, address: int) -> int:
        return struct.unpack("<I", bytes(self.memory.read(address, 4)))[0]

    def bytes_at(self, address: int, length: int) -> bytes:
        return bytes(self.memory.read(address, length)) if length else b""


@dataclass(frozen=True)
class FirmwareGattCharacteristic:
    """One characteristic registered by compiled firmware through S130."""

    uuid: str
    uuid16: int
    uuid_type: int
    firmware_value_handle: int
    properties: int
    max_length: int
    initial_value: bytes
    readable: bool
    writable: bool
    read_authorized: bool


@dataclass(frozen=True)
class FirmwareGattService:
    """One service and its characteristics registered through S130."""

    uuid: str
    firmware_handle: int
    primary: bool
    characteristics: tuple[FirmwareGattCharacteristic, ...]


@dataclass
class _ServiceBuilder:
    uuid: str
    firmware_handle: int
    primary: bool
    characteristics: list[FirmwareGattCharacteristic] = field(default_factory=list)


class S130GattsRegistry:
    """Record the attribute table a compiled image registers through S130.

    The registry owns handle allocation, so the handles it hands back are the
    ones the firmware stores in its own structures and later quotes in write
    and authorization events.
    """

    def __init__(self) -> None:
        self._reader: GuestReader | None = None
        self.reset()

    def attach(self, memory: GuestMemory) -> None:
        """Bind the registry to a booted guest and discard earlier state."""

        self._reader = GuestReader(memory)
        self.reset()

    def detach(self) -> None:
        self._reader = None
        self.reset()

    def reset(self) -> None:
        self._vendor_uuids: dict[int, bytes] = {}
        self._builders: list[_ServiceBuilder] = []
        self._builders_by_handle: dict[int, _ServiceBuilder] = {}
        self._characteristics_by_handle: dict[int, FirmwareGattCharacteristic] = {}
        self._next_handle = 1

    @property
    def reader(self) -> GuestReader:
        if self._reader is None:
            raise S130AbiError("the S130 registry is not attached to a guest")
        return self._reader

    @property
    def services(self) -> tuple[FirmwareGattService, ...]:
        return tuple(
            FirmwareGattService(
                uuid=builder.uuid,
                firmware_handle=builder.firmware_handle,
                primary=builder.primary,
                characteristics=tuple(builder.characteristics),
            )
            for builder in self._builders
        )

    def characteristic_by_value_handle(
        self, handle: int
    ) -> FirmwareGattCharacteristic | None:
        return self._characteristics_by_handle.get(handle)

    def allocate_handle(self) -> int:
        handle = self._next_handle
        if handle >= 0xFFFF:
            raise S130AbiError("firmware exhausted GATT handles")
        self._next_handle += 1
        return handle

    def uuid_vs_add(self, base_pointer: int, type_pointer: int) -> int:
        """Model ``sd_ble_uuid_vs_add``: register or re-use a vendor base."""

        if not base_pointer or not type_pointer:
            return NRF_ERROR_INVALID_PARAM
        reader = self.reader
        base = bytearray(reader.bytes_at(base_pointer, 16))
        base[12:14] = b"\x00\x00"
        normalized = bytes(base)
        for uuid_type, registered in self._vendor_uuids.items():
            if registered == normalized:
                reader.memory.write(type_pointer, bytes((uuid_type,)))
                return NRF_SUCCESS
        uuid_type = _BLE_UUID_TYPE_VENDOR_BEGIN + len(self._vendor_uuids)
        if uuid_type > 0xFF:
            return NRF_ERROR_INVALID_STATE
        self._vendor_uuids[uuid_type] = normalized
        reader.memory.write(type_pointer, bytes((uuid_type,)))
        return NRF_SUCCESS

    def service_add(
        self, service_type: int, uuid_pointer: int, handle_pointer: int
    ) -> int:
        """Model ``sd_ble_gatts_service_add`` and return its handle."""

        if (
            service_type
            not in {BLE_GATTS_SRVC_TYPE_PRIMARY, BLE_GATTS_SRVC_TYPE_SECONDARY}
            or not uuid_pointer
            or not handle_pointer
        ):
            return NRF_ERROR_INVALID_PARAM
        uuid, _uuid16, _uuid_type = self.read_ble_uuid(uuid_pointer)
        handle = self.allocate_handle()
        builder = _ServiceBuilder(
            uuid=uuid,
            firmware_handle=handle,
            primary=service_type == BLE_GATTS_SRVC_TYPE_PRIMARY,
        )
        self._builders.append(builder)
        self._builders_by_handle[handle] = builder
        self.reader.memory.write(handle_pointer, struct.pack("<H", handle))
        return NRF_SUCCESS

    def characteristic_add(
        self,
        service_handle: int,
        metadata_pointer: int,
        attribute_pointer: int,
        handles_pointer: int,
    ) -> int:
        """Model ``sd_ble_gatts_characteristic_add`` and return its handles."""

        builder = self._builders_by_handle.get(service_handle)
        if (
            builder is None
            or not metadata_pointer
            or not attribute_pointer
            or not handles_pointer
        ):
            return NRF_ERROR_INVALID_PARAM
        reader = self.reader

        properties = reader.u8(metadata_pointer)
        uuid_pointer = reader.u32(attribute_pointer)
        attr_metadata_pointer = reader.u32(attribute_pointer + 4)
        if not uuid_pointer or not attr_metadata_pointer:
            return NRF_ERROR_INVALID_PARAM
        uuid, uuid16, uuid_type = self.read_ble_uuid(uuid_pointer)

        init_length = reader.u16(attribute_pointer + 8)
        init_offset = reader.u16(attribute_pointer + 10)
        max_length = reader.u16(attribute_pointer + 12)
        value_pointer = reader.u32(attribute_pointer + 16)
        if (
            max_length > MAX_ATTRIBUTE_LENGTH
            or init_offset + init_length > max_length
            or (init_length and not value_pointer)
        ):
            return NRF_ERROR_INVALID_PARAM
        initial_value = b"\x00" * init_offset + reader.bytes_at(
            value_pointer, init_length
        )

        read_permission = reader.u8(attr_metadata_pointer)
        write_permission = reader.u8(attr_metadata_pointer + 1)
        attr_flags = reader.u8(attr_metadata_pointer + 2)

        # A characteristic consumes a declaration handle before its value.
        self.allocate_handle()
        value_handle = self.allocate_handle()
        cccd_handle = BLE_GATT_HANDLE_INVALID
        if properties & _CHARACTERISTIC_NOTIFY_OR_INDICATE:
            cccd_handle = self.allocate_handle()
        reader.memory.write(
            handles_pointer,
            struct.pack(
                "<4H",
                value_handle,
                BLE_GATT_HANDLE_INVALID,
                cccd_handle,
                BLE_GATT_HANDLE_INVALID,
            ),
        )

        characteristic = FirmwareGattCharacteristic(
            uuid=uuid,
            uuid16=uuid16,
            uuid_type=uuid_type,
            firmware_value_handle=value_handle,
            properties=properties,
            max_length=max_length,
            initial_value=initial_value,
            readable=bool(properties & 0x02) and read_permission != 0,
            writable=bool(properties & 0x0C) and write_permission != 0,
            read_authorized=bool(attr_flags & 0x08),
        )
        builder.characteristics.append(characteristic)
        self._characteristics_by_handle[value_handle] = characteristic
        return NRF_SUCCESS

    def read_ble_uuid(self, pointer: int) -> tuple[str, int, int]:
        """Expand a ``ble_uuid_t`` into its full textual UUID."""

        reader = self.reader
        uuid16 = reader.u16(pointer)
        uuid_type = reader.u8(pointer + 2)
        if uuid_type == _BLE_UUID_TYPE_BLE:
            return f"{uuid16:04x}", uuid16, uuid_type
        try:
            base = bytearray(self._vendor_uuids[uuid_type])
        except KeyError as exc:
            raise S130AbiError(
                f"firmware used unregistered vendor UUID type {uuid_type}"
            ) from exc
        base[12] = uuid16 & 0xFF
        base[13] = uuid16 >> 8
        return str(UUID(bytes=bytes(reversed(base)))), uuid16, uuid_type
