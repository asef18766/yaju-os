"""Qiling boundary for the board's compiled normal-application firmware.

The application registers its GATT services through the Nordic S130 SVC ABI
and handles read-authorization events as compiled Thumb code. This runtime is
the deliberately narrow SoftDevice shim: it records those generic GATTS calls,
delivers ``ble_evt_t`` events, and captures authorization replies. It does not
contain animation UUIDs, frame data, or playback state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import threading
from typing import Any
from uuid import UUID

from .board_runtime import (
    BOARD_FLASH_FILENAME,
    BOARD_METADATA_FILENAME,
    BoardRuntimeArtifact,
    BoardRuntimeArtifactError,
)


NRF_SUCCESS = 0
NRF_ERROR_INVALID_PARAM = 7
NRF_ERROR_INVALID_STATE = 8

_FLASH_SIZE = 0x0004_0000
_SRAM_BASE = 0x2000_0000
_SRAM_SIZE = 0x0000_8000
_POWER_BASE = 0x4000_0000
_POWER_SIZE = 0x1000
_POWER_GPREGRET_OFFSET = 0x51C
_BOOTLOADER_DFU_START = 0xB1
_CALL_SENTINEL = 0x2000_7E00
_CALL_STACK = 0x2000_7D00
_COMMAND_BUFFER = 0x2000_7000
_MAX_COMMAND_LENGTH = 20
_BLE_EVENT_BUFFER = 0x2000_7100
_MAX_ATTRIBUTE_LENGTH = 512

# S130 2.0.0 SVC and event identifiers used by this application.
_SVC_BLE_UUID_VS_ADD = 0x63
_SVC_BLE_GATTS_SERVICE_ADD = 0xA0
_SVC_BLE_GATTS_CHARACTERISTIC_ADD = 0xA2
_SVC_BLE_GATTS_RW_AUTHORIZE_REPLY = 0xA8
_BLE_GAP_EVT_CONNECTED = 0x10
_BLE_GAP_EVT_DISCONNECTED = 0x11
_BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST = 0x51
_BLE_GATTS_AUTHORIZE_TYPE_READ = 1
_BLE_UUID_TYPE_BLE = 1
_BLE_UUID_TYPE_VENDOR_BEGIN = 2
_BLE_GATTS_SRVC_TYPE_PRIMARY = 1
_BLE_GATTS_SRVC_TYPE_SECONDARY = 2
_BLE_GATT_HANDLE_INVALID = 0


class MaintenanceFirmwareError(RuntimeError):
    """The normal application firmware cannot be loaded or invoked."""


class MaintenanceFirmwareArtifactError(MaintenanceFirmwareError):
    """The built application artifact is missing or violates the S130 ABI."""


class _FunctionReturned(Exception):
    """Internal trampoline signal for a returned Thumb function."""


class _PowerRegisters:
    """Minimal nRF51 POWER register model retaining GPREGRET."""

    def __init__(self) -> None:
        self._data = bytearray(_POWER_SIZE)

    @property
    def gpregret(self) -> int:
        return int.from_bytes(
            self._data[_POWER_GPREGRET_OFFSET : _POWER_GPREGRET_OFFSET + 4], "little"
        )

    def clear_boot_request(self) -> None:
        self._data[_POWER_GPREGRET_OFFSET : _POWER_GPREGRET_OFFSET + 4] = b"\x00" * 4

    def read(self, _ql: object, offset: int, size: int) -> int:
        return int.from_bytes(self._data[offset : offset + size], "little")

    def write(self, _ql: object, offset: int, size: int, value: int) -> None:
        self._data[offset : offset + size] = value.to_bytes(size, "little")


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


@dataclass(frozen=True)
class FirmwareGattReadReply:
    """Value update supplied by firmware to an S130 read authorization."""

    gatt_status: int
    update: bool
    offset: int
    value: bytes


@dataclass(frozen=True)
class MaintenanceFirmwareBootResult:
    """Identity and GATT registrations produced by the loaded application."""

    elf_path: Path
    elf_sha256: str
    entry_point: int
    command_handler: int
    gatt_services: tuple[FirmwareGattService, ...]
    svc_calls: tuple[int, ...]


@dataclass
class _GattServiceBuilder:
    uuid: str
    firmware_handle: int
    primary: bool
    characteristics: list[FirmwareGattCharacteristic] = field(default_factory=list)


class MaintenanceFirmwareRuntime:
    """Execute the normal application and emulate its narrow S130 boundary."""

    def __init__(self, elf_path: Path, *, instruction_budget: int = 5_000) -> None:
        if instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")
        requested_path = Path(elf_path).resolve()
        self._board_artifact: BoardRuntimeArtifact | None = None
        if requested_path.is_dir() or requested_path.name in {
            BOARD_FLASH_FILENAME,
            BOARD_METADATA_FILENAME,
        }:
            try:
                self._board_artifact = BoardRuntimeArtifact.load(requested_path)
            except BoardRuntimeArtifactError as exc:
                raise MaintenanceFirmwareArtifactError(str(exc)) from exc
            self.elf_path = self._board_artifact.flash_path
        else:
            self.elf_path = requested_path
        self.instruction_budget = instruction_budget
        self._ql: Any | None = None
        self._bootstrap: tempfile._TemporaryFileWrapper[bytes] | None = None
        self._symbols: dict[str, int] = {}
        self._svc_addresses: dict[int, int] = {}
        self._svc_calls: list[int] = []
        self._power: _PowerRegisters | None = None
        self._boot_result: MaintenanceFirmwareBootResult | None = None
        self._closed = False
        self._lock = threading.Lock()
        self._vendor_uuids: dict[int, bytes] = {}
        self._service_builders: list[_GattServiceBuilder] = []
        self._services_by_handle: dict[int, _GattServiceBuilder] = {}
        self._characteristics_by_handle: dict[int, FirmwareGattCharacteristic] = {}
        self._next_attribute_handle = 1
        self._connection_handle: int | None = None
        self._pending_read_reply: FirmwareGattReadReply | None = None
        self._awaiting_read_authorization = False

    @staticmethod
    def repository_reference_elf() -> Path:
        """Locate the build artifact in a checkout or Compose image."""

        configured_path = os.environ.get("HITCON_MAINTENANCE_FIRMWARE_ELF")
        if configured_path:
            return Path(configured_path).expanduser().resolve()
        return (
            Path(__file__).resolve().parents[2]
            / "artifacts"
            / "maintenance_application"
            / "maintenance_application.elf"
        )

    @classmethod
    def from_board_runtime(
        cls, path: str | Path, *, instruction_budget: int = 5_000
    ) -> "MaintenanceFirmwareRuntime":
        """Create the application phase from one combined board artifact."""

        return cls(Path(path), instruction_budget=instruction_budget)

    def __enter__(self) -> "MaintenanceFirmwareRuntime":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        """Whether a central has been delivered to the compiled application."""

        return self._connection_handle is not None

    @property
    def gatt_services(self) -> tuple[FirmwareGattService, ...]:
        """Return the services produced by firmware S130 registration calls."""

        return self.boot().gatt_services

    def close(self) -> None:
        """Release Qiling's bootstrap file and make future calls invalid."""

        with self._lock:
            if self._bootstrap is not None:
                self._bootstrap.close()
                self._bootstrap = None
            self._ql = None
            self._power = None
            self._connection_handle = None
            self._closed = True

    def boot(self) -> MaintenanceFirmwareBootResult:
        """Load the ELF and run its compiled S130 service initialization."""

        with self._lock:
            self._prepare_qiling()
            assert self._boot_result is not None
            return self._boot_result

    def request_bootloader(self, payload: bytes) -> bool:
        """Run the real Thumb authorization routine for one maintenance write."""

        request = bytes(payload)
        if len(request) > _MAX_COMMAND_LENGTH:
            return False
        with self._lock:
            self._prepare_qiling()
            assert self._ql is not None
            assert self._power is not None
            self._power.clear_boot_request()
            self._ql.mem.write(_COMMAND_BUFFER, b"\x00" * _MAX_COMMAND_LENGTH)
            self._ql.mem.write(_COMMAND_BUFFER, request)
            result = self._call("maintenance_command", _COMMAND_BUFFER, len(request))
            return result != 0 and (self._power.gpregret & 0xFF) == _BOOTLOADER_DFU_START

    def connect(self, connection_handle: int = 0) -> None:
        """Deliver ``BLE_GAP_EVT_CONNECTED`` to the compiled application."""

        if not 0 <= connection_handle < 0xFFFF:
            raise ValueError("connection_handle must fit in an active uint16 handle")
        with self._lock:
            self._prepare_qiling()
            if self._connection_handle is not None:
                raise MaintenanceFirmwareError("normal application already has a connection")
            self._connection_handle = connection_handle
            try:
                self._dispatch_ble_event(
                    struct.pack("<HHH", _BLE_GAP_EVT_CONNECTED, 6, connection_handle)
                    + b"\x00\x00"
                )
            except Exception:
                self._connection_handle = None
                raise

    def disconnect(self) -> None:
        """Deliver ``BLE_GAP_EVT_DISCONNECTED`` and clear connection state."""

        with self._lock:
            if self._connection_handle is None:
                return
            connection_handle = self._connection_handle
            try:
                self._dispatch_ble_event(
                    struct.pack("<HHH", _BLE_GAP_EVT_DISCONNECTED, 6, connection_handle)
                    + b"\x00\x00"
                )
            finally:
                self._connection_handle = None

    def authorize_read(
        self, firmware_value_handle: int, *, offset: int = 0
    ) -> FirmwareGattReadReply:
        """Send one S130 authorized-read event through compiled firmware."""

        if not 0 <= offset <= 0xFFFF:
            raise ValueError("read offset must fit in uint16")
        with self._lock:
            self._prepare_qiling()
            if self._connection_handle is None:
                raise MaintenanceFirmwareError("no central is connected")
            characteristic = self._characteristics_by_handle.get(firmware_value_handle)
            if characteristic is None:
                raise ValueError(f"unknown firmware value handle: {firmware_value_handle}")
            if not characteristic.readable or not characteristic.read_authorized:
                raise ValueError("characteristic does not use S130 read authorization")

            event = struct.pack(
                "<HHHBxHHBxH",
                _BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST,
                16,
                self._connection_handle,
                _BLE_GATTS_AUTHORIZE_TYPE_READ,
                firmware_value_handle,
                characteristic.uuid16,
                characteristic.uuid_type,
                offset,
            )
            self._pending_read_reply = None
            self._awaiting_read_authorization = True
            try:
                self._dispatch_ble_event(event)
            finally:
                self._awaiting_read_authorization = False
            reply = self._pending_read_reply
            self._pending_read_reply = None
            if reply is None:
                raise MaintenanceFirmwareError(
                    "firmware did not call sd_ble_gatts_rw_authorize_reply"
                )
            return reply

    def _dispatch_ble_event(self, event: bytes) -> None:
        if len(event) > 0x100:
            raise ValueError("BLE event exceeds the Qiling harness event buffer")
        assert self._ql is not None
        self._ql.mem.write(_BLE_EVENT_BUFFER, event)
        self._call("application_ble_evt", _BLE_EVENT_BUFFER)

    def _prepare_qiling(self) -> None:
        if self._ql is not None:
            return
        if self._closed:
            raise MaintenanceFirmwareError("runtime is closed")
        if not self.elf_path.is_file():
            raise MaintenanceFirmwareArtifactError(
                f"maintenance firmware ELF does not exist: {self.elf_path}"
            )
        try:
            from qiling import Qiling
            from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        except ModuleNotFoundError as exc:
            raise MaintenanceFirmwareArtifactError(
                "Qiling is required; install the 'emulator' extra"
            ) from exc

        if self._board_artifact is not None:
            phase = self._board_artifact.phase("maintenance")
            self._symbols = dict(phase.symbols)
            entry_point = phase.entry_point
            segments = [(0, self._board_artifact.flash)]
            self._svc_addresses = dict(phase.svc_addresses)
        else:
            try:
                from elftools.elf.elffile import ELFFile
            except ModuleNotFoundError as exc:
                raise MaintenanceFirmwareArtifactError(
                    "pyelftools is required to load a legacy ELF artifact"
                ) from exc
            with self.elf_path.open("rb") as stream:
                elf = ELFFile(stream)
                self._symbols = self._read_symbols(elf)
                entry_point = int(elf.header["e_entry"])
                segments = [
                    (int(segment["p_paddr"]), segment.data())
                    for segment in elf.iter_segments()
                    if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]
                ]
                self._svc_addresses = self._find_svc_instructions(elf)

        command_handler = self._symbol("maintenance_command")
        for symbol in ("Reset_Handler", "application_init", "application_ble_evt"):
            self._symbol(symbol)
        if not segments:
            raise MaintenanceFirmwareArtifactError("maintenance ELF has no loadable segments")

        bootstrap = tempfile.NamedTemporaryFile(suffix=".bin")
        bootstrap.write(struct.pack("<II", _SRAM_BASE + _SRAM_SIZE, 1))
        bootstrap.flush()
        env = {
            "FLASH": {"base": 0, "size": _FLASH_SIZE, "type": "memory"},
            "SRAM": {"base": _SRAM_BASE, "size": _SRAM_SIZE, "type": "memory"},
        }
        try:
            ql = Qiling(
                [bootstrap.name, 0],
                archtype=QL_ARCH.CORTEX_M,
                ostype=QL_OS.MCU,
                env=env,
                verbose=QL_VERBOSE.OFF,
            )
            ql.mem.write(0, b"\xff" * _FLASH_SIZE)
            power = _PowerRegisters()
            ql.mem.map_mmio(_POWER_BASE, _POWER_SIZE, power, "[nRF51 POWER]")
            for address, data in segments:
                self._validate_segment(address, data)
                ql.mem.write(address, data)
            for address in self._svc_addresses:
                ql.mem.write(address, b"\x00\xbf")
            ql.mem.write(_CALL_SENTINEL, b"\x00\xbf")
            ql.hook_code(self._on_code)
        except BaseException:
            bootstrap.close()
            raise

        self._bootstrap = bootstrap
        self._ql = ql
        self._power = power
        try:
            init_result = self._call("application_init")
            if init_result != NRF_SUCCESS:
                raise MaintenanceFirmwareArtifactError(
                    f"firmware GATT initialization returned {init_result}"
                )
            services = tuple(
                FirmwareGattService(
                    uuid=service.uuid,
                    firmware_handle=service.firmware_handle,
                    primary=service.primary,
                    characteristics=tuple(service.characteristics),
                )
                for service in self._service_builders
            )
            if not services or not any(service.characteristics for service in services):
                raise MaintenanceFirmwareArtifactError(
                    "firmware registered no GATT services or characteristics"
                )
            self._boot_result = MaintenanceFirmwareBootResult(
                elf_path=self.elf_path,
                elf_sha256=hashlib.sha256(self.elf_path.read_bytes()).hexdigest(),
                entry_point=entry_point,
                command_handler=command_handler,
                gatt_services=services,
                svc_calls=tuple(self._svc_calls),
            )
        except BaseException:
            bootstrap.close()
            self._bootstrap = None
            self._ql = None
            self._power = None
            raise

    def _on_code(self, ql: Any, address: int, _size: int) -> None:
        svc_number = self._svc_addresses.get(address)
        if svc_number is not None:
            self._svc_calls.append(svc_number)
            self._handle_svc(ql, svc_number)
        if address == _CALL_SENTINEL:
            raise _FunctionReturned()

    def _handle_svc(self, ql: Any, svc_number: int) -> None:
        if svc_number == _SVC_BLE_UUID_VS_ADD:
            ql.arch.regs.r0 = self._handle_uuid_vs_add(ql.arch.regs.r0, ql.arch.regs.r1)
            return
        if svc_number == _SVC_BLE_GATTS_SERVICE_ADD:
            ql.arch.regs.r0 = self._handle_service_add(
                ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2
            )
            return
        if svc_number == _SVC_BLE_GATTS_CHARACTERISTIC_ADD:
            ql.arch.regs.r0 = self._handle_characteristic_add(
                ql.arch.regs.r0,
                ql.arch.regs.r1,
                ql.arch.regs.r2,
                ql.arch.regs.r3,
            )
            return
        if svc_number == _SVC_BLE_GATTS_RW_AUTHORIZE_REPLY:
            ql.arch.regs.r0 = self._handle_authorize_reply(
                ql.arch.regs.r0, ql.arch.regs.r1
            )
            return
        ql.arch.regs.r0 = NRF_ERROR_INVALID_PARAM

    def _handle_uuid_vs_add(self, base_pointer: int, type_pointer: int) -> int:
        if not base_pointer or not type_pointer:
            return NRF_ERROR_INVALID_PARAM
        assert self._ql is not None
        base = bytearray(self._ql.mem.read(base_pointer, 16))
        base[12:14] = b"\x00\x00"
        normalized = bytes(base)
        for uuid_type, registered in self._vendor_uuids.items():
            if registered == normalized:
                self._ql.mem.write(type_pointer, bytes((uuid_type,)))
                return NRF_SUCCESS
        uuid_type = _BLE_UUID_TYPE_VENDOR_BEGIN + len(self._vendor_uuids)
        if uuid_type > 0xFF:
            return NRF_ERROR_INVALID_STATE
        self._vendor_uuids[uuid_type] = normalized
        self._ql.mem.write(type_pointer, bytes((uuid_type,)))
        return NRF_SUCCESS

    def _handle_service_add(
        self, service_type: int, uuid_pointer: int, handle_pointer: int
    ) -> int:
        if (
            service_type not in {_BLE_GATTS_SRVC_TYPE_PRIMARY, _BLE_GATTS_SRVC_TYPE_SECONDARY}
            or not uuid_pointer
            or not handle_pointer
        ):
            return NRF_ERROR_INVALID_PARAM
        uuid, _uuid16, _uuid_type = self._read_ble_uuid(uuid_pointer)
        handle = self._allocate_handle()
        builder = _GattServiceBuilder(
            uuid=uuid,
            firmware_handle=handle,
            primary=service_type == _BLE_GATTS_SRVC_TYPE_PRIMARY,
        )
        self._service_builders.append(builder)
        self._services_by_handle[handle] = builder
        assert self._ql is not None
        self._ql.mem.write(handle_pointer, struct.pack("<H", handle))
        return NRF_SUCCESS

    def _handle_characteristic_add(
        self,
        service_handle: int,
        metadata_pointer: int,
        attribute_pointer: int,
        handles_pointer: int,
    ) -> int:
        service = self._services_by_handle.get(service_handle)
        if (
            service is None
            or not metadata_pointer
            or not attribute_pointer
            or not handles_pointer
        ):
            return NRF_ERROR_INVALID_PARAM
        assert self._ql is not None

        properties = self._read_u8(metadata_pointer)
        uuid_pointer = self._read_u32(attribute_pointer)
        attr_metadata_pointer = self._read_u32(attribute_pointer + 4)
        if not uuid_pointer or not attr_metadata_pointer:
            return NRF_ERROR_INVALID_PARAM
        uuid, uuid16, uuid_type = self._read_ble_uuid(uuid_pointer)

        init_length = self._read_u16(attribute_pointer + 8)
        init_offset = self._read_u16(attribute_pointer + 10)
        max_length = self._read_u16(attribute_pointer + 12)
        value_pointer = self._read_u32(attribute_pointer + 16)
        if (
            max_length > _MAX_ATTRIBUTE_LENGTH
            or init_offset + init_length > max_length
            or (init_length and not value_pointer)
        ):
            return NRF_ERROR_INVALID_PARAM
        initial_value = b"\x00" * init_offset
        if init_length:
            initial_value += bytes(self._ql.mem.read(value_pointer, init_length))

        read_permission = self._read_u8(attr_metadata_pointer)
        write_permission = self._read_u8(attr_metadata_pointer + 1)
        attr_flags = self._read_u8(attr_metadata_pointer + 2)
        readable = bool(properties & 0x02) and read_permission != 0
        writable = bool(properties & 0x0C) and write_permission != 0
        read_authorized = bool(attr_flags & 0x08)

        # A characteristic consumes a declaration handle before its value.
        self._allocate_handle()
        value_handle = self._allocate_handle()
        cccd_handle = _BLE_GATT_HANDLE_INVALID
        if properties & 0x30:
            cccd_handle = self._allocate_handle()
        handles = (
            value_handle,
            _BLE_GATT_HANDLE_INVALID,
            cccd_handle,
            _BLE_GATT_HANDLE_INVALID,
        )
        self._ql.mem.write(handles_pointer, struct.pack("<4H", *handles))

        characteristic = FirmwareGattCharacteristic(
            uuid=uuid,
            uuid16=uuid16,
            uuid_type=uuid_type,
            firmware_value_handle=value_handle,
            properties=properties,
            max_length=max_length,
            initial_value=initial_value,
            readable=readable,
            writable=writable,
            read_authorized=read_authorized,
        )
        service.characteristics.append(characteristic)
        self._characteristics_by_handle[value_handle] = characteristic
        return NRF_SUCCESS

    def _handle_authorize_reply(
        self, connection_handle: int, parameters_pointer: int
    ) -> int:
        if (
            not self._awaiting_read_authorization
            or self._connection_handle != connection_handle
            or not parameters_pointer
        ):
            return NRF_ERROR_INVALID_STATE
        if self._read_u8(parameters_pointer) != _BLE_GATTS_AUTHORIZE_TYPE_READ:
            return NRF_ERROR_INVALID_PARAM

        # ARM EABI aligns the authorization union to four bytes. Its read
        # member is: u16 status, u8 update bitfield, pad, u16 offset, u16 len,
        # then a 32-bit data pointer.
        gatt_status = self._read_u16(parameters_pointer + 4)
        update = bool(self._read_u8(parameters_pointer + 6) & 0x01)
        offset = self._read_u16(parameters_pointer + 8)
        length = self._read_u16(parameters_pointer + 10)
        data_pointer = self._read_u32(parameters_pointer + 12)
        if length > _MAX_ATTRIBUTE_LENGTH or (length and not data_pointer):
            return NRF_ERROR_INVALID_PARAM
        assert self._ql is not None
        value = bytes(self._ql.mem.read(data_pointer, length)) if length else b""
        self._pending_read_reply = FirmwareGattReadReply(
            gatt_status=gatt_status,
            update=update,
            offset=offset,
            value=value,
        )
        return NRF_SUCCESS

    def _read_ble_uuid(self, pointer: int) -> tuple[str, int, int]:
        uuid16 = self._read_u16(pointer)
        uuid_type = self._read_u8(pointer + 2)
        if uuid_type == _BLE_UUID_TYPE_BLE:
            return f"{uuid16:04x}", uuid16, uuid_type
        try:
            base = bytearray(self._vendor_uuids[uuid_type])
        except KeyError as exc:
            raise MaintenanceFirmwareArtifactError(
                f"firmware used unregistered vendor UUID type {uuid_type}"
            ) from exc
        base[12] = uuid16 & 0xFF
        base[13] = uuid16 >> 8
        return str(UUID(bytes=bytes(reversed(base)))), uuid16, uuid_type

    def _allocate_handle(self) -> int:
        handle = self._next_attribute_handle
        if handle >= 0xFFFF:
            raise MaintenanceFirmwareArtifactError("firmware exhausted GATT handles")
        self._next_attribute_handle += 1
        return handle

    def _read_u8(self, address: int) -> int:
        assert self._ql is not None
        return self._ql.mem.read(address, 1)[0]

    def _read_u16(self, address: int) -> int:
        assert self._ql is not None
        return struct.unpack("<H", bytes(self._ql.mem.read(address, 2)))[0]

    def _read_u32(self, address: int) -> int:
        assert self._ql is not None
        return struct.unpack("<I", bytes(self._ql.mem.read(address, 4)))[0]

    @staticmethod
    def _validate_segment(address: int, data: bytes) -> None:
        end = address + len(data)
        in_flash = 0 <= address and end <= _FLASH_SIZE
        in_sram = _SRAM_BASE <= address and end <= _SRAM_BASE + _SRAM_SIZE
        if not (in_flash or in_sram):
            raise MaintenanceFirmwareArtifactError(
                f"maintenance ELF segment outside nRF51 flash/SRAM: {address:#x}+{len(data):#x}"
            )

    @staticmethod
    def _read_symbols(elf: Any) -> dict[str, int]:
        symbol_table = elf.get_section_by_name(".symtab")
        if symbol_table is None:
            raise MaintenanceFirmwareArtifactError("maintenance ELF has no symbol table")
        return {
            symbol.name: int(symbol["st_value"])
            for symbol in symbol_table.iter_symbols()
            if symbol.name
        }

    @staticmethod
    def _find_svc_instructions(elf: Any) -> dict[int, int]:
        symbol_table = elf.get_section_by_name(".symtab")
        if symbol_table is None:
            raise MaintenanceFirmwareArtifactError("maintenance ELF has no symbol table")
        load_segments = [
            (int(segment["p_paddr"]), segment.data())
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]
        ]

        def read_instruction(address: int) -> bytes:
            for base, data in load_segments:
                offset = address - base
                if 0 <= offset <= len(data) - 2:
                    return data[offset : offset + 2]
            return b""

        result: dict[int, int] = {}
        for symbol in symbol_table.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address = int(symbol["st_value"]) & ~1
            instruction = read_instruction(address)
            if len(instruction) == 2 and instruction[1] == 0xDF:
                result[address] = instruction[0]
        if not result:
            raise MaintenanceFirmwareArtifactError(
                "maintenance ELF contains no S130 SVC wrappers"
            )
        return result

    def _symbol(self, name: str) -> int:
        try:
            return self._symbols[name] & ~1
        except KeyError as exc:
            raise MaintenanceFirmwareArtifactError(
                f"maintenance ELF is missing symbol: {name}"
            ) from exc

    def _call(self, symbol: str, *arguments: int) -> int:
        if len(arguments) > 4:
            raise ValueError("ARM register-call helper supports at most four arguments")
        assert self._ql is not None
        for index in range(4):
            value = arguments[index] if index < len(arguments) else 0
            self._ql.arch.regs.write(f"r{index}", value)
        self._ql.arch.regs.msp = _CALL_STACK
        self._ql.arch.regs.lr = _CALL_SENTINEL | 1
        address = self._symbol(symbol)
        self._ql.arch.regs.pc = address | 1
        try:
            self._ql.run(begin=address | 1, count=self.instruction_budget)
        except _FunctionReturned:
            return self._ql.arch.regs.r0
        except Exception as exc:
            raise MaintenanceFirmwareError(
                f"maintenance firmware faulted in {symbol}: {type(exc).__name__}: {exc}"
            ) from exc
        raise MaintenanceFirmwareError(f"maintenance firmware did not return from {symbol}")
