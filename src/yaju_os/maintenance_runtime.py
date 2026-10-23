"""Qiling boundary for the board's compiled normal-application firmware.

The application registers its GATT services through the Nordic S130 SVC ABI
and handles read-authorization events as compiled Thumb code. This runtime is
the deliberately narrow SoftDevice shim: it records those generic GATTS calls,
delivers ``ble_evt_t`` events, and captures authorization replies. It does not
contain animation UUIDs, frame data, or playback state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import threading
from typing import Any
from uuid import UUID

from .board_runtime import BoardRuntimeArtifact, BoardRuntimeArtifactError
from .s130_abi import (
    MAX_ATTRIBUTE_LENGTH as _MAX_ATTRIBUTE_LENGTH,
    NRF_ERROR_INVALID_PARAM,
    NRF_SUCCESS,
    SVC_BLE_GATTS_CHARACTERISTIC_ADD as _SVC_BLE_GATTS_CHARACTERISTIC_ADD,
    SVC_BLE_GATTS_SERVICE_ADD as _SVC_BLE_GATTS_SERVICE_ADD,
    SVC_BLE_UUID_VS_ADD as _SVC_BLE_UUID_VS_ADD,
    FirmwareGattService,
    GuestReader,
    S130GattsRegistry,
)

_FLASH_SIZE = 0x0004_0000
_SRAM_BASE = 0x2000_0000
_SRAM_SIZE = 0x0000_8000
_POWER_BASE = 0x4000_0000
_POWER_SIZE = 0x1000
_POWER_GPREGRET_OFFSET = 0x51C
_MAINTENANCE_BOOT_REQUEST = 0xB1
_CALL_SENTINEL = 0x2000_7E00
_CALL_STACK = 0x2000_7D00
_COMMAND_BUFFER = 0x2000_7000
_MAX_COMMAND_LENGTH = 20
_BLE_EVENT_BUFFER = 0x2000_7100

# S130 2.0.0 event identifiers used by this application; the GATT-server SVC
# numbers and struct layouts live in :mod:`.s130_abi`.
_SVC_BLE_GATTS_RW_AUTHORIZE_REPLY = 0xA8
_BLE_GAP_EVT_CONNECTED = 0x10
_BLE_GAP_EVT_DISCONNECTED = 0x11
_BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST = 0x51
_BLE_GATTS_AUTHORIZE_TYPE_READ = 1


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


class MaintenanceFirmwareRuntime:
    """Execute the normal application and emulate its narrow S130 boundary."""

    def __init__(self, elf_path: Path, *, instruction_budget: int = 5_000) -> None:
        if instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")
        try:
            self._board_artifact = BoardRuntimeArtifact.load(Path(elf_path))
        except BoardRuntimeArtifactError as exc:
            raise MaintenanceFirmwareArtifactError(str(exc)) from exc
        self.elf_path = self._board_artifact.flash_path
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
        self._gatts = S130GattsRegistry()
        self._mem: GuestReader | None = None
        self._connection_handle: int | None = None
        self._pending_read_reply: FirmwareGattReadReply | None = None
        self._awaiting_read_authorization = False

    @staticmethod
    def repository_board_runtime() -> Path:
        """Locate the board artifact in a checkout or Compose image."""

        configured_path = os.environ.get("HITCON_MAINTENANCE_FIRMWARE_ELF")
        if configured_path:
            return Path(configured_path).expanduser().resolve()
        return Path(__file__).resolve().parents[2] / "artifacts" / "board_runtime"

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
            self._mem = None
            self._gatts.detach()
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
            result = self._call("command_handler", _COMMAND_BUFFER, len(request))
            return result != 0 and (self._power.gpregret & 0xFF) == _MAINTENANCE_BOOT_REQUEST

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
            characteristic = self._gatts.characteristic_by_value_handle(
                firmware_value_handle
            )
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
        self._call("ble_event_dispatch", _BLE_EVENT_BUFFER)

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

        phase = self._board_artifact.phase("maintenance")
        self._symbols = dict(phase.symbols)
        entry_point = phase.entry_point
        segments = [(0, self._board_artifact.flash)]
        self._svc_addresses = dict(phase.svc_addresses)

        command_handler = self._symbol("command_handler")
        for role in ("reset_handler", "service_init", "ble_event_dispatch"):
            self._symbol(role)

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
        self._mem = GuestReader(ql.mem)
        self._gatts.attach(ql.mem)
        try:
            init_result = self._call("service_init")
            if init_result != NRF_SUCCESS:
                raise MaintenanceFirmwareArtifactError(
                    f"firmware GATT initialization returned {init_result}"
                )
            services = self._gatts.services
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
            self._mem = None
            self._gatts.detach()
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
            ql.arch.regs.r0 = self._gatts.uuid_vs_add(ql.arch.regs.r0, ql.arch.regs.r1)
            return
        if svc_number == _SVC_BLE_GATTS_SERVICE_ADD:
            ql.arch.regs.r0 = self._gatts.service_add(
                ql.arch.regs.r0, ql.arch.regs.r1, ql.arch.regs.r2
            )
            return
        if svc_number == _SVC_BLE_GATTS_CHARACTERISTIC_ADD:
            ql.arch.regs.r0 = self._gatts.characteristic_add(
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

    def _memory(self) -> GuestReader:
        if self._mem is None:
            raise MaintenanceFirmwareError("firmware runtime is not booted")
        return self._mem

    def _handle_authorize_reply(
        self, connection_handle: int, parameters_pointer: int
    ) -> int:
        if (
            not self._awaiting_read_authorization
            or self._connection_handle != connection_handle
            or not parameters_pointer
        ):
            return NRF_ERROR_INVALID_STATE
        if self._memory().u8(parameters_pointer) != _BLE_GATTS_AUTHORIZE_TYPE_READ:
            return NRF_ERROR_INVALID_PARAM

        # ARM EABI aligns the authorization union to four bytes. Its read
        # member is: u16 status, u8 update bitfield, pad, u16 offset, u16 len,
        # then a 32-bit data pointer.
        gatt_status = self._memory().u16(parameters_pointer + 4)
        update = bool(self._memory().u8(parameters_pointer + 6) & 0x01)
        offset = self._memory().u16(parameters_pointer + 8)
        length = self._memory().u16(parameters_pointer + 10)
        data_pointer = self._memory().u32(parameters_pointer + 12)
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

    @staticmethod
    def _validate_segment(address: int, data: bytes) -> None:
        end = address + len(data)
        in_flash = 0 <= address and end <= _FLASH_SIZE
        in_sram = _SRAM_BASE <= address and end <= _SRAM_BASE + _SRAM_SIZE
        if not (in_flash or in_sram):
            raise MaintenanceFirmwareArtifactError(
                f"maintenance ELF segment outside nRF51 flash/SRAM: {address:#x}+{len(data):#x}"
            )

    def _symbol(self, role: str) -> int:
        try:
            return self._symbols[role] & ~1
        except KeyError as exc:
            raise MaintenanceFirmwareArtifactError(
                f"board runtime metadata is missing the {role!r} address"
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
