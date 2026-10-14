"""Qiling execution boundary for the board's normal application firmware.

The initial BLE service is deliberately not Nordic DFU.  Its write callback
enters ``maintenance_command`` in a compiled Thumb application and observes
the nRF51 ``POWER.GPREGRET`` boot reason written by that code.  This keeps the
mode-switch authorization in the firmware handed to players, while Bumble
continues to supply the HCI/GATT transport that is outside the scope of the
SoftDevice emulation.
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


class MaintenanceFirmwareError(RuntimeError):
    """The normal application firmware cannot be loaded or invoked."""


class MaintenanceFirmwareArtifactError(MaintenanceFirmwareError):
    """The built application artifact is missing or lacks its entry point."""


class _FunctionReturned(Exception):
    """Internal trampoline signal for a Thumb function return."""


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
class MaintenanceFirmwareBootResult:
    """Immutable identity information for the loaded application artifact."""

    elf_path: Path
    elf_sha256: str
    entry_point: int
    command_handler: int


class MaintenanceFirmwareRuntime:
    """Load the application ELF and invoke its maintenance control handler."""

    def __init__(self, elf_path: Path, *, instruction_budget: int = 5_000) -> None:
        if instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")
        self.elf_path = Path(elf_path).resolve()
        self.instruction_budget = instruction_budget
        self._ql: Any | None = None
        self._bootstrap: tempfile._TemporaryFileWrapper[bytes] | None = None
        self._symbols: dict[str, int] = {}
        self._power: _PowerRegisters | None = None
        self._boot_result: MaintenanceFirmwareBootResult | None = None
        self._closed = False
        self._lock = threading.Lock()

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

    def __enter__(self) -> "MaintenanceFirmwareRuntime":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Release Qiling's bootstrap file and make future calls invalid."""

        with self._lock:
            if self._bootstrap is not None:
                self._bootstrap.close()
                self._bootstrap = None
            self._ql = None
            self._power = None
            self._closed = True

    def boot(self) -> MaintenanceFirmwareBootResult:
        """Load and validate the handout ELF without duplicating its checks."""

        with self._lock:
            self._prepare_qiling()
            assert self._boot_result is not None
            return self._boot_result

    def request_bootloader(self, payload: bytes) -> bool:
        """Run the real Thumb authorization routine for one GATT write.

        The return is accepted only when the routine returns nonzero *and*
        asks the nRF51 bootloader for DFU using its GPREGRET convention.
        """

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
            from elftools.elf.elffile import ELFFile
            from qiling import Qiling
            from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        except ModuleNotFoundError as exc:
            raise MaintenanceFirmwareArtifactError(
                "Qiling and pyelftools are required; install the 'emulator' extra"
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

        command_handler = self._symbol("maintenance_command")
        self._symbol("Reset_Handler")
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
            ql.mem.write(_CALL_SENTINEL, b"\x00\xbf")
            ql.hook_code(self._on_code)
        except BaseException:
            bootstrap.close()
            raise

        self._bootstrap = bootstrap
        self._ql = ql
        self._power = power
        self._boot_result = MaintenanceFirmwareBootResult(
            elf_path=self.elf_path,
            elf_sha256=hashlib.sha256(self.elf_path.read_bytes()).hexdigest(),
            entry_point=entry_point,
            command_handler=command_handler,
        )

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

    def _symbol(self, name: str) -> int:
        try:
            return self._symbols[name] & ~1
        except KeyError as exc:
            raise MaintenanceFirmwareArtifactError(
                f"maintenance ELF is missing symbol: {name}"
            ) from exc

    def _on_code(self, _ql: Any, address: int, _size: int) -> None:
        if address == _CALL_SENTINEL:
            raise _FunctionReturned()

    def _call(self, symbol: str, *arguments: int) -> int:
        if len(arguments) > 4:
            raise ValueError("ARM register-call helper supports at most four arguments")
        assert self._ql is not None
        for index in range(4):
            self._ql.arch.regs.write(f"r{index}", arguments[index] if index < len(arguments) else 0)
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
