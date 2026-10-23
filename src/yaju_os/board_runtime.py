"""Validated runtime description for one combined nRF51 board image.

The player lab deliberately ships a raw 256 KiB flash image instead of one
ELF per execution phase.  Qiling still needs a small amount of information
that is not present in a stripped raw binary (function entry points and S130
SVC wrapper locations), so the build emits that narrow ABI as deterministic
JSON beside the image.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any


BOARD_RUNTIME_FORMAT = "hitcon-nrf51-board-runtime"
BOARD_RUNTIME_VERSION = 2
BOARD_FLASH_SIZE = 0x0004_0000
BOARD_FLASH_FILENAME = "board_flash.bin"
BOARD_METADATA_FILENAME = "runtime_symbols.json"


class BoardRuntimeArtifactError(RuntimeError):
    """A combined board image or its runtime metadata is invalid."""


@dataclass(frozen=True)
class BoardRuntimePhase:
    """Runtime-only ABI for one reset-selected firmware phase."""

    name: str
    entry_point: int
    symbols: dict[str, int]
    svc_addresses: dict[int, int]


@dataclass(frozen=True)
class BoardRuntimeArtifact:
    """One immutable nRF51 flash image shared by all emulated reset phases."""

    directory: Path
    flash_path: Path
    metadata_path: Path
    flash: bytes
    flash_sha256: str
    application_base: int
    bootloader_base: int
    phases: dict[str, BoardRuntimePhase]

    @classmethod
    def load(cls, path: str | Path) -> "BoardRuntimeArtifact":
        requested = Path(path).expanduser().resolve()
        if requested.is_dir():
            directory = requested
            metadata_path = directory / BOARD_METADATA_FILENAME
        elif requested.name == BOARD_METADATA_FILENAME:
            directory = requested.parent
            metadata_path = requested
        elif requested.name == BOARD_FLASH_FILENAME:
            directory = requested.parent
            metadata_path = directory / BOARD_METADATA_FILENAME
        else:
            raise BoardRuntimeArtifactError(
                "board runtime must be a directory, board_flash.bin, or "
                "runtime_symbols.json"
            )

        flash_path = directory / BOARD_FLASH_FILENAME
        if not flash_path.is_file():
            raise BoardRuntimeArtifactError(f"board flash image does not exist: {flash_path}")
        if not metadata_path.is_file():
            raise BoardRuntimeArtifactError(
                f"board runtime metadata does not exist: {metadata_path}"
            )

        try:
            raw_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BoardRuntimeArtifactError(
                f"cannot read board runtime metadata: {metadata_path}: {exc}"
            ) from exc
        if not isinstance(raw_metadata, dict):
            raise BoardRuntimeArtifactError("board runtime metadata root must be an object")
        if raw_metadata.get("format") != BOARD_RUNTIME_FORMAT:
            raise BoardRuntimeArtifactError("unsupported board runtime metadata format")
        if raw_metadata.get("format_version") != BOARD_RUNTIME_VERSION:
            raise BoardRuntimeArtifactError("unsupported board runtime metadata version")
        if raw_metadata.get("target") != "nrf51422_xxac":
            raise BoardRuntimeArtifactError("board runtime target must be nrf51422_xxac")

        flash_metadata = cls._object(raw_metadata, "flash")
        if flash_metadata.get("file") != BOARD_FLASH_FILENAME:
            raise BoardRuntimeArtifactError("board runtime metadata names an unexpected flash file")
        if cls._integer(flash_metadata, "size") != BOARD_FLASH_SIZE:
            raise BoardRuntimeArtifactError(
                f"board flash size must be exactly {BOARD_FLASH_SIZE} bytes"
            )
        flash = flash_path.read_bytes()
        if len(flash) != BOARD_FLASH_SIZE:
            raise BoardRuntimeArtifactError(
                f"board flash image is {len(flash)} bytes, expected {BOARD_FLASH_SIZE}"
            )
        flash_sha256 = hashlib.sha256(flash).hexdigest()
        if flash_metadata.get("sha256") != flash_sha256:
            raise BoardRuntimeArtifactError("board flash SHA-256 does not match metadata")

        memory = cls._object(raw_metadata, "memory")
        application_base = cls._flash_address(memory, "application_base")
        bootloader_base = cls._flash_address(memory, "bootloader_base")
        if application_base >= bootloader_base:
            raise BoardRuntimeArtifactError(
                "application_base must be below bootloader_base"
            )

        raw_phases = cls._object(raw_metadata, "phases")
        phases = {
            name: cls._parse_phase(name, raw_phases.get(name), flash)
            for name in ("maintenance", "bootloader")
        }
        return cls(
            directory=directory,
            flash_path=flash_path,
            metadata_path=metadata_path,
            flash=flash,
            flash_sha256=flash_sha256,
            application_base=application_base,
            bootloader_base=bootloader_base,
            phases=phases,
        )

    @staticmethod
    def repository_path() -> Path:
        """Locate the combined artifact in a checkout or packaged image."""

        configured_path = os.environ.get("HITCON_BOARD_RUNTIME")
        if configured_path:
            return Path(configured_path).expanduser().resolve()
        return Path(__file__).resolve().parents[2] / "artifacts" / "board_runtime"

    def phase(self, name: str) -> BoardRuntimePhase:
        try:
            return self.phases[name]
        except KeyError as exc:
            raise BoardRuntimeArtifactError(f"unknown board runtime phase: {name}") from exc

    @classmethod
    def _parse_phase(
        cls, name: str, raw_phase: Any, flash: bytes
    ) -> BoardRuntimePhase:
        if not isinstance(raw_phase, dict):
            raise BoardRuntimeArtifactError(f"phase {name!r} must be an object")
        entry_point = cls._flash_address(raw_phase, "entry_point")
        raw_symbols = cls._object(raw_phase, "symbols")
        symbols: dict[str, int] = {}
        for symbol_name, raw_address in raw_symbols.items():
            if not isinstance(symbol_name, str) or not symbol_name:
                raise BoardRuntimeArtifactError(f"phase {name!r} has an invalid symbol name")
            if not isinstance(raw_address, int) or isinstance(raw_address, bool):
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} symbol {symbol_name!r} address must be an integer"
                )
            if not 0 <= raw_address <= 0xFFFF_FFFF:
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} symbol {symbol_name!r} is outside uint32"
                )
            symbols[symbol_name] = raw_address
        if not symbols:
            raise BoardRuntimeArtifactError(f"phase {name!r} has no runtime symbols")

        raw_svc = cls._object(raw_phase, "svc_addresses")
        svc_addresses: dict[int, int] = {}
        for raw_address, raw_number in raw_svc.items():
            try:
                address = int(raw_address, 0)
            except (TypeError, ValueError) as exc:
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} has an invalid SVC address: {raw_address!r}"
                ) from exc
            if not isinstance(raw_number, int) or isinstance(raw_number, bool):
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} SVC number at {address:#x} must be an integer"
                )
            if not 0 <= address < len(flash) - 1 or not 0 <= raw_number <= 0xFF:
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} has an out-of-range SVC entry"
                )
            if flash[address : address + 2] != bytes((raw_number, 0xDF)):
                raise BoardRuntimeArtifactError(
                    f"phase {name!r} SVC metadata does not match flash at {address:#x}"
                )
            svc_addresses[address] = raw_number
        if not svc_addresses:
            raise BoardRuntimeArtifactError(f"phase {name!r} has no SVC wrappers")
        return BoardRuntimePhase(
            name=name,
            entry_point=entry_point,
            symbols=symbols,
            svc_addresses=svc_addresses,
        )

    @staticmethod
    def _object(parent: dict[str, Any], key: str) -> dict[str, Any]:
        value = parent.get(key)
        if not isinstance(value, dict):
            raise BoardRuntimeArtifactError(f"board runtime field {key!r} must be an object")
        return value

    @staticmethod
    def _integer(parent: dict[str, Any], key: str) -> int:
        value = parent.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise BoardRuntimeArtifactError(f"board runtime field {key!r} must be an integer")
        return value

    @classmethod
    def _flash_address(cls, parent: dict[str, Any], key: str) -> int:
        value = cls._integer(parent, key)
        normalized = value & ~1
        if not 0 <= normalized < BOARD_FLASH_SIZE:
            raise BoardRuntimeArtifactError(
                f"board runtime field {key!r} is outside nRF51 flash"
            )
        return value
