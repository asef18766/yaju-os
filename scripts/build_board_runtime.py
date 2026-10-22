#!/usr/bin/env python3
"""Combine the challenge application and bootloader into one board image."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


FLASH_SIZE = 0x0004_0000
APPLICATION_BASE = 0x0001_B000
BOOTLOADER_BASE = 0x0003_C000
FORMAT_NAME = "hitcon-nrf51-board-runtime"
FORMAT_VERSION = 1

PHASE_SYMBOLS = {
    "maintenance": (
        "Reset_Handler",
        "application_init",
        "application_ble_evt",
        "maintenance_command",
    ),
    "bootloader": (
        "Reset_Handler",
        "dfu_init_prevalidate",
        "dfu_init_postvalidate",
        "ble_evt_dispatch",
        "pstorage_sys_event_handler",
        "app_timer_start",
        "app_timer_stop",
        "m_dfu",
        "m_dfu_state",
        "m_image_size",
        "m_cmd_queue",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build one raw nRF51 board flash image and its narrow Qiling ABI metadata."
    )
    parser.add_argument("--maintenance-bin", type=Path, required=True)
    parser.add_argument("--maintenance-elf", type=Path, required=True)
    parser.add_argument("--bootloader-bin", type=Path, required=True)
    parser.add_argument("--bootloader-elf", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def run_tool(*arguments: str) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"required tool is unavailable: {arguments[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise RuntimeError(f"{' '.join(arguments)} failed: {detail}") from exc
    return completed.stdout


def read_phase(phase_name: str, elf_path: Path, flash: bytes) -> dict[str, object]:
    if not elf_path.is_file():
        raise FileNotFoundError(f"{phase_name} ELF does not exist: {elf_path}")
    symbol_rows: list[tuple[str, str, int]] = []
    for line in run_tool(
        "arm-none-eabi-nm", "-a", "--format=posix", str(elf_path)
    ).splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            address = int(fields[2], 16)
        except ValueError:
            continue
        symbol_rows.append((fields[0], fields[1], address))

    symbols_by_name = {name: address for name, _kind, address in symbol_rows}
    missing = [name for name in PHASE_SYMBOLS[phase_name] if name not in symbols_by_name]
    if missing:
        raise RuntimeError(
            f"{phase_name} ELF lacks required runtime symbols: {', '.join(missing)}"
        )
    symbols = {
        name: symbols_by_name[name]
        for name in PHASE_SYMBOLS[phase_name]
    }

    svc_addresses: dict[str, int] = {}
    for symbol_name, kind, raw_address in symbol_rows:
        if symbol_name.startswith("sd_") and kind in {"t", "T"}:
            address = raw_address & ~1
            instruction = flash[address : address + 2]
            if len(instruction) == 2 and instruction[1] == 0xDF:
                svc_addresses[f"0x{address:08x}"] = instruction[0]
    if not svc_addresses:
        raise RuntimeError(f"{phase_name} ELF exposes no S130 SVC wrappers")

    header = run_tool("arm-none-eabi-readelf", "-h", str(elf_path))
    match = re.search(r"Entry point address:\s*(0x[0-9a-fA-F]+)", header)
    if match is None:
        raise RuntimeError(f"cannot read {phase_name} ELF entry point")
    return {
        "entry_point": int(match.group(1), 16),
        "symbols": symbols,
        "svc_addresses": dict(sorted(svc_addresses.items())),
    }


def read_binary(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    data = path.read_bytes()
    if not data:
        raise ValueError(f"{label} is empty: {path}")
    return data


def place_image(flash: bytearray, base: int, data: bytes, label: str) -> None:
    end = base + len(data)
    if end > len(flash):
        raise ValueError(f"{label} exceeds nRF51 flash: {base:#x}+{len(data):#x}")
    if any(value != 0xFF for value in flash[base:end]):
        raise ValueError(f"{label} overlaps another flash region")
    flash[base:end] = data


def build(args: argparse.Namespace) -> tuple[Path, Path]:
    maintenance = read_binary(args.maintenance_bin, "maintenance binary")
    bootloader = read_binary(args.bootloader_bin, "bootloader binary")
    if APPLICATION_BASE + len(maintenance) > BOOTLOADER_BASE:
        raise ValueError("maintenance binary overlaps the bootloader region")
    flash = bytearray(b"\xff" * FLASH_SIZE)
    place_image(flash, APPLICATION_BASE, maintenance, "maintenance binary")
    place_image(flash, BOOTLOADER_BASE, bootloader, "bootloader binary")

    flash_bytes = bytes(flash)
    flash_sha256 = hashlib.sha256(flash_bytes).hexdigest()
    metadata = {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "target": "nrf51422_xxac",
        "flash": {
            "file": "board_flash.bin",
            "size": FLASH_SIZE,
            "sha256": flash_sha256,
        },
        "memory": {
            "application_base": APPLICATION_BASE,
            "bootloader_base": BOOTLOADER_BASE,
        },
        "phases": {
            "maintenance": read_phase("maintenance", args.maintenance_elf, flash_bytes),
            "bootloader": read_phase("bootloader", args.bootloader_elf, flash_bytes),
        },
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    flash_path = args.output_dir / "board_flash.bin"
    metadata_path = args.output_dir / "runtime_symbols.json"
    flash_path.write_bytes(flash_bytes)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "SHA256SUMS").write_text(
        f"{flash_sha256}  board_flash.bin\n"
        f"{hashlib.sha256(metadata_path.read_bytes()).hexdigest()}  runtime_symbols.json\n",
        encoding="ascii",
    )
    return flash_path, metadata_path


def main() -> int:
    try:
        outputs = build(parse_args())
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"Board runtime build failed: {exc}", file=sys.stderr)
        return 1
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
