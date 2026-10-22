#!/usr/bin/env python3
"""Build deterministic player and service release ZIP files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ATTACHMENT_ARCHIVE = "hitcon-legacy-dfu-attachment.zip"
SERVICE_ARCHIVE = "hitcon-legacy-dfu-service.zip"
SERVICE_DIRECTORY = "hitcon-legacy-dfu-service"
DEFAULT_SOURCE_DATE_EPOCH = 315532800  # 1980-01-01, ZIP's earliest date.

ATTACHMENT_STATIC_FILES = (
    ("packaging/attachment/.dockerignore", ".dockerignore"),
    ("packaging/attachment/Dockerfile", "Dockerfile"),
    ("packaging/attachment/README.md", "README.md"),
    ("packaging/attachment/compose.yaml", "compose.yaml"),
    ("packaging/attachment/local_flag.txt", "local_flag.txt"),
    ("packaging/attachment/probe.py", "workspace/probe.py"),
    ("pyproject.toml", "pyproject.toml"),
)

# Both release bundles contain only the production board-image runtime. Python
# DFU models, clients, payload generators, offline art, and organizer helpers
# remain in the repository for development/tests but are not deployed.
RELEASE_RUNTIME_FILES = (
    "src/hitcon_legacy_dfu/__init__.py",
    "src/hitcon_legacy_dfu/board_runtime.py",
    "src/hitcon_legacy_dfu/gatt_ids.py",
    "src/hitcon_legacy_dfu/hardware.py",
    "src/hitcon_legacy_dfu/maintenance_runtime.py",
    "src/hitcon_legacy_dfu/nrf51_sdk11_runtime.py",
    "src/hitcon_legacy_dfu/qiling_rootcanal.py",
    "src/hitcon_legacy_dfu/qiling_runtime.py",
    "src/hitcon_legacy_dfu/runner.py",
    "src/hitcon_legacy_dfu/s130_gatt.py",
    "src/hitcon_legacy_dfu/session_host.py",
)
ATTACHMENT_RUNTIME_FILES = RELEASE_RUNTIME_FILES

SERVICE_FILES = (
    ".dockerignore",
    "Dockerfile",
    "README.md",
    "compose.yaml",
    "flag.example",
    "pyproject.toml",
    "firmware/maintenance_application.c",
    "firmware/maintenance_application.ld",
    "scripts/build_maintenance_application.sh",
    "scripts/build_board_runtime.py",
    "scripts/build_nrf51_sdk11_legacy_dfu.sh",
    "scripts/fetch_nrf51_sdk11.sh",
) + RELEASE_RUNTIME_FILES


@dataclass(frozen=True)
class ArchiveEntry:
    data: bytes
    mode: int = 0o644


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package the player handout and deployable service source."
    )
    parser.add_argument(
        "--board-flash",
        type=Path,
        required=True,
        help="combined 256 KiB nRF51 board_flash.bin",
    )
    parser.add_argument(
        "--runtime-symbols",
        type=Path,
        required=True,
        help="runtime_symbols.json paired with the combined board image",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPOSITORY_ROOT / "dist",
        help="directory receiving both ZIP files and their SHA256SUMS",
    )
    parser.add_argument(
        "--revision",
        default=os.environ.get("GITHUB_SHA", "unknown"),
        help="source revision recorded in each bundle (default: GITHUB_SHA or unknown)",
    )
    return parser.parse_args()


def checked_revision(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/+@:-]{0,127}", value):
        raise ValueError("revision must be 1-128 safe printable characters")
    return value


def zip_timestamp() -> tuple[int, int, int, int, int, int]:
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", str(DEFAULT_SOURCE_DATE_EPOCH))
    try:
        epoch = int(raw_epoch)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    instant = datetime.fromtimestamp(epoch, timezone.utc)
    if instant.year < 1980 or instant.year > 2107:
        raise ValueError("SOURCE_DATE_EPOCH must fall within ZIP's 1980-2107 range")
    return (
        instant.year,
        instant.month,
        instant.day,
        instant.hour,
        instant.minute,
        instant.second,
    )


def read_source(relative_path: str) -> ArchiveEntry:
    source = REPOSITORY_ROOT / relative_path
    if source.is_symlink() or not source.is_file():
        raise FileNotFoundError(f"release source must be a regular file: {source}")
    mode = stat.S_IMODE(source.stat().st_mode)
    return ArchiveEntry(source.read_bytes(), mode)


def read_artifact(path: Path, label: str) -> ArchiveEntry:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(f"{label} must be a regular file: {path}")
    data = path.read_bytes()
    if not data:
        raise ValueError(f"{label} must not be empty")
    return ArchiveEntry(data)


def checksum_manifest(entries: dict[str, ArchiveEntry]) -> bytes:
    lines = []
    for name in sorted(entries):
        digest = hashlib.sha256(entries[name].data).hexdigest()
        lines.append(f"{digest}  {name}\n")
    return "".join(lines).encode("ascii")


def attachment_entries(
    board_flash: Path,
    runtime_symbols: Path,
    revision: str,
) -> dict[str, ArchiveEntry]:
    board = read_artifact(board_flash, "combined board flash")
    symbols = read_artifact(runtime_symbols, "board runtime symbols")
    entries = {
        archive_path: read_source(source_path)
        for source_path, archive_path in ATTACHMENT_STATIC_FILES
    }
    entries.update({path: read_source(path) for path in ATTACHMENT_RUNTIME_FILES})
    entries.update(
        {
            "BUILD_INFO": ArchiveEntry(
                (
                    "bundle=player-attachment\n"
                    f"revision={revision}\n"
                    "target=nrf51422_xxac\n"
                    "application_base=0x0001b000\n"
                    "board_flash_sha256="
                    f"{hashlib.sha256(board.data).hexdigest()}\n"
                    "runtime_symbols_sha256="
                    f"{hashlib.sha256(symbols.data).hexdigest()}\n"
                ).encode("ascii")
            ),
            "artifacts/board_runtime/board_flash.bin": board,
            "artifacts/board_runtime/runtime_symbols.json": symbols,
        }
    )
    entries["SHA256SUMS"] = ArchiveEntry(checksum_manifest(entries))
    return entries


def service_entries(revision: str) -> dict[str, ArchiveEntry]:
    entries = {path: read_source(path) for path in SERVICE_FILES}
    entries["DEPLOY.md"] = read_source("packaging/service/DEPLOY.md")
    entries["BUILD_INFO"] = ArchiveEntry(
        ("bundle=service\n" f"revision={revision}\n").encode("ascii")
    )
    entries["SHA256SUMS"] = ArchiveEntry(checksum_manifest(entries))
    return entries


def write_zip(
    destination: Path,
    entries: dict[str, ArchiveEntry],
    timestamp: tuple[int, int, int, int, int, int],
    *,
    prefix: str | None = None,
) -> None:
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(entries):
            archive_name = PurePosixPath(prefix, name).as_posix() if prefix else name
            information = zipfile.ZipInfo(archive_name, date_time=timestamp)
            information.create_system = 3
            information.compress_type = zipfile.ZIP_DEFLATED
            information.external_attr = (
                stat.S_IFREG | entries[name].mode
            ) << 16
            archive.writestr(information, entries[name].data, compresslevel=9)


def package(
    board_flash: Path,
    runtime_symbols: Path,
    output_dir: Path,
    revision: str,
) -> tuple[Path, Path, Path]:
    revision = checked_revision(revision)
    timestamp = zip_timestamp()
    output_dir.mkdir(parents=True, exist_ok=True)
    attachment_path = output_dir / ATTACHMENT_ARCHIVE
    service_path = output_dir / SERVICE_ARCHIVE

    write_zip(
        attachment_path,
        attachment_entries(
            board_flash,
            runtime_symbols,
            revision,
        ),
        timestamp,
    )
    write_zip(
        service_path,
        service_entries(revision),
        timestamp,
        prefix=SERVICE_DIRECTORY,
    )

    release_files = (attachment_path, service_path)
    outer_manifest = output_dir / "SHA256SUMS"
    outer_manifest.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in release_files
        ),
        encoding="ascii",
    )
    return attachment_path, service_path, outer_manifest


def main() -> int:
    args = parse_args()
    try:
        outputs = package(
            args.board_flash,
            args.runtime_symbols,
            args.output_dir,
            args.revision,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"Packaging failed: {exc}", file=sys.stderr)
        return 1
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
