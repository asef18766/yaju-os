from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGER = REPOSITORY_ROOT / "scripts" / "package_release.py"
ATTACHMENT_ARCHIVE = "hitcon-legacy-dfu-attachment.zip"
SERVICE_ARCHIVE = "hitcon-legacy-dfu-service.zip"
SERVICE_DIRECTORY = "hitcon-legacy-dfu-service"


def verify_embedded_manifest(
    archive: zipfile.ZipFile, manifest_name: str, *, prefix: str = ""
) -> None:
    manifest = archive.read(manifest_name).decode("ascii")
    for line in manifest.splitlines():
        digest, relative_name = line.split("  ", 1)
        actual = hashlib.sha256(archive.read(prefix + relative_name)).hexdigest()
        if actual != digest:
            raise AssertionError(f"checksum mismatch for {relative_name}")


class ReleasePackagingTests(unittest.TestCase):
    def build_packages(
        self,
        output_dir: Path,
        handout: Path,
        reference_bootloader_elf: Path,
        maintenance_firmware_elf: Path,
    ) -> None:
        environment = {
            **os.environ,
            "SOURCE_DATE_EPOCH": "1760832000",
        }
        subprocess.run(
            [
                sys.executable,
                str(PACKAGER),
                "--handout",
                str(handout),
                "--reference-bootloader-elf",
                str(reference_bootloader_elf),
                "--maintenance-firmware-elf",
                str(maintenance_firmware_elf),
                "--output-dir",
                str(output_dir),
                "--revision",
                "test-revision",
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_release_archives_are_deterministic_and_safely_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            handout = root / "maintenance_application.bin"
            handout.write_bytes(b"compiled-thumb-firmware\x00\x01\x02")
            reference_bootloader_elf = root / "nrf51422_xxac.emulator.elf"
            reference_bootloader_elf.write_bytes(b"stripped-reference-elf\x00\x01")
            maintenance_firmware_elf = root / "maintenance_application.emulator.elf"
            maintenance_firmware_elf.write_bytes(b"stripped-maintenance-elf\x00\x01")
            first = root / "first"
            second = root / "second"
            self.build_packages(
                first,
                handout,
                reference_bootloader_elf,
                maintenance_firmware_elf,
            )
            self.build_packages(
                second,
                handout,
                reference_bootloader_elf,
                maintenance_firmware_elf,
            )

            for filename in (ATTACHMENT_ARCHIVE, SERVICE_ARCHIVE, "SHA256SUMS"):
                self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())

            with zipfile.ZipFile(first / ATTACHMENT_ARCHIVE) as archive:
                names = set(archive.namelist())
                required = {
                    ".dockerignore",
                    "BUILD_INFO",
                    "Dockerfile",
                    "README.md",
                    "SHA256SUMS",
                    "artifacts/maintenance_application/maintenance_application.elf",
                    "artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.elf",
                    "compose.yaml",
                    "local_flag.txt",
                    "maintenance_application.bin",
                    "pyproject.toml",
                    "src/hitcon_legacy_dfu/maintenance_runtime.py",
                    "src/hitcon_legacy_dfu/qiling_runtime.py",
                    "src/hitcon_legacy_dfu/session_host.py",
                    "workspace/probe.py",
                }
                self.assertTrue(required.issubset(names))
                self.assertEqual(
                    archive.read("maintenance_application.bin"), handout.read_bytes()
                )
                self.assertEqual(
                    archive.read(
                        "artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.elf"
                    ),
                    reference_bootloader_elf.read_bytes(),
                )
                self.assertEqual(
                    archive.read(
                        "artifacts/maintenance_application/maintenance_application.elf"
                    ),
                    maintenance_firmware_elf.read_bytes(),
                )
                self.assertEqual(
                    archive.read("local_flag.txt"), b"CTF{local_emulator_test_flag}\n"
                )
                for name in names:
                    path = PurePosixPath(name)
                    self.assertFalse(path.is_absolute())
                    self.assertNotIn("..", path.parts)
                    self.assertNotIn("tests", path.parts)
                    self.assertNotIn("firmware", path.parts)
                    self.assertNotIn("vendor", path.parts)
                    self.assertNotIn("__pycache__", path.parts)
                self.assertNotIn("src/hitcon_legacy_dfu/payloads.py", names)
                self.assertNotIn("src/hitcon_legacy_dfu/inmu_king_art.py", names)
                self.assertNotIn("scripts/smoke_player_attachment.py", names)
                player_text = b"\n".join(
                    archive.read(name)
                    for name in sorted(names)
                    if name.endswith((".py", ".md", ".toml", ".yaml"))
                )
                self.assertNotIn(b"make_gpio_dump_payload", player_text)
                self.assertNotIn(b"11451419198100", player_text)
                verify_embedded_manifest(archive, "SHA256SUMS")

            prefix = f"{SERVICE_DIRECTORY}/"
            with zipfile.ZipFile(first / SERVICE_ARCHIVE) as archive:
                names = set(archive.namelist())
                required = {
                    f"{prefix}.dockerignore",
                    f"{prefix}BUILD_INFO",
                    f"{prefix}DEPLOY.md",
                    f"{prefix}Dockerfile",
                    f"{prefix}SHA256SUMS",
                    f"{prefix}compose.yaml",
                    f"{prefix}flag.example",
                    f"{prefix}firmware/maintenance_application.c",
                    f"{prefix}pyproject.toml",
                    f"{prefix}scripts/build_maintenance_application.sh",
                    f"{prefix}src/hitcon_legacy_dfu/session_host.py",
                }
                self.assertTrue(required.issubset(names))
                self.assertNotIn(f"{prefix}scripts/package_release.py", names)
                self.assertNotIn(f"{prefix}scripts/smoke_player_attachment.py", names)
                for name in names:
                    path = PurePosixPath(name)
                    self.assertFalse(path.is_absolute())
                    self.assertNotIn("..", path.parts)
                    self.assertNotIn("flag.txt", path.parts)
                    self.assertNotIn("artifacts", path.parts)
                    self.assertNotIn("tests", path.parts)
                    self.assertNotIn("vendor", path.parts)
                    self.assertNotIn("__pycache__", path.parts)
                verify_embedded_manifest(
                    archive,
                    f"{prefix}SHA256SUMS",
                    prefix=prefix,
                )
                script = archive.getinfo(
                    f"{prefix}scripts/build_maintenance_application.sh"
                )
                mode = (script.external_attr >> 16) & 0o777
                self.assertTrue(mode & stat.S_IXUSR)
                self.assertIn(
                    b"replace_this_with_the_real_per_team_flag",
                    archive.read(f"{prefix}flag.example"),
                )

            outer_manifest = (first / "SHA256SUMS").read_text(encoding="ascii")
            for line in outer_manifest.splitlines():
                digest, filename = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((first / filename).read_bytes()).hexdigest(),
                    digest,
                )


if __name__ == "__main__":
    unittest.main()
