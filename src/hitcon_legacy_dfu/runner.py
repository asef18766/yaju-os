"""Command-line runner for one legacy-DFU challenge target instance."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from pathlib import Path
import signal
from typing import Sequence

from .bootloader import BootloaderConfig, LegacyDfuBootloader
from .board_runtime import BoardRuntimeArtifact
from .bridge import LegacyDfuGattBridge
from .bumble_adapter import LegacyDfuBumblePeripheral
from .maintenance_runtime import MaintenanceFirmwareRuntime
from .qiling_runtime import QilingRuntime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expose a legacy Nordic DFU CTF target through a Rootcanal HCI TCP port."
    )
    parser.add_argument(
        "--secret-file",
        type=Path,
        required=True,
        help="file containing this instance's flag; it is only supplied to the host GPIO model",
    )
    parser.add_argument(
        "--hci-transport",
        default="tcp-client:127.0.0.1:6402",
        help="Bumble transport spec for the target controller (default: %(default)s)",
    )
    parser.add_argument("--name", default="HITCON Field Node", help="advertised BLE name")
    parser.add_argument(
        "--address",
        default="F6:F7:F8:F9:FA:FB",
        help="static random BLE address exposed by the target",
    )
    parser.add_argument(
        "--instruction-budget",
        type=int,
        default=5_000,
        help="maximum Cortex-M instructions per post-reset execution",
    )
    parser.add_argument(
        "--board-runtime",
        type=Path,
        help=(
            "directory containing one board_flash.bin and runtime_symbols.json; "
            "selects both the maintenance and bootloader reset phases"
        ),
    )
    parser.add_argument(
        "--reference-bootloader-elf",
        type=Path,
        help=(
            "Nordic SDK 11 nRF51 ELF to boot under Qiling; when supplied, "
            "Rootcanal GATT writes drive the compiled legacy-DFU implementation "
            "rather than the Python challenge model"
        ),
    )
    parser.add_argument(
        "--maintenance-firmware-elf",
        type=Path,
        help=(
            "normal application ELF that must authorize the reset into legacy DFU; "
            "requires --reference-bootloader-elf"
        ),
    )
    return parser


async def serve(args: argparse.Namespace) -> None:
    if args.instruction_budget <= 0:
        raise ValueError("--instruction-budget must be positive")
    secret = args.secret_file.read_bytes()
    if not secret:
        raise ValueError("--secret-file must not be empty")

    config = BootloaderConfig.nrf51_sdk11_pca10028_s130()
    runtime = QilingRuntime(
        secret,
        flash_size=config.flash_size,
        sram_base=config.sram_base,
        sram_size=config.sram_size,
        instruction_budget=args.instruction_budget,
    )
    if args.board_runtime is not None and (
        args.reference_bootloader_elf is not None
        or args.maintenance_firmware_elf is not None
    ):
        raise ValueError(
            "--board-runtime cannot be combined with the legacy per-phase ELF options"
        )
    if args.maintenance_firmware_elf is not None and args.reference_bootloader_elf is None:
        raise ValueError("--maintenance-firmware-elf requires --reference-bootloader-elf")

    reference_runtime = None
    maintenance_runtime = None
    if args.board_runtime is not None:
        # Validate once up front; both phase runtimes then load the exact same
        # immutable flash image and select their reset entry from its metadata.
        BoardRuntimeArtifact.load(args.board_runtime)
        from .nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime

        reference_runtime = Nrf51Sdk11BootloaderRuntime.from_board_runtime(
            args.board_runtime
        )
        maintenance_runtime = MaintenanceFirmwareRuntime.from_board_runtime(
            args.board_runtime
        )
    elif args.reference_bootloader_elf is not None:
        from .nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime

        reference_runtime = Nrf51Sdk11BootloaderRuntime(args.reference_bootloader_elf)
        if args.maintenance_firmware_elf is not None:
            maintenance_runtime = MaintenanceFirmwareRuntime(args.maintenance_firmware_elf)

    if reference_runtime is None:
        bootloader = LegacyDfuBootloader(
            config=config,
            runtime=runtime,
        )
        peripheral = LegacyDfuBumblePeripheral(
            LegacyDfuGattBridge(bootloader),
            name=args.name,
            address=args.address,
        )
    else:
        if maintenance_runtime is None:
            from .qiling_rootcanal import Nrf51Sdk11BumblePeripheral

            peripheral = Nrf51Sdk11BumblePeripheral(
                reference_runtime,
                runtime,
                application_base=config.application_base,
                name=args.name,
                address=args.address,
            )
        else:
            from .qiling_rootcanal import LayeredNrf51BumblePeripheral

            peripheral = LayeredNrf51BumblePeripheral(
                maintenance_runtime,
                reference_runtime,
                runtime,
                application_base=config.application_base,
                name=args.name,
                address=args.address,
            )
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signum, stopped.set)

    try:
        await peripheral.start(args.hci_transport)
        phase = getattr(peripheral, "phase", "dfu")
        print(
            f"challenge target is advertising through {args.hci_transport} (phase={phase})",
            flush=True,
        )
        await stopped.wait()
    finally:
        await peripheral.stop()
        if maintenance_runtime is not None:
            maintenance_runtime.close()
        if reference_runtime is not None:
            reference_runtime.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
