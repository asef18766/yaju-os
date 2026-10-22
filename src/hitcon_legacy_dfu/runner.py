"""Command-line runner for one legacy-DFU challenge target instance."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from pathlib import Path
import signal
from typing import Sequence

from .board_runtime import BoardRuntimeArtifact
from .hardware import NRF51_SRAM_BASE, NRF51_SRAM_SIZE
from .maintenance_runtime import MaintenanceFirmwareRuntime
from .nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime
from .qiling_rootcanal import LayeredNrf51BumblePeripheral
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
        required=True,
        help=(
            "directory containing one board_flash.bin and runtime_symbols.json; "
            "selects both the maintenance and bootloader reset phases"
        ),
    )
    return parser


async def serve(args: argparse.Namespace) -> None:
    if args.instruction_budget <= 0:
        raise ValueError("--instruction-budget must be positive")
    secret = args.secret_file.read_bytes()
    if not secret:
        raise ValueError("--secret-file must not be empty")

    board = BoardRuntimeArtifact.load(args.board_runtime)
    runtime = QilingRuntime(
        secret,
        flash_size=len(board.flash),
        sram_base=NRF51_SRAM_BASE,
        sram_size=NRF51_SRAM_SIZE,
        instruction_budget=args.instruction_budget,
    )
    reference_runtime = Nrf51Sdk11BootloaderRuntime.from_board_runtime(args.board_runtime)
    maintenance_runtime = MaintenanceFirmwareRuntime.from_board_runtime(args.board_runtime)
    peripheral = LayeredNrf51BumblePeripheral(
        maintenance_runtime,
        reference_runtime,
        runtime,
        application_base=board.application_base,
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
        maintenance_runtime.close()
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
