#!/usr/bin/env python3
"""Render the INMU KING ASCII chorus in a terminal.

Examples:
    python3 scripts/preview_inmu_king_art.py
    python3 scripts/preview_inmu_king_art.py --fps 2 --loops 0
    python3 scripts/preview_inmu_king_art.py --step
    python3 scripts/preview_inmu_king_art.py --hci-transport tcp-client:127.0.0.1:6402
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import aclosing, suppress
import math
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from yaju_os.inmu_king_art import (
    INMU_KING_DANCE_FRAMES,
    INMU_KING_DANCE_LABELS,
    PREVIEW_FPS,
)
from yaju_os.gatt_ids import INMU_KING_FRAME_UUID, INMU_KING_SERVICE_UUID


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preview the ASCII chorus with pose labels and held keyframes."
    )
    parser.add_argument(
        "--fps",
        type=positive_float,
        default=PREVIEW_FPS,
        help="frames per second in automatic mode (default: %(default)s)",
    )
    parser.add_argument(
        "--loops",
        type=nonnegative_int,
        default=3,
        help="number of animation loops; 0 keeps playing until Ctrl-C (default: %(default)s)",
    )
    parser.add_argument(
        "--step",
        action="store_true",
        help="wait for Enter between frames; enter q to stop",
    )
    parser.add_argument(
        "--no-clear",
        action="store_true",
        help="print every frame below the previous one instead of animating in place",
    )
    parser.add_argument(
        "--hci-transport",
        help="read each frame over GATT instead of locally, e.g. tcp-client:127.0.0.1:6402",
    )
    parser.add_argument(
        "--address",
        default="F6:F7:F8:F9:FA:FB",
        help="target BLE random address for GATT preview (default: %(default)s)",
    )
    return parser.parse_args()


def frame_sequence(loops: int) -> Iterator[tuple[int, bytes]]:
    """Yield 1-based frame numbers, repeating forever when loops is zero."""

    completed_loops = 0
    while loops == 0 or completed_loops < loops:
        for frame_number, frame in enumerate(INMU_KING_DANCE_FRAMES, start=1):
            yield frame_number, frame
        completed_loops += 1


def render(frame_number: int, frame: bytes, *, clear: bool) -> None:
    text = frame.decode("ascii")
    label = INMU_KING_DANCE_LABELS[frame_number - 1]
    heading = f"frame {frame_number}/{len(INMU_KING_DANCE_FRAMES)} | {label}"
    # Clear only the changing heading; the fixed-size canvas overwrites the
    # previous pose without blanking the entire screen between frames.
    prefix = "\x1b[H\x1b[2K" if clear else ""
    suffix = "\n\x1b[J" if clear else "\n\n"
    sys.stdout.write(f"{prefix}{heading}\n{text}{suffix}")
    sys.stdout.flush()


async def playback_frames(args: argparse.Namespace) -> AsyncIterator[tuple[int, bytes]]:
    if not args.hci_transport:
        for item in frame_sequence(args.loops):
            yield item
        return

    try:
        from bumble.core import UUID
        from bumble.device import Device, Peer
        from bumble.hci import Address
        from bumble.transport import open_transport
    except ModuleNotFoundError as exc:
        raise RuntimeError("GATT preview needs: python3 -m pip install -e '.[transport]'") from exc

    async with await open_transport(args.hci_transport) as transport:
        device = Device.with_hci(
            "inmu-art-viewer", Address("F0:F1:F2:F3:F4:F5"), transport.source, transport.sink
        )
        connection = None
        try:
            await device.power_on()
            connection = await device.connect(args.address, timeout=15)
            peer = Peer(connection)
            services = await peer.discover_service(UUID(INMU_KING_SERVICE_UUID))
            if len(services) != 1:
                raise RuntimeError(
                    "animation service not found; target must be in normal application mode"
                )
            await peer.discover_characteristics(service=services[0])
            frames = peer.get_characteristics_by_uuid(UUID(INMU_KING_FRAME_UUID), services[0])
            if len(frames) != 1:
                raise RuntimeError("animation frame characteristic not found")
            # Keep MTU 23 to exercise Read Blob. read_value assembles one full
            # frame; it does not return the client's previously cached value.
            for frame_number, _local_frame in frame_sequence(args.loops):
                yield frame_number, await peer.read_value(frames[0])
        finally:
            if connection is not None:
                with suppress(Exception):
                    await connection.disconnect()
            with suppress(Exception):
                await device.power_off()


async def play(args: argparse.Namespace, *, clear: bool) -> None:
    async with aclosing(playback_frames(args)) as frames:
        async for frame_number, frame in frames:
            render(frame_number, frame, clear=clear)
            if args.step:
                try:
                    command = input("Enter: next frame, q: quit > ").strip().lower()
                except EOFError:
                    return
                if command == "q":
                    return
            else:
                await asyncio.sleep(1 / args.fps)


def main() -> int:
    args = parse_args()
    clear = not args.no_clear and sys.stdout.isatty()
    hide_cursor = clear and not args.step
    if clear:
        sys.stdout.write("\x1b[2J\x1b[H")
    if hide_cursor:
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()

    try:
        asyncio.run(play(args, clear=clear))
    except KeyboardInterrupt:
        return 130
    except (RuntimeError, OSError) as exc:
        print(f"Preview failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if hide_cursor:
            sys.stdout.write("\x1b[?25h\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
