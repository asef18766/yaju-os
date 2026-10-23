#!/usr/bin/env python3
"""Benign player-side smoke test for the local HCI/GATT target."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress

from bumble.core import UUID
from bumble.device import Device, Peer
from bumble.hci import Address
from bumble.transport import open_transport

from field_node.gatt_ids import INMU_KING_FRAME_UUID, INMU_KING_SERVICE_UUID


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read one harmless frame from the local target")
    parser.add_argument("--transport", default="tcp-client:host:6402")
    parser.add_argument("--address", default="F6:F7:F8:F9:FA:FB")
    return parser.parse_args()


async def probe(args: argparse.Namespace) -> None:
    async with await open_transport(args.transport) as transport:
        device = Device.with_hci(
            "player-probe",
            Address("F0:F1:F2:F3:F4:F5"),
            transport.source,
            transport.sink,
        )
        connection = None
        try:
            await device.power_on()
            connection = await device.connect(Address(args.address), timeout=15)
            peer = Peer(connection)
            services = await peer.discover_service(UUID(INMU_KING_SERVICE_UUID))
            if len(services) != 1:
                raise RuntimeError("animation service was not found")
            await peer.discover_characteristics(service=services[0])
            frames = peer.get_characteristics_by_uuid(
                UUID(INMU_KING_FRAME_UUID), services[0]
            )
            if len(frames) != 1:
                raise RuntimeError("animation frame characteristic was not found")
            frame = await peer.read_value(frames[0])
            print(frame.decode("ascii"))
            print(f"\nlocal target OK: read {len(frame)} bytes over GATT")
        finally:
            if connection is not None:
                with suppress(Exception):
                    await connection.disconnect()
            with suppress(Exception):
                await device.power_off()


def main() -> int:
    try:
        asyncio.run(probe(parse_args()))
    except (OSError, RuntimeError) as exc:
        print(f"probe failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
