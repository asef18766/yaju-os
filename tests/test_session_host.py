from __future__ import annotations

import asyncio
from contextlib import suppress
import importlib.util
import tempfile
import time
import unittest
from pathlib import Path

from hitcon_legacy_dfu.nrf51_sdk11_runtime import Nrf51Sdk11BootloaderRuntime
from hitcon_legacy_dfu.session_host import (
    LegacyDfuSessionHost,
    SessionHostConfig,
    _default_rootcanal_binary,
)


REFERENCE_ELF = Nrf51Sdk11BootloaderRuntime.repository_reference_elf()


async def _wait_until(predicate, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError("condition did not become true before timeout")


@unittest.skipUnless(
    importlib.util.find_spec("qiling") is not None
    and importlib.util.find_spec("bumble") is not None
    and importlib.util.find_spec("rootcanal") is not None
    and REFERENCE_ELF.is_file(),
    "Qiling, Rootcanal, or the built nRF51 SDK 11 reference ELF is unavailable",
)
class SessionHostIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_each_player_tcp_connection_gets_and_releases_a_direct_elf_target(self) -> None:
        """The public TCP socket owns one Rootcanal/Qiling pair until EOF."""

        with tempfile.NamedTemporaryFile() as secret_file:
            secret_file.write(b"CTF{session_host_test_flag}")
            secret_file.flush()
            host = LegacyDfuSessionHost(
                SessionHostConfig(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    secret_file=Path(secret_file.name),
                    reference_bootloader_elf=REFERENCE_ELF,
                    rootcanal_binary=_default_rootcanal_binary(),
                    max_sessions=2,
                    startup_timeout=15.0,
                )
            )
            await host.start()
            try:
                players = await asyncio.gather(
                    *(asyncio.open_connection("127.0.0.1", host.listen_port) for _ in range(2))
                )
                try:
                    await _wait_until(lambda: host.active_session_count == 2)
                finally:
                    for reader, writer in players:
                        del reader
                        writer.close()
                    await asyncio.gather(*(writer.wait_closed() for _, writer in players))
                await _wait_until(lambda: host.active_session_count == 0)

                # The released slots can immediately own a fresh Qiling/
                # Rootcanal pair too.
                reader, writer = await asyncio.open_connection("127.0.0.1", host.listen_port)
                del reader
                try:
                    await _wait_until(lambda: host.active_session_count == 1)
                finally:
                    writer.close()
                    await writer.wait_closed()
                await _wait_until(lambda: host.active_session_count == 0)
            finally:
                await host.stop()

    async def test_player_reaches_the_legacy_dfu_service_through_the_public_proxy(self) -> None:
        """A real player HCI client traverses the per-connection proxy."""

        from bumble.core import UUID
        from bumble.device import Device, Peer
        from bumble.hci import Address
        from bumble.transport import open_transport

        from hitcon_legacy_dfu.protocol import SERVICE_UUID

        with tempfile.NamedTemporaryFile() as secret_file:
            secret_file.write(b"CTF{session_host_gatt_test_flag}")
            secret_file.flush()
            host = LegacyDfuSessionHost(
                SessionHostConfig(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    secret_file=Path(secret_file.name),
                    reference_bootloader_elf=REFERENCE_ELF,
                    rootcanal_binary=_default_rootcanal_binary(),
                    max_sessions=1,
                    startup_timeout=15.0,
                )
            )
            await host.start()
            transport = None
            client = None
            connection = None
            try:
                transport = await open_transport(f"tcp-client:127.0.0.1:{host.listen_port}")
                client = Device.with_hci(
                    "session-host-client",
                    Address("F0:F1:F2:F3:F4:F5"),
                    transport.source,
                    transport.sink,
                )
                await client.power_on()
                connection = await client.connect(
                    Address("F6:F7:F8:F9:FA:FB"),
                    timeout=15,
                )
                peer = Peer(connection)
                services = await peer.discover_service(UUID(SERVICE_UUID))
                self.assertEqual(len(services), 1)
            finally:
                if connection is not None:
                    with suppress(Exception):
                        await connection.disconnect()
                if client is not None:
                    with suppress(Exception):
                        await client.power_off()
                if transport is not None:
                    with suppress(Exception):
                        await transport.close()
                await _wait_until(lambda: host.active_session_count == 0)
                await host.stop()


if __name__ == "__main__":
    unittest.main()
