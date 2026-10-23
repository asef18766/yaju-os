from __future__ import annotations

import asyncio
from contextlib import suppress
import importlib.util
import sys
import tempfile
import time
import unittest
from pathlib import Path

from field_node.board_runtime import BoardRuntimeArtifact
from field_node.inmu_king_art import INMU_KING_DANCE_FRAMES, INMU_KING_DANCE_LABELS
from field_node.session_host import (
    LegacyDfuSessionHost,
    SessionHostConfig,
    _default_rootcanal_binary,
)


BOARD_RUNTIME = BoardRuntimeArtifact.repository_path()
VALID_MAINTENANCE_REQUEST = bytes.fromhex("11451419198100")


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
    and (BOARD_RUNTIME / "board_flash.bin").is_file()
    and (BOARD_RUNTIME / "runtime_symbols.json").is_file(),
    "Qiling, Rootcanal, or a built nRF51 challenge firmware artifact is unavailable",
)
class SessionHostIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_preview_script_reads_animation_through_the_public_proxy(self) -> None:
        with tempfile.NamedTemporaryFile() as secret_file:
            secret_file.write(b"CTF{animation_preview_test}")
            secret_file.flush()
            host = LegacyDfuSessionHost(
                SessionHostConfig(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    secret_file=Path(secret_file.name),
                    rootcanal_binary=_default_rootcanal_binary(),
                    max_sessions=1,
                    startup_timeout=15.0,
                    board_runtime=BOARD_RUNTIME,
                )
            )
            await host.start()
            preview = None
            try:
                script = Path(__file__).resolve().parents[1] / "scripts/preview_inmu_king_art.py"
                preview = await asyncio.create_subprocess_exec(
                    sys.executable,
                    str(script),
                    "--hci-transport", f"tcp-client:127.0.0.1:{host.listen_port}",
                    "--loops", "1",
                    "--fps", "1000",
                    "--no-clear",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await _wait_until(lambda: host.active_session_count == 1)
                output, errors = await asyncio.wait_for(preview.communicate(), timeout=30)
                self.assertEqual(preview.returncode, 0, errors.decode())
                expected = "".join(
                    f"frame {index}/{len(INMU_KING_DANCE_FRAMES)} | {label}\n"
                    f"{frame.decode('ascii')}\n\n"
                    for index, (frame, label) in enumerate(
                        zip(INMU_KING_DANCE_FRAMES, INMU_KING_DANCE_LABELS), start=1
                    )
                )
                self.assertEqual(output.decode(), expected)
                await _wait_until(lambda: host.active_session_count == 0)
            finally:
                if preview is not None and preview.returncode is None:
                    preview.kill()
                    await preview.communicate()
                await host.stop()

    async def test_each_player_tcp_connection_gets_and_releases_a_board_target(self) -> None:
        """The public TCP socket owns one Rootcanal/Qiling pair until EOF."""

        with tempfile.NamedTemporaryFile() as secret_file:
            secret_file.write(b"CTF{session_host_test_flag}")
            secret_file.flush()
            host = LegacyDfuSessionHost(
                SessionHostConfig(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    secret_file=Path(secret_file.name),
                    rootcanal_binary=_default_rootcanal_binary(),
                    max_sessions=2,
                    startup_timeout=15.0,
                    board_runtime=BOARD_RUNTIME,
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

        from field_node.gatt_ids import SERVICE_UUID

        with tempfile.NamedTemporaryFile() as secret_file:
            secret_file.write(b"CTF{session_host_gatt_test_flag}")
            secret_file.flush()
            host = LegacyDfuSessionHost(
                SessionHostConfig(
                    listen_host="127.0.0.1",
                    listen_port=0,
                    secret_file=Path(secret_file.name),
                    rootcanal_binary=_default_rootcanal_binary(),
                    max_sessions=1,
                    startup_timeout=15.0,
                    board_runtime=BOARD_RUNTIME,
                )
            )
            await host.start()
            transport = None
            client = None
            initial_connection = None
            dfu_connection = None
            try:
                transport = await open_transport(f"tcp-client:127.0.0.1:{host.listen_port}")
                client = Device.with_hci(
                    "session-host-client",
                    Address("F0:F1:F2:F3:F4:F5"),
                    transport.source,
                    transport.sink,
                )
                await client.power_on()
                initial_connection = await client.connect(
                    Address("F6:F7:F8:F9:FA:FB"),
                    timeout=15,
                )
                disconnected = asyncio.Event()
                initial_connection.on(
                    initial_connection.EVENT_DISCONNECTION,
                    lambda *_args: disconnected.set(),
                )
                peer = Peer(initial_connection)
                from field_node.gatt_ids import (
                    MAINTENANCE_CONTROL_UUID,
                    MAINTENANCE_SERVICE_UUID,
                )

                self.assertEqual(
                    len(await peer.discover_service(UUID(SERVICE_UUID))),
                    0,
                )
                maintenance_services = await peer.discover_service(UUID(MAINTENANCE_SERVICE_UUID))
                self.assertEqual(len(maintenance_services), 1)
                maintenance_service = maintenance_services[0]
                await peer.discover_characteristics(service=maintenance_service)
                control = peer.get_characteristics_by_uuid(
                    UUID(MAINTENANCE_CONTROL_UUID), maintenance_service
                )[0]
                await peer.write_value(control, VALID_MAINTENANCE_REQUEST, with_response=True)
                await asyncio.wait_for(disconnected.wait(), timeout=10)

                deadline = time.monotonic() + 15.0
                last_error: Exception | None = None
                while time.monotonic() < deadline:
                    try:
                        dfu_connection = await client.connect(
                            Address("F6:F7:F8:F9:FA:FB"), timeout=0.5
                        )
                        break
                    except Exception as exc:
                        last_error = exc
                        await asyncio.sleep(0.05)
                if dfu_connection is None:
                    if last_error is not None:
                        raise last_error
                    raise TimeoutError("legacy DFU target did not advertise after maintenance reset")
                dfu_peer = Peer(dfu_connection)
                services = await dfu_peer.discover_service(UUID(SERVICE_UUID))
                self.assertEqual(len(services), 1)
            finally:
                if dfu_connection is not None:
                    with suppress(Exception):
                        await dfu_connection.disconnect()
                if initial_connection is not None:
                    with suppress(Exception):
                        await initial_connection.disconnect()
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
