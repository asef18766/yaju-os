"""One-connection-per-target TCP host for the challenge board.

The public socket is an HCI/H4 TCP socket.  On every accepted player
connection this host creates an isolated Rootcanal instance and an isolated
Qiling-backed target process, then proxies that player socket to the new
Rootcanal HCI listener.  The target process opens its own second HCI
connection to the same Rootcanal instance.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
import itertools
import logging
import os
from pathlib import Path
import signal
import socket
import sys
from typing import Sequence

from .board_runtime import BoardRuntimeArtifact


LOGGER = logging.getLogger(__name__)
_ROOTCANAL_PORT_COUNT = 4
_COPY_BUFFER_SIZE = 64 * 1024


class SessionHostError(RuntimeError):
    """A per-connection Rootcanal/Qiling target could not be started."""


@dataclass(frozen=True)
class SessionHostConfig:
    """Configuration shared by every target created by one host process."""

    listen_host: str
    listen_port: int
    secret_file: Path
    board_runtime: Path
    rootcanal_binary: Path
    max_sessions: int = 8
    startup_timeout: float = 30.0
    shutdown_timeout: float = 5.0
    instruction_budget: int = 5_000

    def validate(self) -> None:
        if not 0 <= self.listen_port <= 0xFFFF:
            raise ValueError("listen_port must fit in uint16")
        if self.max_sessions <= 0:
            raise ValueError("max_sessions must be positive")
        if self.startup_timeout <= 0:
            raise ValueError("startup_timeout must be positive")
        if self.shutdown_timeout <= 0:
            raise ValueError("shutdown_timeout must be positive")
        if self.instruction_budget <= 0:
            raise ValueError("instruction_budget must be positive")
        if not self.secret_file.is_file() or not self.secret_file.read_bytes():
            raise ValueError("secret_file must exist and contain at least one byte")
        BoardRuntimeArtifact.load(self.board_runtime)
        if not self.rootcanal_binary.is_file():
            raise ValueError(f"rootcanal_binary does not exist: {self.rootcanal_binary}")


@dataclass
class _TargetSession:
    """Child processes and transport streams belonging to one player socket."""

    identifier: int
    ports: tuple[int, int, int, int]
    rootcanal: asyncio.subprocess.Process | None = None
    target: asyncio.subprocess.Process | None = None
    target_ready: asyncio.Event = field(default_factory=asyncio.Event)
    rootcanal_log_task: asyncio.Task[None] | None = None
    target_log_task: asyncio.Task[None] | None = None
    backend_reader: asyncio.StreamReader | None = None
    backend_writer: asyncio.StreamWriter | None = None

    @property
    def hci_port(self) -> int:
        return self.ports[0]


class LegacyDfuSessionHost:
    """Expose isolated Rootcanal + board-image Qiling targets over one port.

    A TCP connection is the unit of isolation.  It owns exactly one Rootcanal
    process and one ``field_node.runner`` process.  Closing that player
    connection terminates both children, so no team can observe another
    team's virtual radio or Qiling memory.
    """

    def __init__(self, config: SessionHostConfig) -> None:
        config.validate()
        self.config = config
        self._server: asyncio.AbstractServer | None = None
        self._sessions: dict[int, _TargetSession] = {}
        self._connection_tasks: set[asyncio.Task[None]] = set()
        self._next_session_identifier = itertools.count(1)
        self._slots = asyncio.Semaphore(config.max_sessions)
        self._stopping = False

    @property
    def active_session_count(self) -> int:
        """Number of player connections currently owning target processes."""

        return len(self._sessions)

    @property
    def listen_port(self) -> int:
        """Return the actual port after binding (useful with requested port zero)."""

        server = self._server
        if server is None or not server.sockets:
            raise RuntimeError("session host is not listening")
        return int(server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        """Bind the public HCI/TCP listener without starting a target yet."""

        if self._server is not None:
            raise RuntimeError("session host is already listening")
        self._server = await asyncio.start_server(
            self._accept_connection,
            host=self.config.listen_host,
            port=self.config.listen_port,
            limit=_COPY_BUFFER_SIZE,
        )
        LOGGER.info(
            "session host listening on %s:%d (max %d sessions)",
            self.config.listen_host,
            self.listen_port,
            self.config.max_sessions,
        )

    async def serve_forever(self) -> None:
        """Serve public HCI connections until :meth:`stop` closes the server."""

        if self._server is None:
            raise RuntimeError("call start before serve_forever")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Stop accepting players and tear down every isolated target."""

        if self._stopping:
            return
        self._stopping = True
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

        tasks = tuple(self._connection_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # A cancelled handler normally removes its own session.  Keep this
        # fallback so shutdown remains correct if it was cancelled mid-startup.
        for session in tuple(self._sessions.values()):
            await self._stop_session(session)

    async def _accept_connection(
        self,
        player_reader: asyncio.StreamReader,
        player_writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connection_tasks.add(task)
        try:
            if self._stopping:
                LOGGER.warning("rejecting player: session host is stopping")
                return

            # Keep a connected player queued during another session's short
            # teardown window.  A connection is not rejected merely because
            # the previous owner has closed its socket but Rootcanal/Qiling
            # have not exited quite yet.
            await self._slots.acquire()
            try:
                await self._run_connection(player_reader, player_writer)
            finally:
                self._slots.release()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            peer = player_writer.get_extra_info("peername")
            LOGGER.warning("player session from %s failed: %s", peer, exc)
        finally:
            player_writer.close()
            with suppress(Exception):
                await player_writer.wait_closed()
            if task is not None:
                self._connection_tasks.discard(task)

    async def _run_connection(
        self,
        player_reader: asyncio.StreamReader,
        player_writer: asyncio.StreamWriter,
    ) -> None:
        session = await self._start_session()
        self._sessions[session.identifier] = session
        peer = player_writer.get_extra_info("peername")
        LOGGER.info("session %d ready for player %s", session.identifier, peer)
        try:
            assert session.backend_reader is not None
            assert session.backend_writer is not None
            await self._proxy_streams(
                player_reader,
                player_writer,
                session.backend_reader,
                session.backend_writer,
            )
        finally:
            await self._stop_session(session)
            self._sessions.pop(session.identifier, None)
            LOGGER.info("session %d stopped", session.identifier)

    async def _start_session(self) -> _TargetSession:
        session = _TargetSession(
            identifier=next(self._next_session_identifier),
            ports=_allocate_loopback_ports(_ROOTCANAL_PORT_COUNT),
        )
        try:
            session.rootcanal = await asyncio.create_subprocess_exec(
                str(self.config.rootcanal_binary),
                f"--hci_port={session.ports[0]}",
                f"--test_port={session.ports[1]}",
                f"--link_port={session.ports[2]}",
                f"--link_ble_port={session.ports[3]}",
                "--enable_log_color=false",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            session.rootcanal_log_task = asyncio.create_task(
                self._drain_process_output(session, "rootcanal", session.rootcanal.stdout)
            )

            # This connection becomes the player's actual Rootcanal controller
            # connection once the proxy starts.  It doubles as readiness
            # detection, avoiding a disposable HCI probe connection.
            session.backend_reader, session.backend_writer = await self._connect_rootcanal(session)

            target_arguments = [
                sys.executable,
                "-m",
                "field_node.runner",
                "--secret-file",
                str(self.config.secret_file),
                "--hci-transport",
                f"tcp-client:127.0.0.1:{session.hci_port}",
                "--instruction-budget",
                str(self.config.instruction_budget),
                "--board-runtime",
                str(self.config.board_runtime),
            ]
            session.target = await asyncio.create_subprocess_exec(
                *target_arguments,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
            session.target_log_task = asyncio.create_task(
                self._drain_process_output(session, "target", session.target.stdout)
            )
            await self._wait_for_target_ready(session)
            return session
        except BaseException:
            await self._stop_session(session)
            raise

    async def _connect_rootcanal(
        self,
        session: _TargetSession,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.startup_timeout
        last_error: OSError | None = None
        while loop.time() < deadline:
            if session.rootcanal is None or session.rootcanal.returncode is not None:
                raise SessionHostError("Rootcanal exited before opening its HCI port")
            try:
                return await asyncio.open_connection("127.0.0.1", session.hci_port)
            except OSError as exc:
                last_error = exc
                await asyncio.sleep(0.05)
        detail = f": {last_error}" if last_error is not None else ""
        raise SessionHostError(f"Rootcanal did not open HCI port {session.hci_port}{detail}")

    async def _wait_for_target_ready(self, session: _TargetSession) -> None:
        assert session.target is not None
        ready_wait = asyncio.create_task(session.target_ready.wait())
        exit_wait = asyncio.create_task(session.target.wait())
        try:
            done, pending = await asyncio.wait(
                (ready_wait, exit_wait),
                timeout=self.config.startup_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if ready_wait in done and session.target_ready.is_set():
                return
            if exit_wait in done:
                raise SessionHostError(
                    f"Qiling target exited during startup with status {session.target.returncode}"
                )
            raise SessionHostError("Qiling target did not begin advertising before timeout")
        finally:
            for task in (ready_wait, exit_wait):
                if not task.done():
                    task.cancel()
            await asyncio.gather(ready_wait, exit_wait, return_exceptions=True)

    async def _drain_process_output(
        self,
        session: _TargetSession,
        label: str,
        stream: asyncio.StreamReader | None,
    ) -> None:
        if stream is None:
            return
        try:
            while line := await stream.readline():
                message = line.decode("utf-8", errors="replace").rstrip()
                LOGGER.info("session %d %s: %s", session.identifier, label, message)
                if label == "target" and "challenge target is advertising through" in message:
                    session.target_ready.set()
        except asyncio.CancelledError:
            raise

    async def _proxy_streams(
        self,
        player_reader: asyncio.StreamReader,
        player_writer: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend_writer: asyncio.StreamWriter,
    ) -> None:
        player_to_rootcanal = asyncio.create_task(
            _copy_stream(player_reader, backend_writer)
        )
        rootcanal_to_player = asyncio.create_task(
            _copy_stream(backend_reader, player_writer)
        )
        done, pending = await asyncio.wait(
            (player_to_rootcanal, rootcanal_to_player),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)

    async def _stop_session(self, session: _TargetSession) -> None:
        backend_writer = session.backend_writer
        session.backend_reader = None
        session.backend_writer = None
        if backend_writer is not None:
            backend_writer.close()
            with suppress(Exception):
                await backend_writer.wait_closed()

        await self._stop_process(session.target)
        await self._stop_process(session.rootcanal)
        for task in (session.target_log_task, session.rootcanal_log_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(task for task in (session.target_log_task, session.rootcanal_log_task) if task is not None),
            return_exceptions=True,
        )

    async def _stop_process(self, process: asyncio.subprocess.Process | None) -> None:
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=self.config.shutdown_timeout)
        except TimeoutError:
            process.kill()
            await process.wait()


async def _copy_stream(
    source: asyncio.StreamReader,
    destination: asyncio.StreamWriter,
) -> None:
    while data := await source.read(_COPY_BUFFER_SIZE):
        destination.write(data)
        await destination.drain()


def _allocate_loopback_ports(count: int) -> tuple[int, ...]:
    """Reserve distinct ephemeral IPv4 port numbers for one Rootcanal process.

    Rootcanal needs four listeners.  The reservations are released immediately
    before the child starts, so the usual localhost ephemeral-port race window
    is tiny and contained to the single container namespace.
    """

    if count <= 0:
        raise ValueError("count must be positive")
    reservations: list[socket.socket] = []
    try:
        for _ in range(count):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
        return tuple(int(reservation.getsockname()[1]) for reservation in reservations)
    finally:
        for reservation in reservations:
            reservation.close()


def _default_rootcanal_binary() -> Path:
    try:
        from rootcanal.binaries import get_package_binary_resource_path
    except ModuleNotFoundError as exc:
        raise SessionHostError("the 'transport' extra is required for the session host") from exc
    return Path(get_package_binary_resource_path("rootcanal")).resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create one isolated Rootcanal + Qiling board target per incoming HCI/TCP connection."
        )
    )
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=6402)
    parser.add_argument(
        "--board-runtime",
        type=Path,
        help="combined board_flash.bin + runtime_symbols.json directory",
    )
    parser.add_argument("--rootcanal-binary", type=Path)
    parser.add_argument("--max-sessions", type=int, default=8)
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    parser.add_argument("--shutdown-timeout", type=float, default=5.0)
    parser.add_argument("--instruction-budget", type=int, default=5_000)
    return parser


async def serve(args: argparse.Namespace) -> None:
    rootcanal_binary = (
        args.rootcanal_binary.resolve()
        if args.rootcanal_binary is not None
        else _default_rootcanal_binary()
    )
    board_runtime = (
        args.board_runtime.resolve()
        if args.board_runtime is not None
        else BoardRuntimeArtifact.repository_path()
    )
    config = SessionHostConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        secret_file=args.secret_file.resolve(),
        board_runtime=board_runtime,
        rootcanal_binary=rootcanal_binary,
        max_sessions=args.max_sessions,
        startup_timeout=args.startup_timeout,
        shutdown_timeout=args.shutdown_timeout,
        instruction_budget=args.instruction_budget,
    )
    host = LegacyDfuSessionHost(config)
    await host.start()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(signum, stopped.set)
    try:
        await stopped.wait()
    finally:
        await host.stop()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
