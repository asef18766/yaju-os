# HITCON Field Node local lab

This is the player attachment for the Nordic legacy DFU challenge.  It
contains both the firmware to reverse and a local Rootcanal + Qiling target,
so you can run your own BLE exploit end to end before connecting to the
competition service.

## Requirements

- Docker Engine
- Docker Compose v2 (`docker compose`)
- an `amd64` Docker runtime, or Docker's `linux/amd64` emulation on ARM hosts
- outbound HTTPS access for the first image build

No physical Bluetooth controller is required.  Port `6402/tcp` carries HCI/H4
between your client and the virtual controller; it is not a GATT-over-TCP API.

## Start the local target

Verify the attachment, build the image, and start the session host:

```sh
sha256sum --check SHA256SUMS
docker compose up -d --build host
docker compose logs --tail=50 host
```

The supplied flag is deliberately public and exists only to tell you whether
your exploit worked:

```text
CTF{local_emulator_test_flag}
```

The target address is `F6:F7:F8:F9:FA:FB`.  Every HCI connection to the host
gets a new isolated Rootcanal/Qiling target.  Keep one HCI connection open for
the complete normal-application -> maintenance reset -> DFU -> uploaded
application -> payload-defined GATT flow; closing it destroys that local
target. There is no UART or host-provided BLE console: your uploaded firmware
must register any result characteristic itself, and every client operation
goes through this Rootcanal HCI connection.

Run the harmless GATT probe included in `workspace/`:

```sh
docker compose run --rm --no-deps tools probe.py
```

It connects through the same public HCI endpoint and reads one ASCII-animation
frame.  Use `workspace/probe.py` as a transport/connection example, or place
your own script in `workspace/` and run it in the dependency-complete tools
container:

```sh
docker compose run --rm --no-deps tools exploit.py
```

Inside that container the transport string is `tcp-client:host:6402`.  A
client running directly on your machine should instead use
`tcp-client:127.0.0.1:6402`.  Override the published host port if needed:

```sh
export HCI_PORT=7402
docker compose up -d host
```

Stop the lab with:

```sh
docker compose down
```

## Files

- `maintenance_application.bin` is the raw Cortex-M0 application firmware,
  linked at `0x0001b000`, that is intended for reverse engineering.
- `artifacts/board_runtime/board_flash.bin` is one complete 256 KiB nRF51
  flash image containing both the normal application and legacy bootloader.
- `artifacts/board_runtime/runtime_symbols.json` contains only the narrow
  entry-point/SVC ABI metadata Qiling needs to execute that raw image.
- `src/` is the player-safe emulator/transport harness.
- `workspace/` is bind-mounted into the tools container for your scripts.
- `local_flag.txt` is the non-secret flag exposed by the local GPIO model.

The attachment intentionally excludes challenge firmware source, organizer
tests, known maintenance commands, solution payload generators, and any
production flag.
