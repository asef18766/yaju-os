# HITCON Field Node local lab

This is the player attachment for the HITCON Field Node challenge.  It
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
gets a new isolated Rootcanal/Qiling target, and closing that connection
destroys it, so keep one HCI connection open for a complete run.  Within one
connection you may disconnect and reconnect at the BLE layer as often as you
like.  There is no UART or host-provided BLE console: every client operation
goes through this Rootcanal HCI connection, and anything your own firmware
wants to report back it has to publish itself.

Run the harmless GATT probe shipped with the attachment:

```sh
docker compose run --rm --no-deps tools probe.py
```

It connects through the same public HCI endpoint and reads one ASCII-animation
frame.  Use `probe.py` as a transport/connection example, or drop your own
script next to it and run it in the dependency-complete tools container:

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

- `artifacts/board_runtime/board_flash.bin` is the only firmware blob: one
  complete 256 KiB nRF51 flash image containing both the normal application
  and the bootloader. Load it at image base `0`; the application starts at
  `0x0001b000` and the bootloader starts at `0x0003c000`. You may carve those
  regions yourself if your reverse-engineering tool requires separate images.
- `artifacts/board_runtime/runtime_symbols.json` contains only the narrow
  entry-point/SVC ABI metadata Qiling needs to execute that raw image.
- `src/` is the minimal production board-image emulator/transport harness;
  organizer-side protocol models, clients, payload helpers, and offline
  animation data are intentionally excluded.
- `probe.py` is the example client; the attachment directory is mounted
  read-only into the tools container, so your own scripts can live beside it.
- `local_flag.txt` is the non-secret flag exposed by the local GPIO model.

The attachment intentionally excludes the challenge firmware source, organizer
tests, solution tooling, and any production flag.
