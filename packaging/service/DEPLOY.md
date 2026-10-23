# HITCON Field Node service deployment

This directory is a self-contained Docker Compose build context. It does not
contain a real challenge flag.

Requirements:

- Docker Engine with the Compose v2 plugin
- outbound HTTPS access during the initial image build

Create the secret file and start the service:

```bash
cp flag.example flag.txt
# Replace the placeholder in flag.txt, then restrict its permissions.
chmod 600 flag.txt
FLAG_FILE=./flag.txt docker compose up -d --build
```

The public HCI/H4 TCP endpoint listens on port `6402`. Override the host port
without editing the bundle:

```bash
HCI_PORT=7402 FLAG_FILE=./flag.txt docker compose up -d --build
```

Operational checks:

```bash
docker compose ps
docker compose logs --tail=100 host
sha256sum --check SHA256SUMS
```

Stop and remove the deployment with `docker compose down`. Never replace
`flag.example` with a real flag or add `flag.txt` to a redistributed ZIP.
