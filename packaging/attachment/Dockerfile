FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HITCON_BOARD_RUNTIME=/opt/hitcon/artifacts/board_runtime \
    HITCON_REFERENCE_BOOTLOADER_ELF=/opt/hitcon/artifacts/board_runtime/board_flash.bin \
    HITCON_MAINTENANCE_FIRMWARE_ELF=/opt/hitcon/artifacts/board_runtime/board_flash.bin

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hitcon
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install '.[full]'

COPY artifacts ./artifacts

RUN useradd --create-home --uid 10001 player \
    && chown -R player:player /opt/hitcon
USER player

EXPOSE 6402/tcp

ENTRYPOINT ["yaju-os-host"]
CMD ["--secret-file", "/run/secrets/local_flag", "--listen-host", "0.0.0.0", "--listen-port", "6402", "--max-sessions", "2", "--board-runtime", "/opt/hitcon/artifacts/board_runtime"]
