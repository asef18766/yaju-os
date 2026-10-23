# Build the exact Nordic SDK 11 bootloader once, outside the runtime image.
FROM python:3.12-slim-bookworm AS bootloader-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc-arm-none-eabi \
        libnewlib-arm-none-eabi \
        make \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY scripts/fetch_nrf51_sdk11.sh ./scripts/fetch_nrf51_sdk11.sh
COPY scripts/build_nrf51_sdk11_legacy_dfu.sh ./scripts/build_nrf51_sdk11_legacy_dfu.sh
COPY scripts/build_maintenance_application.sh ./scripts/build_maintenance_application.sh
COPY scripts/build_board_runtime.py ./scripts/build_board_runtime.py
COPY firmware ./firmware
RUN bash ./scripts/fetch_nrf51_sdk11.sh \
    && bash ./scripts/build_nrf51_sdk11_legacy_dfu.sh \
    && bash ./scripts/build_maintenance_application.sh \
    && python3 ./scripts/build_board_runtime.py \
        --maintenance-bin ./artifacts/maintenance_application/maintenance_application.bin \
        --maintenance-elf ./artifacts/maintenance_application/maintenance_application.emulator.elf \
        --bootloader-bin ./artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac_flash.bin \
        --bootloader-elf ./artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.emulator.elf \
        --output-dir ./artifacts/board_runtime \
    && rm -rf vendor


# Rootcanal 1.13's bundled Linux binary requires GLIBC_2.39 and
# GLIBCXX_3.4.32, both provided by Debian Trixie rather than Bookworm.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HITCON_BOARD_RUNTIME=/app/artifacts/board_runtime \
    HITCON_REFERENCE_BOOTLOADER_ELF=/app/artifacts/board_runtime/board_flash.bin \
    HITCON_MAINTENANCE_FIRMWARE_ELF=/app/artifacts/board_runtime/board_flash.bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install '.[full]'
COPY --from=bootloader-build /build/artifacts/board_runtime ./artifacts/board_runtime

RUN useradd --create-home --uid 10001 ctf \
    && chown -R ctf:ctf /app
USER ctf

EXPOSE 6402/tcp

ENTRYPOINT ["field-node-host"]
CMD ["--secret-file", "/run/secrets/flag", "--listen-host", "0.0.0.0", "--listen-port", "6402", "--board-runtime", "/app/artifacts/board_runtime"]
