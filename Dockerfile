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
COPY scripts ./scripts
COPY firmware ./firmware
RUN ./scripts/fetch_nrf51_sdk11.sh \
    && ./scripts/build_nrf51_sdk11_legacy_dfu.sh \
    && bash ./scripts/build_maintenance_application.sh \
    && rm -rf vendor


# Rootcanal 1.13's bundled Linux binary requires GLIBC_2.39 and
# GLIBCXX_3.4.32, both provided by Debian Trixie rather than Bookworm.
FROM python:3.12-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HITCON_REFERENCE_BOOTLOADER_ELF=/app/artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.elf \
    HITCON_MAINTENANCE_FIRMWARE_ELF=/app/artifacts/maintenance_application/maintenance_application.elf

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install '.[full]'
COPY --from=bootloader-build /build/artifacts/nrf51_sdk11_legacy_dfu ./artifacts/nrf51_sdk11_legacy_dfu
COPY --from=bootloader-build /build/artifacts/maintenance_application ./artifacts/maintenance_application
COPY --from=bootloader-build /build/artifacts/maintenance_application/maintenance_application.bin ./handout/maintenance_application.bin

RUN useradd --create-home --uid 10001 ctf \
    && chown -R ctf:ctf /app
USER ctf

EXPOSE 6402/tcp

ENTRYPOINT ["hitcon-legacy-dfu-host"]
CMD ["--secret-file", "/run/secrets/flag", "--listen-host", "0.0.0.0", "--listen-port", "6402", "--reference-bootloader-elf", "/app/artifacts/nrf51_sdk11_legacy_dfu/nrf51422_xxac.elf", "--maintenance-firmware-elf", "/app/artifacts/maintenance_application/maintenance_application.elf"]
