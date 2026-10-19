#!/usr/bin/env bash
# Build the normal application phase and the binary handed to CTF players.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
compiler=$(command -v arm-none-eabi-gcc || true)
default_sdk_root="${repo_root}/vendor/nRF5_SDK_11.0.0_89a8197"

if [[ -n "${NRF5_SDK_ROOT:-}" ]]; then
    sdk_root=${NRF5_SDK_ROOT}
elif [[ -d "${default_sdk_root}/components/softdevice/s130/headers" ]]; then
    sdk_root=${default_sdk_root}
elif [[ -d "${repo_root}/vendor/components/softdevice/s130/headers" ]]; then
    sdk_root="${repo_root}/vendor"
else
    printf 'SDK not found. Run scripts/fetch_nrf51_sdk11.sh first.\n' >&2
    exit 1
fi

if [[ -z "${compiler}" ]]; then
    printf 'arm-none-eabi-gcc is required (Ubuntu: gcc-arm-none-eabi libnewlib-arm-none-eabi).\n' >&2
    exit 1
fi

artifact_dir=${MAINTENANCE_ARTIFACT_DIR:-"${repo_root}/artifacts/maintenance_application"}
source_file="${repo_root}/firmware/maintenance_application.c"
linker_script="${repo_root}/firmware/maintenance_application.ld"
elf="${artifact_dir}/maintenance_application.elf"
bin="${artifact_dir}/maintenance_application.bin"
hex="${artifact_dir}/maintenance_application.hex"

mkdir -p -- "${artifact_dir}"

"${compiler}" \
    -mcpu=cortex-m0 \
    -mthumb \
    -Os \
    -ffreestanding \
    -fdata-sections \
    -ffunction-sections \
    -fno-builtin \
    -fno-stack-protector \
    -nostdlib \
    -I"${sdk_root}/components/softdevice/s130/headers" \
    -Wl,--gc-sections \
    -Wl,-T,"${linker_script}" \
    -Wl,-Map,"${artifact_dir}/maintenance_application.map" \
    -Wl,-e,Reset_Handler \
    -o "${elf}" \
    "${source_file}"

arm-none-eabi-objcopy -O binary "${elf}" "${bin}"
arm-none-eabi-objcopy -O ihex "${elf}" "${hex}"
arm-none-eabi-size -A "${elf}" > "${artifact_dir}/size.txt"
{
    printf 'target=nrf51422_xxac\n'
    printf 'application_base=0x0001b000\n'
    printf 'player_handout=maintenance_application.bin\n'
    printf 'compiler=%s\n' "$(arm-none-eabi-gcc --version | head -1)"
} > "${artifact_dir}/BUILD_INFO"
(
    cd "${artifact_dir}"
    sha256sum maintenance_application.elf maintenance_application.bin maintenance_application.hex \
        maintenance_application.map size.txt BUILD_INFO
) > "${artifact_dir}/SHA256SUMS"

printf 'Built maintenance application artifacts in %s\n' "${artifact_dir}"
