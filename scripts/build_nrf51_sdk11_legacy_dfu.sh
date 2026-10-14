#!/usr/bin/env bash
# Build Nordic's SDK 11 nRF51 PCA10028/S130 legacy BLE DFU bootloader.
set -euo pipefail

readonly SDK_VERSION='11.0.0_89a8197'
readonly PROJECT_RELATIVE_PATH='examples/dfu/bootloader/pca10028/dual_bank_ble_s130/armgcc'
readonly TARGET='nrf51422_xxac'

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
default_sdk_root="${repo_root}/vendor/nRF5_SDK_${SDK_VERSION}"

if [[ -n "${NRF5_SDK_ROOT:-}" ]]; then
    sdk_root=${NRF5_SDK_ROOT}
elif [[ -d "${default_sdk_root}/components" ]]; then
    sdk_root=${default_sdk_root}
elif [[ -d "${repo_root}/vendor/components" ]]; then
    # Compatibility with the first local fetch, whose archive was unpacked
    # directly into vendor/.
    sdk_root="${repo_root}/vendor"
else
    printf 'SDK not found. Run scripts/fetch_nrf51_sdk11.sh first.\n' >&2
    exit 1
fi

project_dir="${sdk_root}/${PROJECT_RELATIVE_PATH}"
compiler=$(command -v arm-none-eabi-gcc || true)
if [[ -z "${compiler}" ]]; then
    printf 'arm-none-eabi-gcc is required (Ubuntu: gcc-arm-none-eabi libnewlib-arm-none-eabi).\n' >&2
    exit 1
fi
if [[ ! -f "${project_dir}/Makefile" ]]; then
    printf 'Legacy DFU Makefile not found: %s\n' "${project_dir}/Makefile" >&2
    exit 1
fi

gnu_install_root=$(dirname -- "$(dirname -- "${compiler}")")
artifact_dir=${NRF51_ARTIFACT_DIR:-"${repo_root}/artifacts/nrf51_sdk11_legacy_dfu"}
build_dir="${project_dir}/_build"

make -C "${project_dir}" GNU_INSTALL_ROOT="${gnu_install_root}" GNU_PREFIX=arm-none-eabi clean
make -C "${project_dir}" GNU_INSTALL_ROOT="${gnu_install_root}" GNU_PREFIX=arm-none-eabi "${TARGET}"

mkdir -p -- "${artifact_dir}"
install -m 0644 "${build_dir}/${TARGET}.out" "${artifact_dir}/${TARGET}.elf"
install -m 0644 "${build_dir}/${TARGET}.hex" "${artifact_dir}/${TARGET}.hex"
install -m 0644 "${build_dir}/${TARGET}.map" "${artifact_dir}/${TARGET}.map"

# The SDK Makefile's raw .bin includes a gap up to UICR at 0x10001014 and is
# roughly 256 MiB. Emit only the actual flash-resident sections instead.
arm-none-eabi-objcopy -O binary \
    --only-section=.text \
    --only-section=.ARM.exidx \
    --only-section=.data \
    "${build_dir}/${TARGET}.out" \
    "${artifact_dir}/${TARGET}_flash.bin"
rm -f -- "${build_dir}/${TARGET}.bin"

arm-none-eabi-size -A "${artifact_dir}/${TARGET}.elf" > "${artifact_dir}/size.txt"
{
    printf 'sdk_version=%s\n' "${SDK_VERSION}"
    printf 'sdk_root=%s\n' "${sdk_root}"
    printf 'project=%s\n' "${PROJECT_RELATIVE_PATH}"
    printf 'target=%s\n' "${TARGET}"
    printf 'compiler=%s\n' "$(arm-none-eabi-gcc --version | head -1)"
    printf 'flash_base=0x0003c000\n'
    printf 'flash_binary=%s_flash.bin\n' "${TARGET}"
} > "${artifact_dir}/BUILD_INFO"
(
    cd "${artifact_dir}"
    sha256sum "${TARGET}.elf" "${TARGET}.hex" "${TARGET}.map" "${TARGET}_flash.bin" "size.txt" "BUILD_INFO"
) > "${artifact_dir}/SHA256SUMS"

printf 'Built official nRF51 legacy BLE DFU bootloader artifacts in %s\n' "${artifact_dir}"
