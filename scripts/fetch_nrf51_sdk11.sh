#!/usr/bin/env bash
# Fetch the exact Nordic nRF5 SDK revision used by the legacy-DFU build.
set -euo pipefail

readonly SDK_VERSION='11.0.0_89a8197'
readonly SDK_ARCHIVE="nRF5_SDK_${SDK_VERSION}.zip"
readonly SDK_URL="https://developer.nordicsemi.com/nRF5_SDK/nRF5_SDK_v11.x.x/${SDK_ARCHIVE}"
readonly SDK_SHA256='06ffde172781f8a9082ba0374aa98e5860d655ac70d9a1d9c91596d51bb328a6'

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)
sdk_root=${NRF5_SDK_ROOT:-"${repo_root}/vendor/nRF5_SDK_${SDK_VERSION}"}

if [[ -e "${sdk_root}" ]] && [[ -n "$(find "${sdk_root}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    printf 'Refusing to overwrite non-empty SDK directory: %s\n' "${sdk_root}" >&2
    exit 1
fi

archive=$(mktemp --suffix=.zip nrf5-sdk-XXXXXX)
trap 'rm -f -- "${archive}"' EXIT
mkdir -p -- "${sdk_root}"

curl -fL --retry 3 --connect-timeout 20 --output "${archive}" "${SDK_URL}"
actual_sha256=$(sha256sum "${archive}" | awk '{print $1}')
if [[ "${actual_sha256}" != "${SDK_SHA256}" ]]; then
    printf 'SDK checksum mismatch: expected %s, got %s\n' "${SDK_SHA256}" "${actual_sha256}" >&2
    exit 1
fi

unzip -q "${archive}" -d "${sdk_root}"
printf 'Fetched Nordic nRF5 SDK %s to %s\n' "${SDK_VERSION}" "${sdk_root}"
