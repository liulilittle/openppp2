#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVISION="92502d92d136ea870a857d1578f13c33191b381f"
ARCHIVE_SHA256="18042dd1ee9263eb40101e38aa7c72f46fb1502331d08619ab69092fb024f1b5"
SOURCE_URL="https://codeload.github.com/liulilittle/corocc/tar.gz/${REVISION}"
DESTINATION="${COROCC_SOURCE_DIR:-${ROOT}/third-party/corocc}"
PATCH_DIR="${ROOT}/tools/corocc-patches"
CACHE_DIR="${ROOT}/third-party/.cache"
ARCHIVE="${CACHE_DIR}/corocc-${REVISION}.tar.gz"
STAMP="$(
    for patch_file in "${PATCH_DIR}"/*.patch; do
        [[ -f "${patch_file}" ]] || continue
        cat "${patch_file}" || exit 1
    done | sha256sum | cut -d' ' -f1
)"
if [[ -f "${DESTINATION}/.openppp2-corocc-revision" ]] &&
   [[ "$(<"${DESTINATION}/.openppp2-corocc-revision")" == "${REVISION}" ]] &&
   [[ -f "${DESTINATION}/.openppp2-corocc-patches" ]] &&
   [[ "$(<"${DESTINATION}/.openppp2-corocc-patches")" == "${STAMP}" ]] &&
   [[ -f "${DESTINATION}/include/corocc/coro_ctx.h" ]]; then
    echo "corocc ${REVISION} ready at ${DESTINATION}"
    exit 0
fi
if [[ -e "${DESTINATION}" ]]; then
    echo "error: existing corocc tree has a different pin/patch set; move it aside or set COROCC_SOURCE_DIR" >&2
    exit 1
fi
mkdir -p "${CACHE_DIR}" "$(dirname "${DESTINATION}")"
temporary_archive=""
temporary_source=""
cleanup() {
    [[ -z "${temporary_archive}" ]] || rm -f -- "${temporary_archive}"
    [[ -z "${temporary_source}" ]] || rm -rf -- "${temporary_source}"
    return 0
}
trap cleanup EXIT
if [[ ! -f "${ARCHIVE}" ]] || ! echo "${ARCHIVE_SHA256}  ${ARCHIVE}" | sha256sum -c - >/dev/null 2>&1; then
    temporary_archive="$(mktemp "${CACHE_DIR}/corocc.XXXXXX")"
    curl -fL --retry 3 "${SOURCE_URL}" -o "${temporary_archive}"
    echo "${ARCHIVE_SHA256}  ${temporary_archive}" | sha256sum -c -
    mv "${temporary_archive}" "${ARCHIVE}"
    temporary_archive=""
fi
temporary_source="$(mktemp -d "${DESTINATION}.XXXXXX")"
tar -xzf "${ARCHIVE}" --no-same-owner --no-same-permissions -m --strip-components=1 -C "${temporary_source}"
test -f "${temporary_source}/include/corocc/coro_ctx.h"
for patch_file in "${PATCH_DIR}"/*.patch; do
    [[ -e "${patch_file}" ]] || continue
    patch -d "${temporary_source}" -p1 --forward --batch <"${patch_file}"
done
printf '%s\n' "${REVISION}" >"${temporary_source}/.openppp2-corocc-revision"
printf '%s\n' "${STAMP}" >"${temporary_source}/.openppp2-corocc-patches"
mv "${temporary_source}" "${DESTINATION}"
temporary_source=""
echo "corocc ${REVISION} prepared at ${DESTINATION}"
