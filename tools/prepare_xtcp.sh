#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVISION="e79db8fd10a1ee39be2dc3a9361727fcad79d04c"
ARCHIVE_SHA256="fd194478fdc850d851297976c926e31caab02fbaa7eddc213c5be545c13494d6"
SOURCE_URL="https://github.com/liulilittle/xtcp/archive/${REVISION}.tar.gz"
DESTINATION="${XTCP_SOURCE_DIR:-${ROOT}/third-party/xtcp}"
MARKER="${DESTINATION}/.openppp2-xtcp-revision"
PATCH_MARKER="${DESTINATION}/.openppp2-xtcp-patches"
PATCH_DIR="${ROOT}/tools/xtcp-patches"
CACHE_DIR="${ROOT}/third-party/.cache"
ARCHIVE="${CACHE_DIR}/xtcp-${REVISION}.tar.gz"

patch_stamp() {
    if [[ -d "${PATCH_DIR}" ]] && compgen -G "${PATCH_DIR}/*.patch" >/dev/null; then
        cat "${PATCH_DIR}"/*.patch | sha256sum | cut -d' ' -f1
    else
        printf 'none\n'
    fi
}

# Applies every tools/xtcp-patches/*.patch (in name order) to the tree at $1.
# Idempotent: a patch that is already applied (reverse applies cleanly) is
# skipped; anything else is a hard failure so a drifting pin cannot silently
# drop a patch.
apply_patches() {
    local target="$1"
    local stamp="$2"
    [[ -d "${PATCH_DIR}" ]] || return 0
    local patch_file
    for patch_file in "${PATCH_DIR}"/*.patch; do
        [[ -e "${patch_file}" ]] || continue
        if patch -d "${target}" -p1 --forward --dry-run -s <"${patch_file}" 2>/dev/null; then
            patch -d "${target}" -p1 --forward -s <"${patch_file}"
        elif patch -d "${target}" -p1 --reverse --dry-run -s <"${patch_file}" 2>/dev/null; then
            : # already applied
        else
            echo "error: XTCP patch $(basename "${patch_file}") does not apply cleanly to ${target}" >&2
            return 1
        fi
    done
    printf '%s\n' "${stamp}" >"${target}/.openppp2-xtcp-patches"
}

cleanup() {
    rm -f -- "${temporary_archive:-}"
    if [[ -n "${temporary_source:-}" ]] &&
       [[ "${temporary_source}" == "${ROOT}/third-party/xtcp.${REVISION}."* ]] &&
       [[ -d "${temporary_source}" ]]; then
        rm -rf -- "${temporary_source}"
    fi
}
trap cleanup EXIT

STAMP="$(patch_stamp)"

if [[ -f "${MARKER}" ]] &&
   [[ "$(<"${MARKER}")" == "${REVISION}" ]] &&
   [[ -f "${DESTINATION}/CMakeLists.txt" ]] &&
   [[ -f "${DESTINATION}/include/xtcp/core/stack.h" ]]; then
    if [[ -f "${PATCH_MARKER}" ]] && [[ "$(<"${PATCH_MARKER}")" == "${STAMP}" ]]; then
        echo "XTCP ${REVISION} is ready at ${DESTINATION}"
        exit 0
    fi
    # Right revision but the patch set drifted. In-place re-patching is
    # unreliable by design: a patch's "already applied" reverse-probe only
    # holds when later patches never touched the same lines, which stacked
    # patches do not guarantee. Rebuild the tree from the cached archive and
    # the full patch set instead (fully deterministic).
    rebuild=1
fi

if [[ -e "${DESTINATION}" && "${rebuild:-0}" != "1" ]]; then
    echo "error: ${DESTINATION} exists but is not a complete XTCP ${REVISION} tree" >&2
    echo "       move it aside or choose a non-existent XTCP_SOURCE_DIR" >&2
    exit 1
fi

mkdir -p "${CACHE_DIR}"
if [[ ! -f "${ARCHIVE}" ]] ||
   [[ "$(sha256sum "${ARCHIVE}" | cut -d' ' -f1)" != "${ARCHIVE_SHA256}" ]]; then
    temporary_archive="$(mktemp "${CACHE_DIR}/xtcp-${REVISION}.XXXXXX")"
    curl -fL --retry 3 "${SOURCE_URL}" -o "${temporary_archive}"
    actual_sha256="$(sha256sum "${temporary_archive}" | cut -d' ' -f1)"
    if [[ "${actual_sha256}" != "${ARCHIVE_SHA256}" ]]; then
        echo "error: XTCP archive checksum mismatch" >&2
        echo "       expected ${ARCHIVE_SHA256}" >&2
        echo "       actual   ${actual_sha256}" >&2
        exit 1
    fi
    mv "${temporary_archive}" "${ARCHIVE}"
    temporary_archive=""
fi

temporary_source="$(mktemp -d "${ROOT}/third-party/xtcp.${REVISION}.XXXXXX")"
tar -xzf "${ARCHIVE}" --strip-components=1 -C "${temporary_source}"
if [[ ! -f "${temporary_source}/CMakeLists.txt" ]] ||
   [[ ! -f "${temporary_source}/include/xtcp/core/stack.h" ]]; then
    echo "error: downloaded archive does not contain the expected XTCP tree" >&2
    exit 1
fi

printf '%s\n' "${REVISION}" >"${temporary_source}/.openppp2-xtcp-revision"
apply_patches "${temporary_source}" "${STAMP}"
if [[ -e "${DESTINATION}" ]]; then
    # rebuild path (patch-set drift): swap the stale tree aside only after
    # the fresh one is fully built and patched.
    stale_backup="${ROOT}/third-party/.xtcp-stale.$$"
    mv "${DESTINATION}" "${stale_backup}"
    if mv "${temporary_source}" "${DESTINATION}"; then
        temporary_source=""
        rm -rf -- "${stale_backup}"
    else
        mv "${stale_backup}" "${DESTINATION}"  # roll back
        exit 1
    fi
else
    mv "${temporary_source}" "${DESTINATION}"
    temporary_source=""
fi
trap - EXIT

echo "XTCP ${REVISION} prepared at ${DESTINATION}"
