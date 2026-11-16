#!/usr/bin/env bash
# Compile-smoke: ClientPacketDispatchHandler.cpp must build in isolation (Wave B3).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-build/test/dispatch_handler_compile.o}"
mkdir -p "$(dirname "$OUT")"

CXX="${CXX:-clang++}"
INCLUDES=(
    -I"$ROOT"
    -I"$ROOT/common"
    -I"$ROOT/common/dnslib"
    -I"$ROOT/common/json/include"
)

for hint in /usr/include /usr/local/include /opt/homebrew/include; do
    if [[ -f "$hint/boost/version.hpp" ]]; then
        INCLUDES+=("-I$hint")
        break
    fi
done

# Windows vcpkg layouts keep boost outside the default compiler search path.
for hint in /c/vcpkg/installed/x64-windows-static/include /c/vcpkg/installed/x64-windows/include; do
    if [[ -f "$hint/boost/version.hpp" ]]; then
        INCLUDES+=("-I$hint")
        break
    fi
done

"$CXX" -std=gnu++17 -DFUNCTION "${INCLUDES[@]}" \
    -c "$ROOT/ppp/app/client/ClientPacketDispatchHandler.cpp" \
    -o "$OUT"

echo "ClientPacketDispatchHandler compile smoke: OK ($OUT)"
