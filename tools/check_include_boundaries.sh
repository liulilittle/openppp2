#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
violations=0

if command -v rg >/dev/null 2>&1 && rg --version >/dev/null 2>&1; then
  search_sources() { rg -n "$1" "$2" -g'*.h' -g'*.cpp'; }
  search_headers() { rg -n "$1" "$2" -g'*.h'; }
  list_headers() { rg -l "$1" "$2" --glob '*.h'; }
else
  search_sources() { grep -R -n -E --include='*.h' --include='*.cpp' "$1" "$2"; }
  search_headers() { grep -R -n -E --include='*.h' "$1" "$2"; }
  list_headers() { grep -R -l -E --include='*.h' "$1" "$2"; }
fi

# client must not include server headers
if search_sources '#include <ppp/app/server/' ppp/app/client/ 2>/dev/null; then
  echo "FAIL: client includes server headers"
  violations=$((violations + 1))
fi

# application internal hub must not pull client+server switcher headers
if search_headers '#include <ppp/app/(client/VEthernetNetworkSwitcher|server/VirtualEthernetSwitcher)\.h>' ppp/app/PppApplicationInternal.h 2>/dev/null; then
  echo "FAIL: PppApplicationInternal includes switcher headers"
  violations=$((violations + 1))
fi

# facade/views must not pull heavy deps (skip if directory missing)
if [[ -d ppp/facade/views ]]; then
  if search_headers 'configurations/AppConfiguration|json/json' ppp/facade/views/ 2>/dev/null; then
    echo "FAIL: facade views pull heavy deps"
    violations=$((violations + 1))
  fi
fi

# stdafx in headers: baseline grows only with new headers, fail only if count increases
# 103 -> 105: P2-e adds ServerUdpRelayHost.h + ServerDatagramPortManager.h, mirroring the client udp headers.
# 105 -> 107: P2-f adds StaticUdpRelayHost.h + StaticDatagramPortManager.h for the static-echo table.
# 107 -> 109: PMTU hardening adds VirtualEthernetPathMtu.h + VirtualEthernetTcpMss.h.
STDAFX_BASELINE=109
stdafx_count=$({ list_headers 'stdafx' ppp 2>/dev/null || true; } | wc -l | tr -d ' ')
if [[ "$stdafx_count" -gt "$STDAFX_BASELINE" ]]; then
  echo "FAIL: stdafx in ppp/**/*.h increased ($stdafx_count > $STDAFX_BASELINE)"
  violations=$((violations + 1))
else
  echo "INFO: stdafx in ppp/**/*.h = $stdafx_count (baseline $STDAFX_BASELINE)"
fi

if [[ $violations -eq 0 ]]; then
  echo "PASS: include boundaries"
else
  exit 1
fi
