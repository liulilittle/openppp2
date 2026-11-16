#!/usr/bin/env bash
# The outer namespace contains even transient veth creation and netns registries.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == --inside ]]; then
  shift
  [[ "$(readlink /proc/self/ns/net)" != "$OPENPPP2_M3_INITIAL_NET" ]]
  [[ "$(readlink /proc/self/ns/mnt)" != "$OPENPPP2_M3_INITIAL_MNT" ]]
  mount --make-rprivate /
  mount --bind "$OPENPPP2_M3_ISOLATION_ROOT/etc-netns" /etc/netns
  mount --bind "$OPENPPP2_M3_ISOLATION_ROOT/run-netns" /run/netns
  mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
  export TMPDIR="$OPENPPP2_M3_ISOLATION_ROOT/tmp"
  python3 "$ROOT/tools/datapath_matrix_metadata.py" --check-isolation
  setsid "$@" & child=$!
  trap 'kill -TERM -- "-$child" 2>/dev/null || true' INT TERM
  status=0
  wait "$child" || status=$?
  # Do not let an interrupted wait release the caller's measurement lock early.
  if kill -0 "$child" 2>/dev/null; then wait "$child" || status=$?; fi
  # This registry is private to this invocation. Verify namespace identity
  # again before signalling any surviving process (never use names alone).
  while read -r namespace rest; do
    [[ -n "$namespace" ]] || continue
    status=1
    expected="$(stat -Lc 'net:[%i]' "/run/netns/$namespace")"
    for signal in TERM KILL; do
      for pid in $(ip netns pids "$namespace"); do
        [[ "$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)" == "$expected" ]] || continue
        kill -"$signal" "$pid" 2>/dev/null || true
      done
      [[ "$signal" != TERM ]] || sleep 0.2
    done
    if [[ -z "$(ip netns pids "$namespace")" ]]; then
      ip netns del "$namespace"
    else
      echo 'owned namespace still has processes; retaining isolation evidence' >&2
    fi
  done < <(ip netns list)
  exit "$status"
fi
dry_run=false
[[ "${1:-}" != --dry-run ]] || { dry_run=true; shift; }
[[ "${1:-}" == --run-dir && -n "${2:-}" ]] || { echo 'usage: run_m3_isolated.sh [--dry-run] --run-dir DIR -- COMMAND...' >&2; exit 2; }
run_dir="$(realpath "$2")"; shift 2
[[ "${1:-}" == -- ]] || exit 2
shift
[[ $# -gt 0 && -d "$run_dir" ]] || exit 2
if [[ "$dry_run" == true ]]; then
  printf 'unshare --net --mount --fork --kill-child bash %q --inside ' "$0"
  printf '%q ' "$@"
  printf '\n# private propagation; private /etc/netns and /run/netns; namespace sysfs; IRQ writes prohibited; M3 manifest passes --kernel-steering off\n'
  exit 0
fi
for command in unshare mount ip python3 setsid; do command -v "$command" >/dev/null; done
[[ -d /etc/netns && -d /run/netns ]] || { echo 'existing host mountpoints /etc/netns and /run/netns required' >&2; exit 1; }
export OPENPPP2_M3_INITIAL_NET="$(readlink /proc/self/ns/net)"
export OPENPPP2_M3_INITIAL_MNT="$(readlink /proc/self/ns/mnt)"
export OPENPPP2_M3_ISOLATION_ROOT="$(mktemp -d "$run_dir/isolation.XXXXXXXX")"
mkdir "$OPENPPP2_M3_ISOLATION_ROOT"/{etc-netns,run-netns,tmp}
chmod 700 "$OPENPPP2_M3_ISOLATION_ROOT"
exec unshare --net --mount --fork --kill-child bash "$0" --inside "$@"
