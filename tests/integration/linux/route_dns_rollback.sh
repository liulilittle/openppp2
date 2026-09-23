#!/usr/bin/env bash
set -euo pipefail

NS="openppp2-route-dns-$$"
PEER="${NS}-peer"
STATE_DIR="$(mktemp -d)"
NETNS_DNS_DIR="/etc/netns/$NS"

cleanup() {
  if [[ -n "${OPENPPP2_NAMESPACE_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "$OPENPPP2_NAMESPACE_ARTIFACT_DIR"
    cp -f "$STATE_DIR"/* "$OPENPPP2_NAMESPACE_ARTIFACT_DIR"/ 2>/dev/null || true
  fi
  ip netns del "$NS" 2>/dev/null || true
  ip netns del "$PEER" 2>/dev/null || true
  rm -rf "$NETNS_DNS_DIR" "$STATE_DIR"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "route_dns_rollback.sh must run as root" >&2
  exit 2
fi

mkdir -p "$NETNS_DNS_DIR"
printf 'nameserver 192.0.2.53\n' >"$NETNS_DNS_DIR/resolv.conf"

ip netns add "$NS"
ip netns add "$PEER"
ip link add openppp2-client type veth peer name openppp2-peer
ip link set openppp2-client netns "$NS"
ip link set openppp2-peer netns "$PEER"
ip -n "$NS" addr add 198.51.100.2/24 dev openppp2-client
ip -n "$PEER" addr add 198.51.100.1/24 dev openppp2-peer
ip -n "$NS" link set lo up
ip -n "$PEER" link set lo up
ip -n "$NS" link set openppp2-client up
ip -n "$PEER" link set openppp2-peer up
ip -n "$NS" route add default via 198.51.100.1

snapshot() {
  ip -n "$NS" -j route show table all >"$1.routes"
  ip netns exec "$NS" cat /etc/resolv.conf >"$1.dns"
}

assert_baseline() {
  snapshot "$STATE_DIR/after"
  diff -u "$STATE_DIR/before.routes" "$STATE_DIR/after.routes"
  diff -u "$STATE_DIR/before.dns" "$STATE_DIR/after.dns"
}

apply_policy() {
  ip -n "$NS" route add 203.0.113.0/24 via 198.51.100.1
  ip -n "$NS" route add 192.0.2.53/32 via 198.51.100.1
  printf 'nameserver 203.0.113.53\n' >"$NETNS_DNS_DIR/resolv.conf"
}

rollback_policy() {
  ip -n "$NS" route del 203.0.113.0/24 via 198.51.100.1 2>/dev/null || true
  ip -n "$NS" route del 192.0.2.53/32 via 198.51.100.1 2>/dev/null || true
  cp "$STATE_DIR/before.dns" "$NETNS_DNS_DIR/resolv.conf"
}

snapshot "$STATE_DIR/before"

apply_policy
rollback_policy
assert_baseline

ip -n "$NS" route add 203.0.113.0/24 via 198.51.100.1
if ip -n "$NS" route add unreachable.invalid/24 via 198.51.100.1 2>/dev/null; then
  echo "partial apply unexpectedly succeeded" >&2
  exit 1
fi
rollback_policy
assert_baseline

echo "PASS: Linux namespace Route/DNS rollback"
