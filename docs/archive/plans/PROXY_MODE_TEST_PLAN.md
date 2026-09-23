# Proxy-only mode test plan
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


Test matrix for `feature/proxy-only-mode`.

## Phase 1 — Mode / config / TapStub (unit)

| ID | Test file | Case |
|----|-----------|------|
| M1 | `test_application_mode.cpp` | `--mode=proxy` → `ApplicationMode::Proxy` |
| M2 | `test_application_mode.cpp` | `--mode=client` / `server` parsing |
| M3 | `test_application_mode.cpp` | `ApplicationModeName` / `IsClientRuntimeMode` |
| C1 | `test_proxy_defaults.cpp` | Empty bind/port → 127.0.0.1:8080 / 1080 |
| C2 | `test_proxy_defaults.cpp` | Existing bind/port preserved |
| T1 | `test_tap_stub.cpp` | `TapStub::Create(nullptr)` returns null |
| T2 | `test_tap_stub.cpp` | Open + Output no-op success |

## Phase 2 — Switcher (manual / future mock)

| ID | Scope | Case |
|----|-------|------|
| S1 | `VEthernetNetworkSwitcher` | `proxy_only_` skips `AddAllRoute` |
| S2 | Switcher | Requires ≥1 proxy listener at startup |
| S3 | Switcher | Telemetry `client.proxy.attach` vs `client.tun.attach` |

## Phase 3 — HTTP/SOCKS handshake (future)

| ID | Scope | Case |
|----|-------|------|
| P1 | HTTP proxy | CONNECT request parsing |
| P2 | SOCKS5 | method negotiation |

## Phase 4 — Integration

| ID | Tool | Case |
|----|------|------|
| I1 | `tools/proxy_mode_smoke.sh` | Process starts, port listens |
| I2 | Manual | `curl -x socks5h://127.0.0.1:1080` through server |
| I3 | Manual | Default route unchanged after proxy-only exit |

## Phase 5 — Android

| ID | Scope | Case |
|----|-------|------|
| A1 | Flutter options | `proxyOnly` toggle saved per profile |
| A2 | `PppVpnService` | Minimal route when `proxyOnly=true` |
| A3 | Native | `libopenppp2` sets `ProxyOnly(true)` |

## Coverage gate

Run `./scripts/coverage.sh` and verify ≥ **70%** line coverage on:

- `ppp/app/ApplicationMode.cpp`
- `ppp/tap/TapStub.cpp`
- `ppp/configurations/AppConfiguration.cpp` (ApplyProxyModeDefaults)
- `ppp/app/ApplicationInitialize.cpp`
- `ppp/app/client/VEthernetNetworkSwitcher.cpp`

## Regression

- `./ppp --mode=client` full TUN path unchanged
- Server mode unchanged
- iOS build excludes proxy-only UI (desktop/Android only)
