# Security

> Status: Active
> Type: Operations
> Last verified: 2026-10-11 (against the security diagnostics in `AppConfiguration.cpp`, `ppp/diagnostics/ErrorCodes.def`, `TransportAuthConfiguration.cpp`, `ApplicationMode.cpp`, `VEthernetLocalProxySwitcher.cpp`, `go/ppp/Admin.go`, `go/guardian/config.go`)
>
> **Purpose:** Assets to protect, configurations to avoid, and a hardening checklist.
> **Audience:** Operators deploying and maintaining OPENPPP2.
> **Parent index:** [Operations](README.md) · **Chinese:** [安全](SECURITY_CN.md)

This page is operational hardening guidance, not a formal security assessment; it does not claim forward secrecy, a leak-proof kill switch, or automatic firewall management.

## 1. Assets to protect

| Asset | Location | If leaked |
|---|---|---|
| Tunnel keys | Configuration `key.protocol-key` / `transport-key` | Forged clients can connect; traffic can be decrypted |
| `transport-auth` key files | `keys[].secret-file` | Connection authentication can be passed |
| Manager keys and tokens | Manager `key`, `admin.token`; C++ `server.backend-key` | Node impersonation or manager control |
| Subscription links and documents | `/sub/{token}` | Documents contain node addresses and keys |
| Manager data | `manager-data.json` | All users, nodes, subscriptions |
| Guardian configuration | `guardian.json` (`auth.jwtSecret` is the login password) | Control of local `ppp` processes and configs |
| Policy stores, status files, logs | `.ppp-policy`, `dns-fake-ip`, `server.log`, telemetry logs | Access records, internal addresses |

Make these readable only by the service account (e.g. `chmod 600`); never commit them, paste them into tickets, or include them in screenshots.

## 2. Encryption settings

Startup prints `[security] WARN` for the following (warnings only — **startup is not blocked**):

| Warning | Trigger | Action |
|---|---|---|
| `ConfigPlaintextEnabled` | `key.plaintext` is `true` — **which it is when the field is omitted** | Write `"plaintext": false` explicitly |
| `ConfigWeakKeyDefault` | A key equals the built-in default `"ppp"` (an empty key also falls back to it) | Generate unique random keys per deployment |
| `ConfigWeakKeyShort` | A key is shorter than 8 bytes | Use random strings of 16+ characters |
| `ConfigLegacyCipherAlgorithm` / `ShortKey` | RC4, DES, Blowfish, CAST5, SEED, IDEA, or a key below 128 bits | Use the default `aes-128-cfb` / `aes-256-cfb` |
| `ConfigLegacyKdfMd5` | Always: key derivation uses `EVP_BytesToKey` (MD5) internally | A known legacy design; compensate with long random keys |

Notes:

- A misspelled cipher name **silently falls back** to the default instead of failing; if both sides use the same wrong name they still connect, but not with the cipher you think.
- The default CFB modes provide no integrity protection by themselves. Enable `transport-auth` for connection authentication beyond the keys, and consider a WSS (TLS) carrier across untrusted networks.
- Generate a random key, for example: `openssl rand -base64 24`. Never reuse keys from documentation or repository samples.

## 3. `transport-auth` (optional connection authentication)

- Uses a 32-byte pre-shared key file (64 lowercase hex characters), owned by the service user with mode `600`, otherwise loading fails. Generate: `openssl rand -hex 32 | tr -d '\n' > k.hex && chmod 600 k.hex`.
- When enabled, exactly one key must be `active`. To rotate: add the new key as `verify-only` on all nodes, switch it to `active`, then mark the old one `revoked`.
- Windows cannot read secret files. Field details are in the [Configuration reference · transport-auth](../reference/CONFIGURATION.md).

## 4. Listeners and exposure

| Listener | Default | Recommendation |
|---|---|---|
| Server tunnel ports (`tcp` / `websocket` / `udp` / `cdn`) | All addresses | Open only the ports in use; bind to a specific interface with `ip.interface` if needed |
| Client local proxies (proxy mode) | Forced `127.0.0.1` | Nothing to do |
| Client local proxies (TUN mode) | **All addresses** when `bind` is empty | Use `127.0.0.1` for local-only use; set SOCKS5 username/password when serving the LAN |
| Manager (`go/`) | `:10000` (all addresses), **no TLS** | Bind to private / loopback; expose via a TLS reverse proxy; set a fixed `admin.token` (otherwise a temporary one is generated each start) |
| Guardian | `127.0.0.1:18080` | Keep it local; use an SSH tunnel or TLS reverse proxy for remote access |

## 5. Host networking is part of the boundary

TUN clients change routes and DNS; servers may change IPv6, NDP, and NAT rules.

- Review split lists and DNS rules before rollout: wrong rules can send traffic or DNS queries outside the tunnel.
- An abnormal client exit can leave stale routes; default-route protection is not a kill switch and does not guarantee zero leaks.
- Keep host firewall, route persistence, and DNS service policy under operator control; the program does not manage firewalls.
- Linux server GUA / NAT66 / NDP are privileged host operations that need their own upstream and firewall review.

## 6. Subscriptions and management

- Subscription links are credentials and tokens never expire. When a user leaves or a link leaks, rotate the token or disable the subscription in the manager.
- Publish subscriptions over HTTPS only (`admin.public-base-url` changes generated links; it does not add TLS to the listener).
- The manager `key` and C++ `server.backend-key` must match and stay secret; use different values per environment.

## 7. Hardening checklist

1. Configurations, key files, manager data, and logs readable only by the service account.
2. Full `key` block, `"plaintext": false`, distinct random keys per environment; no `[security] WARN` at startup (except the MD5 KDF line).
3. A unique `client.guid` per client.
4. Open only the ports in use; never expose the manager or Guardian directly to the Internet.
5. HTTPS for public management / subscription entry points, with access-log monitoring.
6. Review subscription contents before publishing — no stray nodes or test keys.
7. Revalidate routing, DNS, IPv6, and peer prefix policy after upgrades or topology changes.
8. On suspected leaks: rotate affected keys / tokens, restrict listeners, redeploy configurations, and confirm the old credentials no longer work.

## Related documents

- [Deployment](DEPLOYMENT.md) · [Operations and troubleshooting](OPERATIONS.md)
- [Management backend](../guides/MANAGEMENT_BACKEND.md) · [Remote subscription](../guides/REMOTE_SUBSCRIPTION.md) · [Configuration reference](../reference/CONFIGURATION.md)
