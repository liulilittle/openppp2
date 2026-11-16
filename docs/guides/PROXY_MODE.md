# Proxy Mode

> Status: Active
> Type: Guide
> Last verified: 2026-10-12 (against `ApplicationMode.cpp`, `ApplicationClientBootstrap.cpp`, `ClientConnectionOpener.cpp`, `VEthernetLocalProxySwitcher.cpp`)
>
> **Purpose:** Provide local HTTP / SOCKS5 proxies only, without changing system routes or DNS.
> **Audience:** Users who want some applications, not the whole machine, to use the tunnel.
> **Parent index:** [Guides](README.md) · **Chinese:** [代理模式](PROXY_MODE_CN.md)

## 1. When to use it

| Need | Choose |
|---|---|
| All machine traffic follows the tunnel rules | TUN client: `--mode=client` |
| Only a browser / some programs use the tunnel; system networking unchanged | **Proxy mode**: `--mode=proxy` |
| Desktop without administrator rights | Proxy mode (no adapter, no administrator; other clients are reachable through the local proxy too) |

## 2. Quick start

Use the same client configuration as a TUN client (`key` + `client.guid` + `client.server`):

```bash
./ppp --mode=proxy --config=./client.json
```

Verify:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

Point the browser or application proxy at `127.0.0.1:1080` (SOCKS5) or `127.0.0.1:8080` (HTTP).

## 3. Two ways to enable it

| Way | How |
|---|---|
| Command line | `--mode=proxy` |
| Configuration | `"client": { "proxy-only": true }`, then start with `--mode=client` |

Both behave the same.

## 4. Listen addresses and ports

| Listener | Address | Default port | Change the port |
|---|---|---|---|
| HTTP (including HTTPS CONNECT) | `127.0.0.1` (forced) | `8080` | `client.http-proxy.port` or `--proxy-http-port` |
| SOCKS5 (CONNECT and UDP ASSOCIATE) | `127.0.0.1` (forced) | `1080` | `client.socks-proxy.port` or `--proxy-socks-port` |

- In proxy mode `bind` is **always `127.0.0.1`**; a configured `bind` is ignored, and a bind failure is an error rather than a fallback to all addresses. To serve other LAN devices, use the TUN client with an explicit `bind`.
- SOCKS5 username/password authentication is enabled with `client.socks-proxy.username` / `password`.

## 5. Split rules still apply

Bypass lists, routes, and DNS rules from `client.routing` (or `client.policy`) load as usual in proxy mode: destinations matched as direct are connected locally, the rest go through the tunnel. The only difference is that the rules are not written into the OS route table or DNS settings.

```json
"client": {
  "guid": "{...}",
  "server": "ppp://SERVER_IP:20000/",
  "proxy-only": true,
  "routing": {
    "ip":  { "bypass": ["./ip.txt"] },
    "dns": { "rules": ["./dns-rules.txt"] }
  }
}
```

## 6. Reaching other clients (virtual subnet)

When the server enables `server.subnet`, clients of the same server reach each other by virtual IP. Desktop proxy mode **creates no adapter**; it joins the virtual subnet inside the client process (the in-process stack). Two independent switches give three uses:

| Use | `--proxy-subnet` | `--proxy-internet` | Effect |
|---|---|---|---|
| Subnet + proxy (default) | `yes` | `yes` | The local proxy reaches the Internet and other clients |
| Subnet only | `yes` | `no` | The local proxy accepts only virtual-subnet targets and rejects the rest (`ProxyInternetDisabled`); the client does not set the system proxy |
| Proxy only | `no` | `yes` | The previous behavior: Internet proxying without the virtual subnet |

With the virtual subnet joined:

- **Outbound**: TCP and UDP to peer virtual IPs through the local HTTP / SOCKS5 proxy leave from the local virtual IP inside the process, over P2P once a direct path is established, otherwise through the server relay. This traffic never leaves through a host socket. Other programs cannot reach peers without the local proxy.
- **Inbound**: peers can open only explicitly listed TCP ports, set with `--proxy-forward`, for example `--proxy-forward=22,8080:3000`: virtual-IP port 22 goes to `127.0.0.1:22` and 8080 to `127.0.0.1:3000`. Unlisted ports are refused.
- **Virtual IP**: with `--tun-ip` the address is registered as manual and the server pool is not asked; without it the client asks the server pool and applies the assigned address to the in-process stack (requires `server.ipv4-pool` in the client configuration; otherwise the default address is used).
- P2P reads the physical NIC to bind sockets and gather candidates; it reads only and changes no routes.

Current limits: inbound forwards are TCP only; a UDP datagram carries at most 1372 payload bytes; peer LAN prefixes (peer-routes) are not provided. See the [plan](../design/p2p-direct-channel/proxy-only-subnet-plan_CN.md) (Chinese).

## 7. Platform differences

| Platform | In proxy mode | Privileges |
|---|---|---|
| Windows / Linux / macOS | No adapter is created. The in-process stack is used when the virtual subnet is joined, otherwise an internal stub. Routes and DNS are never changed | No administrator |
| Android | A minimal VPN interface is still created (for socket protection) with only its subnet route; no DNS or IPv6 capture; the local proxy is not published as a system proxy | VPN consent |
| iOS | The Network Extension keeps only the tunnel-subnet route and sets no system DNS | Network Extension entitlement |

The Android app labels the switch “仅代理模式” (proxy only).

## 8. Other limits

- Proxy mode forces the static UDP tunnel off: `--tun-static` has no effect, and no `STATIC`/`STATICACK` exchange takes place. Without the virtual subnet, IPv4 assignment uses automatic mode even when `--tun-ip` is given; with the virtual subnet joined, `--tun-ip` is honored as a manual address.
- System DNS is unchanged, so an application's own DNS lookups do not use the tunnel; use `socks5h://` (proxy-side name resolution) to avoid local lookups.

## Related documents

- [Configuration reference · client](../reference/CONFIGURATION.md) · [CLI reference](../reference/CLI_REFERENCE.md)
- [Routing and DNS](ROUTING_AND_DNS.md) · [Platforms](PLATFORMS.md)
