# User Manual

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against current source and the `.github/workflows/release.yml` package manifest)
>
> **Purpose:** From download to a working tunnel, then common scenarios.
> **Audience:** Users deploying and running OPENPPP2.
> **Parent index:** [Getting started](README.md) · **Chinese:** [用户手册](USER_MANUAL_CN.md)

## 1. What OPENPPP2 is

OPENPPP2 is a single-file, cross-platform virtual network program, `ppp`. The same executable takes one of three roles depending on its flags:

| Role | Start with | Purpose |
|---|---|---|
| Server | `ppp --mode=server` (default) | Runs on a machine with a public address, accepts clients, and forwards traffic. |
| TUN client | `ppp --mode=client` | Creates a virtual adapter and sends host traffic into the tunnel, fully or by split rules. |
| Proxy client | `ppp --mode=proxy` | Opens local HTTP / SOCKS5 proxies only, without changing system routes or DNS. |

## 2. Choose a package

Each release provides these binary packages (they unpack to `ppp` or `ppp.exe`):

| Platform | Package | Notes |
|---|---|---|
| Linux x86_64 | `openppp2-linux-amd64.zip` | Generic |
| | `openppp2-linux-amd64-simd.zip` | SIMD enabled, recommended for newer CPUs |
| | `…-io-uring…`, `…-tc…` combinations | io_uring / other build variants |
| | `openppp2-linux-amd64-debian10.zip` | For older glibc |
| Other Linux architectures | `openppp2-linux-{aarch64,armv7l,riscv64,ppc64el,s390x,mipsel}-cross.zip` | Cross-compiled |
| Windows | `openppp2-windows-x64-Release.zip`, `openppp2-windows-ARM64-Release.zip` | |
| macOS | `openppp2-darwin-arm64.zip`, `openppp2-darwin-x86_64.zip` | |
| Android | `openppp2-android-{arm64-v8a,armeabi-v7a,x86,x86_64}.zip` | Native libraries for app integration |

Packages with `-asan` are debug builds; do not use them in production. To build yourself, see [Development](../development/README.md).

## 3. Privileges and system changes

| System item | TUN client | Proxy client | Server |
|---|---|---|---|
| Privileges | Administrator / root (`CAP_NET_ADMIN` on Linux) | Usually none on desktop; mobile uses the OS VPN consent | Administrator / root (checked at startup) |
| Virtual adapter | Created | Not created on desktop | Not created (platform-dependent for IPv6 and similar features) |
| System routes | Tunnel and split routes added, restored on exit | Unchanged | Unchanged |
| System DNS | Set to tunnel DNS (`--dns` or derived from `dns.servers`) | Unchanged | Unchanged |
| System HTTP proxy | Only on Windows with `--set-http-proxy=yes` | Unchanged | — |

Split rules (`client.routing` / `client.policy`) apply in both client modes; proxy mode just does not take over system routes and DNS.

Stop a client with `Ctrl+C`, `openppp2 exit`, or the service manager's normal stop so routes and DNS are restored. Killing the process forcibly can leave stale routes.

## 4. Quick start

1. **Download and unpack** the package for your platform, for example on Linux:

   ```bash
   mkdir -p /opt/openppp2 && cd /opt/openppp2
   unzip openppp2-linux-amd64-simd.zip
   chmod +x ppp
   ```

2. **Write the configuration**: follow [Writing the configuration file](CONFIGURE.md) to create `server.json` and `client.json`. The `key` blocks must be identical, and `"plaintext": false` must be present.

3. **Start the server** (on the server machine):

   ```bash
   sudo ./ppp --mode=server --config=./server.json
   ```

   Open the port given by `tcp.listen.port`.

4. **Start the client**:

   ```bash
   sudo ./ppp --mode=client --config=./client.json
   ```

   On Windows, run `ppp.exe --mode=client --config=client.json` from an administrator terminal.

5. **Confirm the tunnel**: the client's bottom status bar shows the connection as established; run `openppp2 info` on the input line to see the virtual address, DNS, and statistics; then open an external site and check that your egress address is the server's. A running process or a startup log alone does not prove the tunnel works.

List every flag with `./ppp --help`.

## 5. Common scenarios

### 5.1 Full tunnel

The minimal configuration is already a full tunnel: all traffic leaves through the server. To keep some networks out of the tunnel, see 5.2.

### 5.2 Split tunnel: China direct, everything else tunneled

```bash
./ppp --pull-iplist=ip.txt/CN     # download the China IP list to ./ip.txt
```

Add to the client configuration:

```json
"client": {
  "guid": "{...}",
  "server": "ppp://SERVER_IP:20000/",
  "routing": {
    "ip":  { "bypass": ["./ip.txt"] },
    "dns": { "rules": ["./dns-rules.txt"] }
  }
}
```

Sample `dns-rules.txt` (format in [Configuration · DNS rules](../reference/CONFIGURATION.md)):

```text
cn/doh.pub
baidu.com/doh.pub
google.com/cloudflare/tun
```

Add `--virr=ip.txt/CN` at startup to refresh the list automatically. With `client.routing` present, the `--bypass` / `--dns-rules` flags no longer apply. For more complex rules, use the v2 policy: `ppp policy init --template split-cn ...`; see the [Policy CLI guide](../guides/POLICY_CLI.md).

### 5.3 Local proxy only

```bash
./ppp --mode=proxy --config=./client.json
```

Listens on `127.0.0.1:8080` (HTTP) and `127.0.0.1:1080` (SOCKS5); point your browser or application there. Change ports with `--proxy-http-port` / `--proxy-socks-port`. See [Proxy mode](../guides/PROXY_MODE.md).

### 5.4 Behind Nginx (WebSocket)

Server:

```json
"websocket": { "host": "vpn.example.com", "path": "/tun", "listen": { "ws": 20080 } }
```

Nginx (terminating TLS):

```nginx
location /tun {
    proxy_pass http://127.0.0.1:20080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

Client:

```json
"server": "wss://vpn.example.com/tun"
```

`websocket.host` must be a domain; the client URL path must equal `websocket.path`.

### 5.5 Publish a client LAN service on the server

In the `client` block:

```json
"mappings": [
  { "protocol": "tcp", "local-ip": "127.0.0.1", "local-port": 22, "remote-ip": "::", "remote-port": 10022 }
]
```

Once connected, `SERVER_IP:10022` reaches port 22 on the client. The server must keep `server.mapping: true` (the default).

### 5.6 Assign IPv6 to clients (server)

```json
"server": {
  "ipv6": { "mode": "nat66", "cidr": "fd42:4242:4242::/64" }
}
```

`mode` is required (`nat66` or `gua`); `cidr` alone does not enable IPv6. On unsupported platforms the configuration fails to load. See [IPv6 client assignment](../guides/IPV6.md).

### 5.7 Connect a management backend

```json
"server": { "node": 1, "backend": "ws://127.0.0.1/ppp/webhook", "backend-key": "replace-with-backend-key" }
```

The backend authenticates and accounts sessions; see [Management backend](../guides/MANAGEMENT_BACKEND.md).

### 5.8 Multi-link acceleration

```bash
sudo ./ppp --mode=client --config=./client.json --tun-mux=4
```

`--tun-mux` sets the parallel connection count; scheduling comes from `mux.mode` (`compat` / `flow` / `balance`); see [Configuration · mux](../reference/CONFIGURATION.md).

## 6. Acting as a LAN gateway

### Linux

Enable forwarding (add to `/etc/sysctl.conf`, then run `sysctl -p`):

```conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
```

NAT the LAN (adjust the network and egress):

```bash
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### Windows

The [VGW](https://github.com/liulilittle/vgw-release) virtual gateway tool can be used, for example `--ip=192.168.0.40 --ngw=192.168.0.1 --mask=255.255.255.0`.

## 7. Certificates

TLS connections such as DoH / DoT and WSS load `cacert.pem` from the program directory first when it exists, otherwise the built-in roots and the system store. For a custom trust chain, place a PEM CA bundle named `cacert.pem` next to `ppp` (for example [curl's CA bundle](https://curl.se/docs/caextract.html)).

## 8. Quick troubleshooting

| Symptom | Check first |
|---|---|
| Exits immediately | Running as administrator / root; configuration path; the error code printed on the console (see [Error codes](../reference/ERROR_CODES.md)) |
| Keeps reconnecting | [Writing the configuration file · fields that must line up](CONFIGURE.md); server port reachable (`nc -vz SERVER_IP PORT`) |
| `[security] WARN` printed | Default / short keys, or `plaintext` is `true` |
| Connected but pages do not load | DNS: is the `--dns` server reachable; did split rules send the DNS server direct |
| No network after exit | The process was killed and routes were not restored; restart networking, or run again and exit normally |

See [Operations and troubleshooting](../operations/OPERATIONS.md) for the full workflow.

## Related documents

- [Writing the configuration file](CONFIGURE.md) · [Configuration reference](../reference/CONFIGURATION.md) · [CLI reference](../reference/CLI_REFERENCE.md)
- [Routing and DNS](../guides/ROUTING_AND_DNS.md) · [Proxy mode](../guides/PROXY_MODE.md) · [Platforms](../guides/PLATFORMS.md)
- [Deployment](../operations/DEPLOYMENT.md) · [Security](../operations/SECURITY.md)
