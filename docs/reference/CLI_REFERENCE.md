# CLI Reference

> Status: Active
> Type: Reference
> Last verified: 2026-10-11 (against `ppp/app/ApplicationHelp.cpp`, `ApplicationConfig.cpp`, `ApplicationInitialize.cpp`, `ApplicationPolicyCommand.cpp`, `ConsoleUI.cpp`)
>
> **Purpose:** Every command-line flag, subcommand, and runtime console command of the `ppp` executable.
> **Audience:** Users starting, debugging, and deploying OPENPPP2.
> **Parent index:** [Reference](README.md) · **Chinese:** [命令行参考](CLI_REFERENCE_CN.md)

JSON fields are in the [Configuration reference](CONFIGURATION.md). `ppp --help` prints the flags supported by the current build (platform-specific flags appear only on their platform).

## 1. Syntax

```bash
ppp [--flag=value ...]
ppp policy <subcommand> [options]
```

- Flags are written `--name=value`; booleans accept `yes`/`no` (also `y`, `true`, `1`, and similar). Quote values that contain spaces.
- `-h`, `--h`, `-help`, `--help` print help and exit.
- Most client flags affect only the current run and are not written back to the configuration file.

## 2. General flags

| Flag | Default | Meaning |
|---|---|---|
| `--mode=client\|server\|proxy` | `server` | Runtime role. Aliases `--m`, `-mode`, `-m`. Anything starting with `c` is client; `proxy` must be spelled in full; anything else, or nothing, is server. |
| `--config=<path>` | see right | Configuration file. Aliases `-c`, `--c`, `-config`. If unset or unreadable, `./config.json` then `./appsettings.json` are tried. |
| `--rt=yes\|no` | `yes` | Real-time (high-priority) scheduling. |
| `--dns=<ip-list>` | derived from `dns.servers` | DNS pushed to the OS in TUN mode, comma-separated. When unset it is derived from `dns.servers.foreign` / `domestic`; if nothing can be derived it is `8.8.8.8` (Windows clients add `8.8.4.4`). |
| `--tun-flash=yes\|no` | `no` | Set a high-priority TOS (QoS) on sockets. |
| `--block-quic=yes\|no` | `no` | Block QUIC so applications fall back to TCP. |
| `--auto-restart=<seconds>` | `0` | Restart the process after running this long; 0 = off. |
| `--link-restart=<count>` | `0` | Restart the process when the client's reconnection count reaches this value; 0 = off. |
| `--stats-json=<path\|stdout>` | off | Write local runtime statistics as NDJSON; ignored if the path is not writable. |

## 3. Server flags

| Flag | Default | Meaning |
|---|---|---|
| `--firewall-rules=<file>` | `./firewall-rules.txt` | Firewall rules file. |

Server listeners, address pools, IPv6, and the rest live in the configuration file; see the [Configuration reference](CONFIGURATION.md).

## 4. Client flags

### Adapter and addressing

| Flag | Default | Meaning |
|---|---|---|
| `--tun=<name>` | platform default | Virtual adapter name. |
| `--tun-ip=<ip>` | `10.0.0.2` | Virtual adapter IPv4. When given explicitly and the server has an address pool, it is requested as a specific address. |
| `--tun-gw=<ip>` | `10.0.0.1` | Virtual adapter gateway. |
| `--tun-mask=<bits>` | `30` | Prefix length, clamped to 16–32. |
| `--tun-ipv6=<ip>` | server-assigned | Request a specific IPv6 address. |
| `--tun-vnet=yes\|no` | `yes` | Subnet forwarding (client-to-client). |
| `--proxy-subnet=yes\|no` | `yes` | Proxy mode only: join the virtual subnet through the in-process stack (no adapter). See [Proxy mode](../guides/PROXY_MODE.md). |
| `--proxy-internet=yes\|no` | `yes` | Proxy mode only: also proxy Internet destinations; `no` leaves a subnet-only client. |
| `--proxy-forward=<port>[:<local>][,...]` | (none) | Proxy mode with the virtual subnet: TCP ports on the virtual IP that peers may open, forwarded to `127.0.0.1`. |
| `--tun-host=yes\|no` | `yes` | Point the default route at the tunnel (full tunnel). |
| `--tun-static=yes\|no` | `no` | Static UDP tunnel mode (uses the server's `udp.listen.port`). Ignored in proxy mode: no `STATIC`/`STATICACK` exchange. With `--proxy-subnet=yes`, an explicit `--tun-ip` is still honored; otherwise proxy-mode IPv4 assignment remains automatic. |
| `--nic=<interface>` | auto | Physical egress interface. |
| `--ngw=<ip>` | auto | Physical gateway. |

### Stack and multiplexing

| Flag | Default | Meaning |
|---|---|---|
| `--tcp-stack=native\|lwip\|xtcp` | `native` (`lwip` on Windows without the Wintun driver) | TCP stack. `xtcp` works only when enabled at build time; otherwise startup fails. XTCP uses a 1 MiB per-connection send-buffer quota by default; see [configuration reference](CONFIGURATION.md#xtcp-runtime-tuning). |
| `--lwip=yes\|no` | same as above | Legacy switch, equivalent to `--tcp-stack=lwip`. |
| `--tun-mux=<connections>` | `0` | Parallel MUX connections; 0 = MUX off. |
| `--tun-mux-acceleration=<0-3>` | `0` | MUX acceleration mode; values above 3 become 0. |
| `--mux-mode=compat\|flow\|balance\|stripe` | `compat` | Overrides `mux.mode`. |
| `--mux-mode-turbo=yes\|no` | `no` | Overrides `mux.turbo` (meaningful only with `flow`). |
| `--debug-key=<secret>` | off | Overrides `mux.debug.key`. |
| `--mux-mode-set=<mode>` | off | After the session is up, ask the peer to switch scheduler; requires matching `debug.key`. Current run only, never persisted. |

### Platform-specific

| Flag | Platform | Default | Meaning |
|---|---|---|---|
| `--tun-promisc=yes\|no` | Linux, macOS | `yes` | Adapter promiscuous mode. |
| `--tun-ssmt=<N>[/mq]` | Linux | `0` | Packet worker threads; with `mq`, each worker opens its own TUN queue. |
| `--tun-ssmt=<N>` | macOS | `0` | Packet worker threads. |
| `--tun-route=yes\|no` | Linux | `no` | Route compatibility mode. |
| `--tun-protect=yes\|no` | Linux | `yes` | Keep the tunnel's own connections out of the tunnel. |
| `--bypass-nic=<interface>` | Linux | auto | Egress interface for the bypass list. |
| `--tun-lease-time-in-seconds=<sec>` | Windows | `7200` | Virtual adapter DHCP lease. |
| `--set-http-proxy=yes\|no` | Windows | `no` | Point the system HTTP proxy at the client's local HTTP proxy (not applied in proxy mode). |

### Split routing

| Flag | Default | Meaning |
|---|---|---|
| `--bypass=<file1\|file2>` | `./ip.txt` | Direct (bypass) IP lists, `\|`-separated. **Ignored when the config has `client.routing`.** |
| `--bypass-ngw=<ip>` | auto | Gateway for the bypass list. |
| `--dns-rules=<file>` | `./dns-rules.txt` | DNS rules file. **Ignored when the config has `client.routing`.** |
| `--virr=[file/country]` | off | Periodically download a country IP list from APNIC and re-apply it, e.g. `--virr=ip.txt/CN`. Intervals come from `virr.*`. Same argument format as `--pull-iplist`. |
| `--vbgp=yes\|no` | `yes` | Enable remote route updates from `ip.routes[].vbgp`. |

### Proxy mode

| Flag | Default | Meaning |
|---|---|---|
| `--proxy-http-port=<port>` | `8080` | Overrides `client.http-proxy.port`. Must be an integer in 1..65535; invalid values abort startup. |
| `--proxy-socks-port=<port>` | `1080` | Overrides `client.socks-proxy.port`. Must be an integer in 1..65535; invalid values abort startup. |

See [Proxy mode](../guides/PROXY_MODE.md) for the full `--mode=proxy` behavior.

## 5. Utility commands (run and exit)

| Command | Platform | Meaning |
|---|---|---|
| `--pull-iplist [file/country]` | all | Download a country IP list from APNIC; the file defaults to `./ip.txt`. See the format note below. |
| `--system-network-reset` | Windows | Reset the Windows network stack. |
| `--system-network-optimization` | Windows | Apply network performance tuning. |
| `--system-network-preferred-ipv4` / `--system-network-preferred-ipv6` | Windows | Prefer IPv4 / IPv6. |
| `--no-lsp <program>` | Windows | Let the program bypass LSP. |

**`file/country` format:** the program splits file and country code at the **first** `<` (or, without `<`, the first `/`). When the file name itself contains `/`, separate with `<`:

```bash
./ppp --pull-iplist=ip.txt/CN                    # ip.txt in the current directory
./ppp --pull-iplist="/opt/openppp2/ip.txt<CN"    # with a path, use < and quote it
```

The form `./ip.txt/CN` is split at `./` — **do not use it** (the default shown by `ppp --help` has the same problem).

## 6. `ppp policy` subcommands

Check, explain, initialize, migrate, and update `client.policy` (v2) configurations without starting the tunnel.

| Command | Purpose |
|---|---|
| `ppp policy check --config FILE --runtime tun\|http\|socks [--platform P] [--json]` | Validate and compile the policy. |
| `ppp policy explain --config FILE --runtime R (--domain HOST\|--ip ADDR) [--network tcp\|udp] [--port N] [--json]` | Explain which route and DNS a target would use. |
| `ppp policy init --out DIR --template proxy-all\|direct-all\|split-cn --runtime R [--geoip SRC --geosite SRC] [--json]` | Write a starter policy bundle. |
| `ppp policy migrate --config LEGACY --out DIR [--bypass F] [--dns-rules F] [--runtime R] [--platform P] [--json]` | Migrate a legacy config to a v2 draft. |
| `ppp policy export --config FILE --out FILE [--store DIR] [--json]` | Export policy data. |
| `ppp policy status --config FILE [--store DIR] [--json]` | Show update status. |
| `ppp policy update --config FILE [--store DIR] (--interface IF [--bootstrap udp://IP:PORT] \| --proxy-endpoint 127.0.0.1:PORT) [--json]` | Fetch and validate remote rule sets. |

`--platform` is `linux`, `windows`, `macos`, `android`, or `ios`. Exit codes: `0` success, `2` argument / configuration / compilation error, `3` unavailable source or storage failure, `4` unsupported capability, `5` migration draft needs review. See the [Policy CLI guide](../guides/POLICY_CLI.md).

## 7. Runtime console commands

When running in the foreground of a terminal, the bottom input line accepts these commands (the `openppp2` prefix is required; other input runs as a system shell command):

| Command | Meaning |
|---|---|
| `openppp2 help` | List commands. |
| `openppp2 info` | Print a full runtime environment snapshot. |
| `openppp2 restart` / `openppp2 reload` | Restart the process (reloads the configuration). |
| `openppp2 exit` | Exit. |
| `openppp2 clear` | Clear the command output section. |
| `openppp2 peer status` | Print P2P peer status. |
| `openppp2 peer set <uuid> ipv4-first\|ipv6-first\|relay-first` | Set a peer's P2P priority. |
| `openppp2 telemetry [status\|help]` | Show telemetry console filter state. |
| `openppp2 telemetry log\|metric\|span on\|off\|toggle` | Toggle console output filters (does not change the config file). |
| `openppp2 telemetry level 0-3` | Console verbosity (0=Info … 3=Trace). |
| `openppp2 telemetry all\|quiet\|clear` | Enable all / disable all / clear the telemetry buffer. |

Keys: `↑`/`↓` history, `PageUp`/`PageDown` scroll command output, `Home`/`End` scroll the status area, `Ctrl+A`/`Ctrl+E` line start / end.

## 8. Examples

```bash
# Server
sudo ./ppp --mode=server --config=/etc/ppp/server.json

# Full-tunnel TUN client with 4 MUX connections
sudo ./ppp --mode=client --config=./client.json --tun-mux=4

# Local proxies only (127.0.0.1:1080 / 8080), no system route changes
./ppp --mode=proxy --config=./client.json --proxy-socks-port=1080

# Download the China IP list to ./ip.txt
./ppp --pull-iplist=ip.txt/CN
```

## Related documents

- [Writing the configuration file](../getting-started/CONFIGURE.md) · [Configuration reference](CONFIGURATION.md)
- [Proxy mode](../guides/PROXY_MODE.md) · [Routing and DNS](../guides/ROUTING_AND_DNS.md) · [Platforms](../guides/PLATFORMS.md)
