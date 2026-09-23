# CLI Reference
> Status: Active
> Type: Reference
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [命令行参考](CLI_REFERENCE_CN.md)


[中文版本](CLI_REFERENCE_CN.md)

## Position

This document explains the real `ppp` command line, not just the help banner. The CLI is
a startup-time shaping layer, not the whole configuration model. Most behavioral tuning
is done in `appsettings.json`; the CLI flags are overrides and platform helper actions
applied before the config file is fully parsed.

Source anchors:

- `main.cpp::PrintHelpInformation()` — help text generation
- `main.cpp::GetNetworkInterface()` — CLI parsing and `NetworkInterface` population
- `main.cpp::IsModeClientOrServer()` — mode detection

---

## High-Level Startup Flow

```mermaid
flowchart TD
    A["main()"] --> B["Parse CLI args\nGetNetworkInterface()"]
    B --> C{"--mode=?"}
    C -->|"starts with 'c'"| D["Client mode"]
    C -->|"server (default)"| E["Server mode"]
    D --> F["Load --config file\n(explicit / config.json / appsettings.json)"]
    E --> F
    F --> G["Apply CLI overrides\n(dns, bypass, firewall-rules, etc.)"]
    G --> H{"Platform helper\nflag present?"}
    H -->|"yes (Windows only)"| I["Execute helper action\nthen exit"]
    H -->|"no"| J["PppApplication::Run()\nstart VPN"]
    J --> K["ConsoleUI or plain-text banner"]
```

---

## CLI Argument Groups

The CLI surface splits into:

1. Role selection
2. Configuration file
3. Runtime shaping
4. Client network shaping
5. Routing and DNS inputs
6. Server policy inputs
7. Platform helper commands (Windows only)
8. Utility commands

---

## Role Selection

### `--mode=[client|server|proxy]`

- **Default:** `server`
- **Aliases:** `--m`, `-mode`, `-m`
- Values `client` (or any string beginning with `c`) select TUN client mode. Its native policy still consumes bypass, ordinary routes, peer-prefix routes, and DNS rules.
- Value `proxy` selects **proxy-only** mode: local HTTP/SOCKS listeners plus the same native policy. Desktop does not install host OS routes or take over system DNS (it uses `TapStub`).

This choice changes the entire startup branch:

- **client mode** creates/uses the virtual adapter path (`VEthernetNetworkSwitcher`,
  `VEthernetExchanger`, virtual TUN/TAP NIC)
- **proxy mode** connects to the server and exposes local HTTP/SOCKS proxies while retaining native bypass, route, peer-prefix, and DNS policy. Desktop uses `TapStub` and does not install desktop host routes or take over system DNS.
- **server mode** opens the server-side listener/switcher path
  (`VirtualEthernetSwitcher`, `VirtualEthernetExchanger`)

Proxy-only startup forces static transport off and does not initiate `STATIC`/`STATICACK`. If server-side IPv4 allocation is configured, it requests automatic allocation rather than a manual request derived from the local TUN address.

`client.routing` is the canonical policy when present. The legacy `--bypass` and `--dns-rules` inputs are compatibility sources for the same native policy when the canonical object is absent; they are not TUN-only switches.

```mermaid
flowchart TD
    A["--mode=<value>"] --> B{"value == proxy?"}
    B -->|yes| P["TapStub + native policy + local HTTP/SOCKS\nNo desktop host route/DNS takeover"]
    B -->|no| C{"value[0] == 'c'?"}
    C -->|"yes: client"| D["Create virtual NIC\nStart VEthernetNetworkSwitcher\nConnect to server"]
    C -->|"no: server"| E["Open listener\nStart VirtualEthernetSwitcher\nAccept clients"]
```

**Examples:**

```bash
ppp --mode=server --config=./server.json
ppp --mode=client --config=./client.json
ppp --mode=proxy --config=./client.json
ppp -m=client -c=./client.json
```

### `--proxy-http-port=<port>`

Local HTTP proxy listen port in proxy mode (overrides `client.http-proxy.port`).

### `--proxy-socks-port=<port>`

Local SOCKS5 proxy listen port in proxy mode (overrides `client.socks-proxy.port`).

---

## Configuration File

### `--config=<path>`

Aliases: `-c`, `--c`, `-config`, `--config`

Lookup order when not specified or specified path not found:

1. Explicit CLI path (if provided)
2. `./config.json`
3. `./appsettings.json`

Use an explicit path in production to avoid accidentally picking up a wrong configuration
from the working directory.

**Examples:**

```bash
ppp --mode=server --config=/etc/ppp/server.json
ppp --mode=client -c=/home/user/.config/client.json
```

---

## Runtime Shaping

### `--rt=[yes|no]`

Sets process-level real-time scheduling preference. When `yes`, the process attempts to
elevate its scheduling priority. Useful on low-latency servers.

### `--dns=<ip-list>`

Overrides the local DNS list for the current run. Accepts a comma-separated or
semicolon-separated list of IP addresses. Writes to `NetworkInterface::DnsAddresses`; it
does not replace DNS rules or server-side DNS logic.

**Example:**

```bash
ppp --mode=client -c=./client.json --dns=8.8.8.8,1.1.1.1
```

### `--tun-flash=[yes|no]`

Sets the default flash/TOS tendency early in startup. Controls whether the virtual
adapter marks packets with expedited forwarding DSCP bits.

### `--auto-restart=<seconds>`

Process-level restart timer. When the specified number of seconds elapses, the process
initiates a graceful restart via `ShutdownApplication(true)`. `0` disables the timer.

**Example:**

```bash
ppp --mode=client -c=./client.json --auto-restart=3600
```

### `--link-restart=<count>`

Restarts the process after the VPN link has reconnected more than `count` times. Useful
for detecting stale state and forcing a clean restart.

---

## Server Inputs

### `--block-quic=[yes|no]`

When `yes`, blocks QUIC-related UDP traffic for the current run. QUIC traffic uses
high-numbered UDP ports; blocking it forces HTTPS connections through TCP, which may
improve tunnel performance in some configurations.

### `--firewall-rules=<file>`

Specifies the firewall rules file. The file contains IP ranges and port rules that
the server applies to forwarded traffic. Default: `./firewall-rules.txt`.

**Example:**

```bash
ppp --mode=server -c=./server.json --firewall-rules=/etc/ppp/firewall.txt
```

---

## Client Inputs

### `--lwip=[yes|no]`

Selects the client network stack behavior. When `yes`, uses the lwIP TCP/IP stack for
virtual NIC packet processing. When `no`, uses the host network stack path.

### `--vbgp=[yes|no]`

Enables vBGP (virtual BGP) route updates. When enabled, the client periodically pulls
updated routing tables from the server. Refresh cadence is controlled by
`vbgp.update-interval` in the configuration file.

### `--nic=<interface>`

Physical interface hint. Tells the client which physical NIC to use as the egress
interface for VPN tunnel traffic. Used on multi-homed hosts.

**Example:**

```bash
ppp --mode=client -c=./client.json --nic=eth0
```

### `--ngw=<ip>`

Physical gateway hint. Specifies the next-hop gateway for the physical NIC. Used when
the default route needs to be preserved alongside the VPN route.

### `--tun=<name>`

Virtual adapter name. Overrides the TUN/TAP interface name assigned by the OS.

**Examples:**

```bash
# Linux
ppp --mode=client -c=./client.json --tun=ppp0

# Windows
ppp --mode=client -c=./client.json --tun="PPP Adapter"
```

### `--tun-ip=<ip>`

IPv4 address to assign to the virtual adapter.

### `--tun-ipv6=<ip>`

IPv6 address to assign to the virtual adapter.

### `--tun-gw=<ip>`

Gateway address for the virtual adapter. This is the server-side gateway address
assigned to the TUN interface.

### `--tun-mask=<bits>`

Network prefix length (CIDR notation number) for the virtual adapter's IPv4 subnet.
For example, `24` means a `/24` subnet mask (`255.255.255.0`).

### `--tun-vnet=[yes|no]`

Controls subnet-forwarding behavior. When `yes`, traffic for the entire virtual subnet
is routed through the tunnel, enabling LAN-to-LAN connectivity.

### `--tun-host=[yes|no]`

Controls whether host-network behavior is preferred. When `yes` (default), the virtual
adapter's gateway is used as the default route, routing all host traffic through the VPN.

### `--tun-static=[yes|no]`

Enables static tunnel mode. When `yes`, uses `PACKET_HEADER` static packet format
instead of the normal transmission packet format. See `PACKET_FORMATS.md`.

### `--tun-mux=<connections>`

MUX connection count. Sets the number of parallel multiplexed underlying connections.
`0` disables MUX. When MUX is enabled, the `nmux` flag in the handshake will reflect
the mux state.

**Example:**

```bash
ppp --mode=client -c=./client.json --tun-mux=4
```

### `--tun-mux-acceleration=<mode>`

MUX acceleration mode. Controls how the multiplexed connections distribute traffic.
Valid values depend on the build configuration.

### `--mux-mode=<compat|flow|balance|stripe>`

MUX scheduler mode. `compat` / `flow` / `balance` send by **competition** (any
linklayer with send credit takes the next queued frame — no per-connection binding,
which would risk load imbalance and degenerate to a single TCP under several heavy
flows). `stripe` is the experimental exception: it prefers round-robin per-packet
distribution, with busy-link fallback. Modes differ in receiver-side ordering and intent.
`flow` with turbo, `balance`, and `stripe` add an optional MUX capability byte for
flow-v2 negotiation.
Configure both peers consistently.

| Mode | Behavior | Use case |
|------|----------|----------|
| `compat` | Original upstream behavior: competition send + single global sequence/ack ordering on receive. One connection's gap head-of-line blocks all connections. | Default / rollback / regression baseline. |
| `flow` | Latency-oriented direction: competition send + global ordering. Optional `--mux-mode-turbo` layers best-link-first first-packet, prewarmed carrier links, and negotiated per-flow DSN on top for first-byte responsiveness without cross-flow HoL blocking or per-connection binding. | Interactive / web / latency-sensitive use. |
| `balance` | Competition send + **negotiated per-flow receiver ordering (flow v2)**: each connection is reordered independently by per-flow DSN, so a slow/blocked connection only head-of-line blocks itself, not the others — while every link stays fully and adaptively utilized (no binding). | Many concurrent connections wanting throughput with per-flow isolation. |
| `stripe` | Experimental: round-robin per-packet distribution + per-flow ordering. | Future pseudo-MPTCP / 9000-MTU work. |

> **`flow+turbo`, `balance`, and `stripe` negotiate per-flow ordering and need both ends on a supporting
> build.** Negotiation is an intersection; against an older peer the session falls back to
> `compat` global ordering (no regression, no per-flow benefit). The trade-off of per-flow
> ordering is that a connection's own frames may arrive out of order across links and wait
> in a bounded reorder buffer up to `mux.flow.reorder.timeout`.
>
> **`stripe` caveat (experimental):** striping one flow across links of different speeds
> causes heavy intra-connection reordering and can be *worse* than `compat`/`flow`. It is a
> base for future per-link sequencing work, not a fast path today.

Set `mux.mode` in JSON or pass `--mux-mode=flow` at startup (CLI overrides JSON).

**Default:** `compat`

### `--mux-mode-turbo=[yes|no]`

flow-mode turbo (opt-in, default `no`; only meaningful under `--mux-mode=flow`). It sends
a new connection's first packet over the most-recently-active carrier link (an approximate
"best link" by recency of inbound traffic — **not** an RTT measurement; it reuses existing
per-link activity and adds no control frames) to cut first-byte latency. The connection is
**not** bound to that link — every later frame returns to the normal competition pool.

Turbo also negotiates flow-v2 per-flow DSN when both peers support it, so a delayed frame
from one connection does not globally head-of-line block unrelated connections while the
extra carrier pool is active. It opens and retires extra carrier TCP links at runtime to
widen the competition pool when backlog indicates poor quality. The original `--tun-mux`
value remains the base pool size; turbo raises only the runtime carrier ceiling and does
not add per-connection binding or rebuild the mux session. Set `mux.turbo` in JSON or pass
`--mux-mode-turbo=yes`.

**Default:** `no`

### `--debug-key=<secret>` and `--mux-mode-set=<compat|flow|balance|stripe>`

Debug-only remote control of the peer's scheduler mode. This is opt-in and intended for
testing on jittery links, not for production.

- `--debug-key=<secret>` sets a shared secret. Remote mux-mode control is **disabled
  unless this key is non-empty on the receiving side**. Configure the **same** key on
  both client and server.
- `--mux-mode-set=<compat|flow|balance|stripe>` asks the *other* endpoint to switch its
  scheduler mode. The request is sent once, after the mux session is established, over the
  existing encrypted vmux transport (a new `cmd_mux_mode_set` control frame; no new
  per-packet header field).

The receiver applies the change only when its own `--debug-key` is non-empty and matches
the key carried in the frame (compared in constant time). A missing key, a mismatched
key, or a malformed frame is logged and ignored — the session is never torn down, so a
forged frame cannot disrupt traffic.

The pushed mode is **sticky on the receiver**: it is recorded as a runtime override and
survives mux session rebuilds (link flap, idle/heartbeat timeout, reconnect), so it does
not silently revert to the configured `mux.mode` on the next reconnect. It is not written
to disk and resets to the configured value when the receiver process restarts.

You can also set the key in JSON as `mux.debug.key`. The `--mux-mode-set` request itself
is transient (CLI only) and is never written back to the configuration file.

> **Compatibility:** the `cmd_mux_mode_set` control frame is only emitted when both
> `--debug-key` and `--mux-mode-set` are set. Both peers must run a build that
> understands this frame; sending it to an older peer that predates the feature will be
> treated as an invalid command and drop that mux session. Only use it when both ends run
> a matching build.

```
# server (allows remote control, same key as client)
ppp --mode=server -c=./server.json --debug-key=lab-secret

# client (push the server to flow mode at runtime for an A/B test)
ppp --mode=client -c=./client.json --tun-mux=8 --debug-key=lab-secret --mux-mode-set=flow
```

### `--tun-promisc=[yes|no]`

Promiscuous mode on Linux and macOS. When `yes`, the virtual NIC accepts all frames
regardless of destination MAC address. Required for certain bridge configurations.

### `--tun-ssmt=<threads>` or `--tun-ssmt=<N>[/<mode>]`

SSMT (server-side multi-threading) tuning. On Linux, the `mq` mode opens one TUN queue
per worker thread, enabling parallel packet processing across CPU cores. On macOS, only
the thread-count form is documented.

**Examples:**

```bash
# Linux: 4 worker threads with multi-queue
ppp --mode=client -c=./client.json --tun-ssmt=4/mq

# macOS: 4 worker threads
ppp --mode=client -c=./client.json --tun-ssmt=4
```

### `--tun-route=[yes|no]`

Linux route-compatibility toggle. Controls whether the client modifies the system
routing table to add routes for the VPN subnet.

### `--tun-protect=[yes|no]`

Linux route-protection toggle. When `yes`, the client adds a host route for the VPN
server's IP address through the physical gateway, preventing routing loops.

### `--tun-lease-time-in-seconds=<sec>`

Windows DHCP lease time for the virtual adapter. Controls how long the virtual NIC
holds its DHCP lease before renewal. Only applies on Windows.

---

## Routing Inputs

### `--bypass=<file1|file2>`

Bypass IP list source. IP addresses and ranges are loaded into the native route policy/RIB/FIB as bypass entries. In normal TUN mode, supported desktop platforms may also project them to host routes; proxy-only keeps the native classification without installing desktop host routes. Multiple files can be separated by `|`. Default: `./ip.txt`.

**Example:**

```bash
ppp --mode=client -c=./client.json --bypass=./cn.txt|./local.txt
```

### `--bypass-nic=<interface>`

Interface hint for bypass-list processing on Linux. It supplies the egress interface
when the native policy is also projected to desktop host routes; it does not disable
native policy in proxy-only mode.

### `--bypass-ngw=<ip>`

Gateway hint for bypass-list processing. It supplies the next hop when bypass policy is
projected to desktop host routes; the native policy remains available in proxy-only mode.

### `--virr=[file/country]`

Enables IP-list refresh behavior (VIRR: Virtual IP Route Refresh). The argument is
either a file path or a country code. When enabled, the client periodically re-downloads
and re-applies the bypass IP list. Refresh cadence is controlled by
`virr.update-interval` and `virr.retry-interval` in the configuration file.

**Example:**

```bash
ppp --mode=client -c=./client.json --virr=CN
```

### `--dns-rules=<file>`

DNS rules source. The file specifies domain patterns and their target DNS servers or
forwarding behavior and is loaded into native DNS policy in both TUN and proxy-only
modes. Normal TUN mode may additionally configure tunnel/system DNS; proxy-only does
not take over system DNS. Default: `./dns-rules.txt`.

**Example:**

```bash
ppp --mode=client -c=./client.json --dns-rules=/etc/ppp/dns-rules.txt
```

---

## Platform Helpers (Windows Only)

These are helper actions that modify system network configuration. They are not tunnel
start options; they execute the specified action and then exit.

| Flag | Action |
|------|--------|
| `--system-network-reset` | Resets Windows network stack to defaults |
| `--system-network-optimization` | Applies recommended TCP/UDP tuning parameters |
| `--system-network-preferred-ipv4` | Sets IPv4 as preferred over IPv6 in Windows binding order |
| `--system-network-preferred-ipv6` | Sets IPv6 as preferred over IPv4 in Windows binding order |
| `--no-lsp <program>` | Launches `<program>` with LSP (Layered Service Provider) bypass |

**Examples:**

```cmd
ppp --system-network-reset
ppp --system-network-optimization
ppp --system-network-preferred-ipv4
ppp --no-lsp "C:\Program Files\MyApp\app.exe"
```

---

## Utility Commands

### `--help`

Prints the help output listing all CLI flags with brief descriptions and exits. The
help output is generated by `main.cpp::PrintHelpInformation()`.

### `--pull-iplist [file/country]`

Downloads an IP list (bypass list) for the specified country code or from the specified
URL/file, writes it to the target file, and exits after the action completes. Useful for
pre-populating the bypass list before starting the tunnel.

**Example:**

```bash
ppp --pull-iplist CN
ppp --pull-iplist ./cn.txt
```

---

## Console UI Commands And Layout

The runtime Console UI is a dedicated interactive surface, separate from startup CLI
flags. It is only active when stdout is connected to a terminal.

Source anchors:

- `ppp/app/ConsoleUI.cpp::ExecuteCommand(...)` — command dispatch
- `ppp/app/ConsoleUI.cpp::RenderFrame(...)` — frame rendering
- `ppp/diagnostics/ErrorHandler.cpp::GetLastErrorCodeSnapshot(...)` — status error snapshot

### Built-In Console Commands

| Command | Action |
|---------|--------|
| `openppp2 help` | Print available command list |
| `openppp2 restart` | Graceful restart via `ShutdownApplication(true)` |
| `openppp2 reload` | Same action as restart |
| `openppp2 exit` | Process shutdown via `ShutdownApplication(false)` |
| `openppp2 info` | Pull and print a full runtime environment snapshot |
| `openppp2 clear` | Clear cmd output ring buffer and reset scroll |
| `openppp2 telemetry status` | Print current telemetry configuration |
| `openppp2 telemetry help` | Print telemetry subcommand usage |
| `openppp2 telemetry log on\|off\|toggle` | Enable / disable / toggle telemetry log console output filter |
| `openppp2 telemetry metric on\|off\|toggle` | Enable / disable / toggle metric console output filter |
| `openppp2 telemetry span on\|off\|toggle` | Enable / disable / toggle span console output filter |
| `openppp2 telemetry level 0\|1\|2\|3` | Set telemetry verbosity threshold (0=Info … 3=Trace) |
| `openppp2 telemetry all` | Enable all console telemetry filters |
| `openppp2 telemetry quiet` | Disable all console telemetry filters |
| `openppp2 telemetry clear` | Clear telemetry event buffer (TUI right panel) |
| *(any other input)* | Execute as shell command, capture output to cmd section |

Notes:

- Bare commands such as `help`, `restart`, `exit`, `clear`, and `status` are treated as system shell commands.
- Built-in handling requires the `openppp2` namespace prefix.
- The `openppp2 telemetry` shorthand (without a subcommand) is equivalent to `openppp2 telemetry status`.

### Keyboard Controls

| Key | Action |
|-----|--------|
| `Up` / `Down` | Command history navigation |
| `Left` / `Right` | Move cursor in editor line |
| `Home` | Scroll info section to top |
| `End` | Scroll info section to bottom |
| `Backspace` / `Delete` | Erase character before / at cursor |
| `PageUp` / `PageDown` | Scroll cmd output section up / down |
| `Ctrl+A` | Move cursor to beginning of line |
| `Ctrl+E` | Move cursor to end of line |
| `Enter` | Execute command |

### Telemetry Commands

> **Migration note:** Previous versions used single-character hotkeys (`l`, `m`, `s`, `0`–`3`,
> `a`, `q`, `?`) that were intercepted immediately on keypress to toggle telemetry subsystems.
> These hotkeys were **removed** because they interfered with normal shell input — typing an
> `l` in a shell command could unintentionally toggle telemetry logging.
>
> Telemetry is now controlled exclusively through the `openppp2 telemetry …` command namespace.
> Commands are only parsed after `Enter`, so normal shell input is never intercepted or
> truncated.

| Command | Description |
|---------|-------------|
| `openppp2 telemetry` / `openppp2 telemetry status` | Print current telemetry state (log, metric, span enabled/disabled, verbosity threshold) |
| `openppp2 telemetry help` | Print telemetry subcommand usage guide |
| `openppp2 telemetry log on` | Enable telemetry log console output filter |
| `openppp2 telemetry log off` | Disable telemetry log console output filter |
| `openppp2 telemetry log toggle` | Toggle telemetry log console output filter |
| `openppp2 telemetry metric on` | Enable metric console output filter |
| `openppp2 telemetry metric off` | Disable metric console output filter |
| `openppp2 telemetry metric toggle` | Toggle metric console output filter |
| `openppp2 telemetry span on` | Enable span console output filter |
| `openppp2 telemetry span off` | Disable span console output filter |
| `openppp2 telemetry span toggle` | Toggle span console output filter |
| `openppp2 telemetry level 0` | Verbosity threshold: Info only |
| `openppp2 telemetry level 1` | Verbosity threshold: Info + Verb |
| `openppp2 telemetry level 2` | Verbosity threshold: Info + Verb + Debug |
| `openppp2 telemetry level 3` | Verbosity threshold: Info + Verb + Debug + Trace (all) |
| `openppp2 telemetry all` | Enable all console telemetry filters (log + metric + span) |
| `openppp2 telemetry quiet` | Disable all console telemetry filters (log + metric + span) |
| `openppp2 telemetry clear` | Clear telemetry event buffer (visible in TUI right panel) |

> **Note:** The `log`, `metric`, and `span` commands only toggle console/local output
> filters. They do **not** change global telemetry runtime gates (`telemetry.enabled`,
> count gates, or span gates) or the verbosity threshold configured in
> `appsettings.json`. Similarly, `level` controls only the console verbosity threshold
> and does not affect the configuration file setting.

The `telemetry` namespace requires the `openppp2` prefix — bare `telemetry` input will be
executed as a shell command. See `OTEL_DESIGN.md` for the underlying telemetry subsystem
architecture and `appsettings.json` configuration keys.

### Layout

The TUI frame is divided into:

1. **Header** (10 fixed rows): top border, hint lines, ASCII art, spacer, separator
2. **Info section** (dynamic, ~60% of middle area): scrollable VPN status lines, `Home`/`End`
3. **Cmd section** (dynamic, ~40% of middle area): scrollable command output, `PageUp`/`PageDown`
4. **Input line** (1 row): editor with white-background caret
5. **Status bar** (1 row): left column shows diagnostics + telemetry filter indicators (`T:LMS @<level> (openppp2 telemetry help)`), right column shows VPN state and throughput summary

See `TUI_DESIGN.md` for the complete layout specification.

### Status Bar Semantics

The bottom status row is split into two columns (roughly 60/40):

- **Left column** — Diagnostics snapshot and telemetry filter indicators:
  - `[INFO] 0 Success: Success` when `ErrorCode::Success` is active.
  - `[%LEVEL%] <numeric_id> <CodeName>: <message> (<age>)` for the most recent non-success
    error, where `<age>` is derived from `GetLastErrorTimestamp()` and rendered as `Ns ago`.
  - Followed by telemetry filter state: `  | T:LMS @<level> (openppp2 telemetry help)` where each of `L`, `M`, `S`
    is shown when the corresponding console filter (log, metric, span) is enabled, or `-`
    when disabled. `<level>` is the current verbosity threshold (0–3).
  - ANSI color follows severity: info=green, warn=yellow, error=red, fatal=bright red.
- **Right column** — VPN state and throughput summary (e.g. `VPN: connected  ↑ 1.2MB/s  ↓ 3.4MB/s`).

---

## Defaults Worth Remembering

| Flag | Default |
|------|---------|
| `--mode` | `server` |
| `--config` | `./config.json` then `./appsettings.json` |
| `--dns` | Falls back to preferred DNS pair from config if parsing fails |
| `--bypass` | `./ip.txt` |
| `--dns-rules` | `./dns-rules.txt` |
| `--firewall-rules` | `./firewall-rules.txt` |
| `--tun-host` | `yes` |
| `--rt` | `yes` |
| `--tun-mux` | `0` (disabled) |
| `--mux-mode` | `compat` |
| `--debug-key` | (disabled) |
| `--mux-mode-set` | (off) |

---

## Typical Usage Examples

### Server

```bash
# Minimal server start
ppp --mode=server --config=/etc/ppp/server.json

# Server with custom firewall rules and real-time scheduling
ppp --mode=server --config=/etc/ppp/server.json \
    --firewall-rules=/etc/ppp/firewall.txt \
    --rt=yes
```

### Client (Linux)

```bash
# Basic client
ppp --mode=client --config=/etc/ppp/client.json

# Client with bypass list, MUX, and DNS override
ppp --mode=client --config=/etc/ppp/client.json \
    --bypass=./cn.txt \
    --tun-mux=4 \
    --dns=8.8.8.8,8.8.4.4 \
    --tun-ssmt=4/mq

# Client with route protection and auto-restart every hour
ppp --mode=client --config=/etc/ppp/client.json \
    --tun-protect=yes \
    --auto-restart=3600
```

### Client (Windows)

```cmd
rem Optimize network stack first (run once as administrator)
ppp --system-network-optimization

rem Start client
ppp --mode=client --config=C:\ppp\client.json --tun-lease-time-in-seconds=86400
```

### Utility

```bash
# Download Chinese IP bypass list and exit
ppp --pull-iplist CN

# Show help
ppp --help
```

---

## Error Code Reference

CLI-related error codes (from `ppp/diagnostics/Error.h`):

| ErrorCode | Description |
|-----------|-------------|
| `ConfigFileNotFound` | Config file not found at any lookup path |
| `ConfigFileMalformed` | Config file JSON parsing failed or is malformed |
| `AppInvalidCommandLine` | CLI option or `--mode` value not recognized |
| `DnsAddressInvalid` | DNS address value contained an invalid IP address |
| `FileNotFound` | Referenced file path not found |
| `ConfigDnsRuleLoadFailed` | DNS rules file failed to load |
| `FirewallLoadFileFullPathEmpty` | Firewall rules file path was empty or invalid for loading |
| `NetworkInterfaceUnavailable` | `--nic` specified interface not found |
| `NetworkGatewayInvalid` | `--ngw` or `--bypass-ngw` value invalid |
| `NetworkAddressInvalid` | `--tun-ip`, `--tun-ipv6`, or `--tun-gw` value invalid |

---

## Related Documents

- [`CONFIGURATION.md`](CONFIGURATION.md) — Full `appsettings.json` schema
- [`TRANSMISSION.md`](../architecture/TRANSMISSION.md) — Transport layer details
- [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) — System architecture overview
- [`ERROR_HANDLING_API.md`](ERROR_HANDLING_API.md) — Error code system
- [`TUI_DESIGN.md`](../architecture/TUI_DESIGN.md) — Console UI layout and behavior
