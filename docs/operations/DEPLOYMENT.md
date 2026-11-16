# Deployment

> Status: Active
> Type: Operations
> Last verified: 2026-10-11 (against `ppp/app/ApplicationInitialize.cpp`, `PppApplication.cpp`, `go/guardian/config.go`, `go/guardian/service/systemd.go`, `go/guardian/instance/manager.go`, `.github/workflows/release.yml`)
>
> **Purpose:** Run OPENPPP2 as a long-lived system service, plus upgrades, rollback, and multiple instances.
> **Audience:** Operators deploying a server or an always-on client.
> **Parent index:** [Operations](README.md) · **Chinese:** [部署](DEPLOYMENT_CN.md)

Get it working in the foreground first (see the [User manual](../getting-started/USER_MANUAL.md)), then turn it into a service with this page.

## 1. Pre-deployment checks

| Item | Requirement |
|---|---|
| Privileges | Server and TUN client must run as administrator / root (proxy mode excepted), otherwise startup fails with `AppPrivilegeRequired`. |
| Configuration | Pass `--config=<absolute path>`; write the full `key` block with `"plaintext": false`; a distinct `client.guid` per client. |
| Ports | Open `tcp.listen.port` in the server firewall / security group, plus any enabled `websocket.listen.ws/wss`, `udp.listen.port`, `cdn`. |
| Drivers | Linux has `/dev/net/tun`; Windows keeps the release package's `Driver\` directory. |
| Certificates | WSS certificate and key files readable by the service user. |
| Time | Accurate server clock (TLS validation depends on it). |

## 2. Directory layout (Linux example)

```text
/opt/openppp2/
├── ppp                 # executable
├── server.json         # or client.json
├── ip.txt              # split list (client, optional)
├── dns-rules.txt       # DNS rules (client, optional)
└── cacert.pem          # custom CA (optional)
```

```bash
chmod 700 /opt/openppp2
chmod 600 /opt/openppp2/*.json    # configurations contain keys
```

## 3. Linux: systemd

The repository does not ship a unit file for `ppp`; this is an example — adjust the paths:

```ini
# /etc/systemd/system/openppp2-server.service
[Unit]
Description=OPENPPP2 server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/openppp2
ExecStart=/opt/openppp2/ppp --mode=server --config=/opt/openppp2/server.json
Restart=always
RestartSec=10
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now openppp2-server
journalctl -u openppp2-server -f
```

- For a client, replace `--mode=server` with `--mode=client` (or `--mode=proxy`) and use `client.json`.
- `systemctl stop` sends SIGTERM; `ppp` exits cleanly and restores routes and DNS.
- Graceful restart (re-reads the configuration): `kill -64 <pid>`, or `openppp2 restart` in the console.
- Under systemd there is no interactive console; read output with `journalctl`, and add `--stats-json=/var/log/openppp2/stats.ndjson` for statistics.

## 4. Supervising with Guardian

Guardian (`go/guardian/`, release asset `guardian-<platform>.tar.gz` / `.zip`) is a local supervisor and configuration manager for `ppp`: automatic restarts, logs, configuration backup / rollback, and a web UI. It is a different program from the [Management backend](../guides/MANAGEMENT_BACKEND.md).

```bash
./guardian -config guardian.json
```

Example `guardian.json`:

```json
{
  "listen": "127.0.0.1:18080",
  "auth": { "enabled": true, "jwtSecret": "", "tokenExpiryHours": 24 },
  "profilesDir": "./profiles",
  "binariesDir": "./binaries",
  "backup": { "enabled": true, "maxBackups": 10, "dir": "./backups" },
  "instances": [
    {
      "name": "server",
      "enabled": true,
      "binary": "/opt/openppp2/ppp",
      "workDir": "/opt/openppp2",
      "configPath": "/opt/openppp2/server.json",
      "args": ["--mode=server", "--config=/opt/openppp2/server.json"],
      "autoRestart": { "enabled": true, "maxRetries": 0, "retryDelayMs": 3000 }
    }
  ]
}
```

- `autoRestart.maxRetries` of `0` means unlimited; `retryDelayMs` is the wait before each restart.
- **Only `args` is used to start `ppp`**; `configPath` is for management and display. Put `--mode` and `--config` in `args`.
- The web UI is on the `listen` address (local only by default). The login password is `auth.jwtSecret`; if empty at first start it is generated and written back. Protect that file as a secret; never print or commit it.
- The management API prefix is `/api/v1`. For remote access use an SSH tunnel or a TLS reverse proxy; do not expose it publicly.
- On Linux, the web UI (or `POST /api/v1/service/install`) can install Guardian itself as the systemd service `openppp2-guardian`.
- Guardian runs `ppp` in a pseudo-terminal, so the console UI and logs are viewable in the web UI.

## 5. Windows

- Run as administrator; keep the `Driver\` directory (Wintun / TAP drivers) next to `ppp.exe`.
- For start at boot, use Task Scheduler: trigger "At startup", check "Run with highest privileges", action `ppp.exe --mode=client --config=C:\openppp2\client.json`, start in the program directory.
- Stop it preferably with `openppp2 exit` or `Ctrl+C` so routes and DNS are restored.

## 6. macOS: launchd

```xml
<!-- /Library/LaunchDaemons/org.openppp2.client.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.openppp2.client</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/openppp2/ppp</string>
    <string>--mode=client</string>
    <string>--config=/opt/openppp2/client.json</string>
  </array>
  <key>WorkingDirectory</key><string>/opt/openppp2</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

```bash
sudo launchctl load -w /Library/LaunchDaemons/org.openppp2.client.plist
```

## 7. Multiple instances on one machine

Within one mode, **the same configuration file** can run only once (a second instance fails with `AppAlreadyRunning`). Different configuration files can run side by side, but:

- server instances must not share listen ports;
- multiple TUN clients need different adapter names (`--tun=`) and non-overlapping routes.

## 8. Upgrade and rollback

1. Back up the current `ppp` and configuration files.
2. Put the new version in a new directory and confirm `./ppp --help` runs; clients can try proxy mode first.
3. Stop the service → replace the executable → start; check startup output for `[security] WARN` or configuration warnings.
4. If something is wrong, restore the old executable and configuration and restart.

Read the release notes before upgrading. v2.1.7 added `client.policy` and `ppp policy`; `client.policy` cannot be mixed with legacy split fields (see [Policy v2](../guides/POLICY_CLI.md)).

## 9. Common topologies

| Topology | Reference |
|---|---|
| Single server + clients (native TCP) | [Writing the configuration file](../getting-started/CONFIGURE.md) |
| Server behind Nginx / CDN (WS / WSS) | [User manual · behind Nginx](../getting-started/USER_MANUAL.md) |
| Multiple nodes with central auth and accounting | [Management backend](../guides/MANAGEMENT_BACKEND.md) |
| Site-to-site | [Peer prefix routing](../guides/PEER_PREFIX_ROUTING.md) |

## Related documents

- [Operations and troubleshooting](OPERATIONS.md) · [Security](SECURITY.md) · [Platforms](../guides/PLATFORMS.md)
