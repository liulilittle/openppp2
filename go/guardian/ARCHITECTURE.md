# OpenPPP2 Guardian architecture

> [Go overview](../debug.md) · [中文](ARCHITECTURE_CN.md)

**Status:** Experimental operator surface

**Type:** Local/remote process, profile, and binary manager

**Last verified:** 2026-07-22

Guardian is a separate Go 1.22 module under `go/guardian`. It supervises configured `ppp` child processes and provides REST, Server-Sent Events (SSE), an embedded Web UI, and a separate terminal UI client. It does not change the C++ runtime and is not a stable public management API.

## Startup and persisted state

`main.go` accepts `-config` (default `guardian.json`), resolves it to an absolute path, loads configuration, creates the managers/API server, starts enabled instances, and shuts down on interrupt/SIGTERM.

On first run, a missing config uses `DefaultConfig()`:

- listens on `127.0.0.1:18080`;
- enables authentication by default;
- uses a 24-hour token expiry and a generated JWT secret when one is absent;
- defaults profiles, binary records, and backups to directories relative to the config location;
- keeps 2,000 log lines by default.

The generated secret is persisted to `guardian.json`; `SaveConfigFile` writes the config with `0600` mode. Treat that file, profile files, and instance environment maps as sensitive operational data. Existing relative paths are resolved relative to the config file directory.

## Component map

| Component | Responsibility |
|---|---|
| `guardian.go`, `config.go` | Orchestrate configuration and the instance/profile/binary managers. |
| `instance/` | Child lifecycle, output/log buffering, optional auto-restart and health checks, event/log subscriptions, and platform process behavior. |
| `profile/` | Profile validation, persistence, backups, restore, and retention. |
| `binary/` | Registered binary records and best-effort binary discovery. |
| `api/` | HTTP routing, auth, REST handlers, SSE streams, static-Web-UI serving, and Linux systemd integration entry points. |
| `webui/` | Svelte/Vite Web UI source. `webui.go` embeds built `webui/dist/*` assets. |
| `cmd/tui/` | Separate Go module that calls the Guardian API and consumes its SSE streams. |

`NewGuardian` also attempts best-effort automatic discovery in several working-directory/system locations. Treat discovery results as host-dependent; explicitly register and validate the binary needed by an instance.

## API and stream boundary

The router exposes groups for:

- login, token refresh, and password changes;
- instances and instance logs;
- profiles, validation, backups, and restore;
- registered/discovered binaries;
- Guardian configuration and status;
- Linux systemd service status/install/uninstall;
- instance-log and global-event SSE streams.

Auth is enabled by default. Ordinary protected `/api/` endpoints require a valid in-memory issued Bearer token. `/api/v1/status` is intentionally public. SSE routes perform their own token/JWT check when authentication is enabled, accepting a query `token` or Bearer header; the generic middleware exemption for SSE is therefore not an unauthenticated-stream guarantee.

CORS currently allows `*`, and Guardian does not configure TLS. Keep the default loopback bind unless a reviewed network boundary provides TLS, authentication, authorization, and exposure controls.

## Web UI and TUI build boundary

`webui.go` requires built `webui/dist/*` files at Go compile time. This checkout contains the Svelte/Vite source and package lock, not a committed `dist` directory. Build it before building/testing Guardian packages that compile the embed declaration:

```sh
cd go/guardian/webui
npm ci
npm run build

cd ..
go test ./...
go run . -config ./guardian.json
```

The terminal UI under `cmd/tui/` is a separate Go module. Build/test it from its own directory and pass a Guardian API URL/token as appropriate; do not assume it runs an embedded Guardian instance.

## Platform and operational limits

- Enabled instances are started at Guardian startup. Create/test profiles and binaries before enabling automatic startup.
- Instance stop/restart/profile writes can affect live child processes and configuration; use backups and a maintenance window.
- Systemd service installation is implemented only on Linux and requires root. Non-Linux service handlers report unsupported behavior.
- Guardian's log/status data is an operator aid, not a replacement for protocol-level observability or a stable SDK telemetry contract.
- No feature in this document guarantees multi-host security, a production service manager, or safe remote exposure.

For the root Go control plane, which is a different service and configuration model, see [the Go overview](../debug.md).
