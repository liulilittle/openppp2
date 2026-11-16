# OpenPPP2 Go control-plane surfaces

> [中文](debug_CN.md) · [Core service](ppp/debug.md) · [Infrastructure](io/debug.md) · [Local daemon](daemon/README.md) · [Guardian](guardian/ARCHITECTURE.md)

**Status:** Experimental and internal

**Type:** Go control-plane, local-operation, and process-management surfaces

**Last verified:** 2026-07-22

`go/` contains several separate Go programs and packages. They support management/control-plane work; they do not implement the VPN data path and are not published as a stable Go SDK.

## Surface map

| Surface | Purpose | Current boundary |
|---|---|---|
| Root module (`main.go`, `ppp/`, `io/`) | Node control plane, managed users/servers, subscription/admin HTTP routes, and websocket node traffic. | Experimental internal service. |
| `daemon/` | Manages one local `ppp` child process and exposes a small HTTP UI/API. | Unauthenticated local operator tool; do not expose it to a network. |
| `guardian/` | Multi-instance process/profile/binary manager with REST, SSE, embedded Web UI, and a separate TUI client. | Experimental operator surface, defaulting to loopback and token auth. |

The root `go.mod` declares Go 1.22 and external dependencies including GORM/MySQL, Redis Sentinel support, Gorilla WebSocket, and UUID handling. The root service is not a stdlib-only component.

## Root control-plane modes

`ppp.NewManagedServer()` loads a configuration path from the first positional process argument. If none is supplied, it falls back to `appsettings.json` and then default values where the loader permits them.

### Managed mode

Managed mode is enabled only when configuration supplies both:

- a complete `database.master` section; and
- Redis Sentinel addresses plus a master name.

In this mode the service initializes database/Redis-backed users and servers, accepts node websocket connections, and runs its periodic server work.

### Standalone local-store mode

If neither database nor Redis is configured, the service opens a local subscription manager based on `admin.data` (default `manager-data.json`). This is not a degraded database-backed node service: the websocket acceptor closes node connections in standalone mode. It is intended for local server/subscription administration only.

A partial database/Redis setup is invalid; it is not interpreted as standalone mode.

## Local checks and startup

From `go/`, use non-mutating source checks first:

```sh
go test ./...
```

To run the root service, give the configuration file as the first positional argument when one is needed:

```sh
go run . ./path/to/control-plane.json
```

Startup may contact configured Redis/MySQL services or create/read local management data. Use a disposable configuration for development and never commit passwords, database credentials, admin tokens, or real subscription links.

## Security boundary

The root service is not documented here as production-hardened:

- Its default listen prefix is `:10000`; review the bind address before starting it outside a local environment.
- The Gorilla WebSocket upgrader currently accepts every Origin, and this layer does not configure TLS.
- `/api/v1/*` admin operations use a Bearer token. Set `admin.token` or `OPENPPP2_ADMIN_TOKEN` deliberately; when the service needs to generate a token, it logs it.
- Public subscription routes are intentionally separate from authenticated admin routes.
- Database, Redis, configuration, and cache state can all influence observed authentication/traffic behavior.

Place a reviewed network boundary, TLS termination, authentication policy, and secret handling in front of any non-local deployment. That work is outside the guarantees of these internal documents.

## Read by responsibility

- [Core service](ppp/debug.md): configuration modes, websocket lifecycle, admin/subscription handler boundary, and source entry points.
- [Infrastructure](io/debug.md): MySQL/GORM, Redis Sentinel, WebSocket, and file helpers.
- [Single-instance daemon](daemon/README.md): intentionally local process wrapper with no authentication.
- [Guardian](guardian/ARCHITECTURE.md): independently configured multi-instance manager with its own module, auth, Web UI, and TUI.

The paths and interfaces described here are implementation maps, not compatibility promises.
