# Go core control-plane implementation map

> [Go overview](../debug.md) · [中文](debug_CN.md) · [Infrastructure](../io/debug.md)

**Status:** Experimental internal implementation

**Type:** Root Go service and management-plane source map

**Last verified:** 2026-07-22

`go/ppp/` owns the root Go service's management-plane behavior. It is coupled to the configuration, storage, websocket protocol, and embedded admin UI in this tree. It is not a supported importable API.

## Entry and lifecycle

`go/main.go` creates `ppp.NewManagedServer()`, attaches signal handling, and calls `ListenAndServe()`.

`ManagedServer` is constructed from `ManagedServerConfiguration` and owns:

- the configured websocket/HTTP server;
- managed-mode Redis and MySQL connections, or a standalone `LocalStore`;
- in-memory server, node, user, and dirty-state maps;
- the embedded admin/subscription HTTP handler.

On managed startup, `ListenAndServe()` loads servers and users, starts the server tick, then listens. On disposal it closes the HTTP/websocket server, closes nodes, and attempts final user archival only in managed mode.

## Configuration modes

`Configuration.go` makes the mode boundary explicit:

| Configuration state | Result |
|---|---|
| Complete database master + Redis Sentinel configuration | Managed mode: database/cache-backed server and node behavior. |
| No database and no Redis configuration | Standalone `LocalStore` subscription/admin mode. Node websocket connections are rejected. |
| Partial database/Redis configuration | Startup configuration error. |

The first positional process argument selects a configuration file. The loader otherwise tries `appsettings.json`. Treat all database, Redis, key, and admin token fields as secrets.

## Request and protocol ownership

`ManagedServer.request()` routes requests in this order:

1. embedded admin API/UI and public subscription paths;
2. legacy/configured consumer and server HTTP interfaces in managed mode;
3. `404` otherwise.

`Admin.go` registers the current `/api/v1/` management groups for status, users, servers, subscriptions, and the public `/sub/{token}` route. This page intentionally does not freeze individual payload fields or turn those internal handlers into an external API contract.

`ManagedServer.accept()` reads an initial websocket packet and accepts only an expected connect command with a valid node identifier. `run()` then dispatches echo, authentication, and traffic packet processing to the handlers in this package. `Packet.go`, `Node.go`, `User.go`, `Server.go`, and `Traffic.go` divide the corresponding encoding, node, user/cache, server, and traffic work.

## Storage and synchronization

- `User.go` and `Traffic.go` participate in quota/traffic and cache synchronization.
- `Server.go` loads and caches server records.
- `LocalStore.go` backs the standalone admin/subscription path instead of the managed database/Redis path.
- `../io/DB.go` uses GORM/MySQL; `../io/RedisClient.go` uses Redis failover/Sentinel settings.

When diagnosing an apparent node/authentication issue, identify the mode first. A local-store service cannot accept managed nodes, while a managed service can fail because of database, Redis, cache, or configuration state before a protocol handler is at fault.

## Operational cautions

- Default listen settings are not a security boundary. The websocket upgrader in `../io/WebSocket.go` accepts all Origins and this service layer does not add TLS.
- The admin handler checks Bearer tokens for `/api/v1/` operations. A configured `admin.token` or `OPENPPP2_ADMIN_TOKEN` is preferable to relying on a generated token emitted to logs.
- `/sub/{token}` is intentionally a public-subscription route and needs a separately reviewed exposure policy.
- Do not use source-level handler names or package structures as a stable SDK contract.

For startup/security context see the [Go overview](../debug.md); for connector behavior see [the infrastructure map](../io/debug.md).
