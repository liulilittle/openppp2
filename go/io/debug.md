# Go infrastructure implementation map

> [Go overview](../debug.md) · [中文](debug_CN.md) · [Core service](../ppp/debug.md)

**Status:** Experimental internal implementation

**Type:** Storage, Redis, WebSocket, and file utility source map

**Last verified:** 2026-07-22

`go/io/` contains helpers used by the root Go control plane. It is not a stable library package and should not be treated as a general-purpose database or WebSocket abstraction.

## Current components

| File | Current responsibility |
|---|---|
| `DB.go` | Opens MySQL through GORM, exposes the underlying GORM handle, configures the SQL pool, and recognizes duplicate-key errors. |
| `RedisClient.go` | Creates a Redis failover client from Sentinel/master settings and wraps selected cache/set/hash/lock operations. |
| `WebSocket.go` | Hosts the root HTTP server, upgrades requests on the configured websocket path, tracks connections, and provides HTTP helper functions. |
| `File.go` | File/path helpers used by root service configuration loading. |

## Important behavior

### MySQL/GORM

`ConnectDB` builds a MySQL DSN from configuration, opens GORM, and sets max open/idle connections plus connection lifetime. The caller chooses master versus slave use through the core service; this package does not provide independent migration/configuration policy.

### Redis Sentinel

`NewRedisClient` constructs a Redis failover client using `master`, `addresses`, `password`, and `db`. Cache behavior and lock use are implementation details of the core service. Connection failures or cache inconsistency can surface as user/node/traffic problems farther up the stack.

### HTTP and WebSocket

`NewWebSocketServer` binds the configured listen prefix, sends non-websocket requests to the caller's HTTP handler, and upgrades matching websocket-path requests through Gorilla WebSocket.

The current Gorilla upgrader's `CheckOrigin` returns true. This is a material security limitation: do not assume origin checking, TLS, or authenticated HTTP exposure is provided by `go/io`. Bind addresses, TLS termination, authentication, and firewall policy belong to the caller/deployment boundary.

## Debug order

1. Confirm which root-service mode is active: standalone local store or managed MySQL/Redis mode.
2. Confirm configuration and network reachability before changing handler logic.
3. For MySQL failures, inspect the configured connection/pool and GORM error at the caller.
4. For Redis failures, inspect Sentinel/master reachability and the cache state used by `go/ppp`.
5. For websocket failures, distinguish an HTTP routing mismatch from an upgrade/connection failure.

Do not add external callers to these helpers without first defining a supported interface and security contract. See [the core service map](../ppp/debug.md) for the code that owns their business behavior.
