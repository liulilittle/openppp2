# Management Backend

> **Status:** Current implementation boundary
> **Type:** Guide
> **Last verified:** Native Go manager, C++ managed-link, admin, and subscription sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [管理后端](MANAGEMENT_BACKEND_CN.md)

## Choose the correct Go surface

This tree contains two separate Go programs:

| Surface | Role | C++ `server.backend` compatible? |
|---|---|---|
| Native manager at `go/` | Subscription publishing, admin API, and optional managed C++ control link | Yes, only in managed mode |
| Guardian at `go/guardian/` | Separate process/profile manager | No; it is not the native C++ backend endpoint |

Do not mix their flags or configuration schemas. In particular, native manager configuration is selected by its first positional argument; Guardian's `--config` belongs to Guardian.

## Native manager modes

The native manager has two distinct modes:

- **Standalone subscription manager:** no complete external database/Redis setup. It persists local data (default `manager-data.json`) and serves its admin/subscription surfaces, but rejects native C++ node control WebSocket links.
- **Managed mode:** uses the configured database/Redis shape and accepts native C++ managed links. This is the mode required by `server.backend`.

The default listener/path values are `:10000` and `/ppp/webhook`. Bind an explicit loopback or management address when public access is not intended.

## C++ managed-link prerequisites

All of these conditions are required before expecting a C++ server to use the native manager:

| Requirement | Why it matters |
|---|---|
| `server.node >= 1` | The C++ server does not open the managed link for node values below one. |
| Nonempty `server.backend` | Gives the native manager WebSocket URL. |
| Matching `server.backend-key` and Go top-level `key` | CONNECT compares these values directly. |
| Matching server/node record in the manager | The control link identifies a specific node. |
| Native manager in managed mode | Standalone mode rejects node control links. |

A C++ configuration fragment can safely use placeholders:

```json
{
  "server": {
    "node": 1,
    "backend": "ws://127.0.0.1:10000/ppp/webhook",
    "backend-key": "<shared-manager-key>"
  }
}
```

The Go manager must use the same path/key and be started before relying on managed authentication. Do not use a standalone-only configuration as evidence that the C++ link is active.

## What travels over the control link

The native protocol frames JSON as:

```text
[8 hexadecimal length characters][JSON]
```

Packet fields are `Id`, `Node`, `Guid`, `Cmd`, and `Data`. The implemented command set is ECHO (1000), CONNECT (1001), AUTHENTICATION (1002), and TRAFFIC (1003).

CONNECT establishes the C++ node-to-manager link before user authentication. TRAFFIC is batch reporting; this protocol does not define a `SessionEnd` command or a direct per-tick SQL update contract.

## Admin and subscription surfaces

The manager implements bearer-token-protected `/api/v1/` status and CRUD routes for users, servers, and subscriptions, plus token rotation/preview. `GET /sub/{token}` publishes a subscription document through an unauthenticated capability URL.

Treat all of the following as secrets or sensitive control material:

- the admin bearer token;
- the native manager `key` / C++ `server.backend-key`;
- `manager-data.json` when used;
- public subscription URLs and their generated documents, because published nodes can contain tunnel key material.

The direct Go HTTP server does not add TLS itself. Use a trusted network binding or operator-managed TLS termination before making admin or subscription surfaces publicly reachable.

## Run boundary

The native manager is built from `go/` using its Go module, for example:

```bash
cd go
go build -o ppp-go .
./ppp-go ./manager.json
```

The positional path is optional; when omitted, the manager looks for `appsettings.json` and then uses defaults. Verify whether that configuration selects standalone or managed mode before connecting a C++ server.

## Related pages

- [Remote subscription format](REMOTE_SUBSCRIPTION.md)
- [Deployment model](../operations/DEPLOYMENT.md)
- [Security model](../operations/SECURITY.md)
- [Configuration reference](../reference/CONFIGURATION.md)