# Management Backend

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `go/ppp/Configuration.go`, `go/ppp/ManagedServer.go`, `go/ppp/Admin.go`, `ppp/app/server/VirtualEthernetSwitcher.cpp`)
>
> **Purpose:** Deploy the Go manager to publish subscriptions, manage users and nodes, and connect C++ servers for authentication and traffic accounting.
> **Audience:** Operators running several nodes or distributing subscriptions.
> **Parent index:** [Guides](README.md) · **Chinese:** [管理后端](MANAGEMENT_BACKEND_CN.md)

## 1. Two different Go programs

| Program | Directory | Purpose | Usable as C++ `server.backend`? |
|---|---|---|---|
| **Manager** | `go/` | Subscription publishing, admin UI, user / node management, optional C++ node control link | Yes (managed mode only) |
| Guardian | `go/guardian/` | Local supervisor for `ppp` processes and profiles | No |

This page covers the manager only. Their configuration files and flags are not interchangeable.

## 2. Two modes

| Mode | Condition | Capabilities |
|---|---|---|
| **Standalone** | No `database` and no `redis` in the configuration | Data in a local JSON file (default `manager-data.json`); admin UI and subscription publishing; **rejects C++ node links**. |
| **Managed** | Complete `database.master` (MySQL) and `redis` (Sentinel: `addresses` + `master`) | Everything in standalone, plus C++ server control links for user authentication and traffic accounting. Configuring only one of the two fails startup. |

## 3. Build and run

```bash
cd go
go build -o ppp-go .
./ppp-go ./manager.json
```

The first argument is the configuration path; if omitted or missing, `appsettings.json` in the current directory is read, else built-in defaults are used. Two samples are provided: `go/appsettings.json` (standalone) and `go/appsettings.managed.json` (managed; its passwords and keys are placeholders).

## 4. Configuration fields

| Field | Default | Meaning |
|---|---|---|
| `prefixes` | `:10000` | HTTP listen address. Use `127.0.0.1:10000` if it should not be public. |
| `path` | `/ppp/webhook` | WebSocket path C++ nodes connect to. |
| `key` | empty | Shared secret compared with the C++ `server.backend-key` (managed mode). |
| `admin.token` | empty | Admin API bearer token. When empty, a temporary token is generated at startup and printed to the log; the `OPENPPP2_ADMIN_TOKEN` environment variable also sets it. |
| `admin.path` | `/admin/` | Web admin UI path. |
| `admin.public-base-url` | empty | External base URL used in generated subscription links, e.g. `https://manager.example.com`. |
| `admin.data` | `manager-data.json` | Standalone data file. |
| `database` / `redis` | none | Required for managed mode; see `go/appsettings.managed.json`. |
| `interfaces` / `concurrency-control` | built-in | Managed-mode internal paths and timeouts; normally left alone. |

## 5. Connecting a C++ server (managed mode)

C++ server configuration:

```json
"server": {
  "node": 1,
  "backend": "ws://127.0.0.1:10000/ppp/webhook",
  "backend-key": "<same as the manager key>"
}
```

The link is established only when **all** of these hold:

| Condition | Why |
|---|---|
| `server.node >= 1` | The C++ server does not connect for node numbers below 1. |
| Non-empty `server.backend` | Manager WebSocket URL (`ws://` or `wss://`). |
| `server.backend-key` equals the manager `key` | Compared directly on connect. |
| A matching node record exists in the manager | The control link identifies the node by number. |
| The manager runs in managed mode | Standalone mode rejects node links. |

Once connected, the manager handles user authentication and traffic reports. The control protocol frames `[8 hex length characters][JSON]` with commands ECHO (1000), CONNECT (1001), AUTHENTICATION (1002), and TRAFFIC (1003, batched).

## 6. Admin UI and API

- Web UI: `http://<manager>/admin/`.
- Admin API: CRUD for `status`, `users`, `servers`, and `subscriptions` under `/api/v1/`, plus subscription `preview` and `rotate-token`; send `Authorization: Bearer <admin.token>`.
- Subscription publishing: `GET /sub/{token}`; format in [Remote subscription](REMOTE_SUBSCRIPTION.md).

## 7. Security

- All of these are sensitive: the admin token, `key` / `server.backend-key`, `manager-data.json`, and subscription URLs and their contents (which include node keys).
- The shared `key` is compared in constant time and may be sent as `?key=` (legacy) or `Authorization: Bearer <key>`. Prefer the header: query strings are recorded by reverse proxies and access logs, so a `?key=` value can leak there.
- A node connection is bound to the node id given at the handshake; authentication or traffic packets carrying a different `Node` are dropped and logged. A traffic report counter above 1 TiB (2^40) or not a plain non-negative integer is ignored.
- API errors return generic messages; database/Redis details are written to the server log only.
- The manager does not provide TLS itself. Put it behind a TLS-terminating proxy such as Nginx before exposing it, or bind it to a private / loopback address.
- Subscription tokens do not expire; to revoke access, rotate the token (`rotate-token`) or disable the subscription.

## Related documents

- [Remote subscription](REMOTE_SUBSCRIPTION.md) · [Configuration reference · server](../reference/CONFIGURATION.md)
- [Deployment](../operations/DEPLOYMENT.md) · [Security](../operations/SECURITY.md)
