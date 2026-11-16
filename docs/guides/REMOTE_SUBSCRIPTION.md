# Remote Subscription

> Status: Active
> Type: Guide
> Last verified: 2026-10-11 (against `go/ppp/Subscription.go` and the Android / desktop subscription parsers)
>
> **Purpose:** Subscription link format, how clients use it, and security when publishing.
> **Audience:** Operators publishing subscriptions and users consuming them.
> **Parent index:** [Guides](README.md) · **Chinese:** [远程订阅](REMOTE_SUBSCRIPTION_CN.md)

## 1. Overview

The [manager](MANAGEMENT_BACKEND.md) publishes a subscription document at `GET /sub/{token}`. Clients (Android, iOS, desktop client) import the link and turn each node in the document into a connectable profile.

The token in the link is the access credential: anyone with the link can read the document, and the document contains node keys. Treat subscription links like passwords.

## 2. Document format (v1)

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "Example subscription",
  "profilePrefix": "Example",
  "updatedAt": "2026-10-11T00:00:00Z",
  "nodes": [
    {
      "id": "server-1",
      "name": "Example node",
      "subtitle": "vpn.example.invalid:20000",
      "server": "ppp://vpn.example.invalid:20000/",
      "key": {
        "protocol": "aes-128-cfb",
        "protocol-key": "<protocol-key>",
        "transport": "aes-256-cfb",
        "transport-key": "<transport-key>"
      },
      "client": { "guid": "<GUID assigned to the user>" },
      "options": {}
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `type` / `version` | Always `openppp2-subscription` / `1`. |
| `name` / `profilePrefix` | Subscription name and node display-name prefix. |
| `updatedAt` | Generation time. |
| `nodes[].id` | Stable node identity; clients update existing profiles by it. |
| `nodes[].server` / `key` / `client.guid` | Same as the client configuration fields; see the [Configuration reference](../reference/CONFIGURATION.md). |
| `nodes[].options` | Arbitrary JSON copied from the subscription record; each client reads only the options it supports. |

Clients also accept some extra forms (such as a full `config` inside a node), but those are not a cross-platform contract; publish only the structure above. Keep documents far below 2 MiB (the client limit).

## 3. Client behavior

| Aspect | Behavior |
|---|---|
| Accepted links | Android / iOS accept HTTPS only (HTTP on loopback is for development) and limit redirects; the experimental desktop client accepts both HTTP and HTTPS. |
| Updates | Android / iOS update profiles by subscription URL + node `id`; the desktop client has its own cache logic. Handling of removed nodes is not guaranteed to match across clients. |
| Caching | The manager returns `ETag` and `Cache-Control: private, max-age=60` and honors `If-None-Match`; current clients do not send conditional requests and download the full document on each refresh. |

## 4. Publishing and security

- **Always publish over HTTPS**: the manager does not terminate TLS itself, so put a TLS proxy in front and set `admin.public-base-url` to the external HTTPS address.
- Never paste subscription links or documents into logs, tickets, screenshots, or public repositories.
- Tokens do not expire. When a user leaves or a link leaks, rotate the token (`rotate-token`) or disable the subscription in the admin UI.
- The admin API bearer token and the subscription token are different credentials.

## Related documents

- [Management backend](MANAGEMENT_BACKEND.md) · [Security](../operations/SECURITY.md)
