# Remote Subscription Format

> **Status:** Current publisher contract; client handling is platform-specific
> **Type:** Guide
> **Last verified:** Native manager publisher and bundled Android/iOS/desktop consumer sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [远程订阅格式](REMOTE_SUBSCRIPTION_CN.md)

## Scope

The native Go manager can publish an `openppp2-subscription` v1 JSON document at `GET /sub/{token}`. The URL token is an unauthenticated capability: possession grants access to the document. Treat the URL and its response as credential-bearing material.

This page describes the publisher's stable v1 shape. Client applications accept some additional compatibility fields, but those are not a portable subscription schema.

## Published v1 shape

The publisher emits these top-level fields:

| Field | Meaning |
|---|---|
| `type` | Always `openppp2-subscription` |
| `version` | Currently `1` |
| `name` | Subscription display name |
| `profilePrefix` | Optional display-name prefix |
| `updatedAt` | Publisher timestamp |
| `nodes` | Node array |

A generated compact node contains `id`, `name`, `subtitle`, `server`, `key`, `client.guid`, and `options`. `id` is generated from the manager's server record and should be treated as the stable identity used by consumers that upsert profiles.

Use placeholders, never production keys, in examples:

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "name": "Example subscription",
  "profilePrefix": "Example",
  "updatedAt": "2026-07-22T00:00:00Z",
  "nodes": [
    {
      "id": "server-1",
      "name": "Example node",
      "subtitle": "vpn.example.invalid:20000",
      "server": "ppp://vpn.example.invalid:20000/",
      "key": {
        "protocol": "aes-128-cfb",
        "protocol-key": "<provisioned-protocol-key>",
        "transport": "aes-256-cfb",
        "transport-key": "<provisioned-transport-key>"
      },
      "client": {
        "guid": "<assigned-client-guid>"
      },
      "options": {}
    }
  ]
}
```

## Publisher and client boundaries

| Topic | Current behavior |
|---|---|
| `options` | The manager copies an arbitrary JSON map from a subscription record; clients consume only the options their own code supports. Do not assume one universal options schema. |
| Extra node forms | Bundled consumers support compatibility paths such as compact nodes and full `config` objects/JSON strings. Do not rely on undocumented extras for cross-platform publication. |
| Size | The inspected bundled consumers cap documents at 2 MiB. Keep documents much smaller. |
| Refresh identity | Android/iOS upsert nodes by subscription URL plus node ID; the desktop client maintains its own subscription cache behavior. Do not infer deletion semantics from one client. |
| ETag | The manager emits ETag/cache headers, but inspected consumers do not make conditional requests. Treat ETag as publisher support, not a refresh guarantee. |

## URL and transport policy

- Android and iOS allow HTTPS subscription URLs and narrowly allow loopback HTTP development URLs; they enforce redirect limits.
- The experimental desktop client accepts both HTTP and HTTPS URLs in its current implementation.
- Therefore, an operator should publish over HTTPS regardless of the least restrictive client. Do not describe HTTPS-only behavior as universal client enforcement.

## Security and lifecycle

- Published documents can include protocol and transport keys. Do not put them in logs, issue trackers, screenshots, or public repositories.
- The public token has no expiry mechanism in the inspected publisher. Rotate it, disable/delete the subscription, or restrict network exposure when access must end.
- The native manager's admin bearer token and the public subscription token are different credentials.
- The direct Go server does not terminate TLS by itself; use an operator-managed TLS endpoint before publishing on an untrusted network.

## Related pages

- [Management backend](MANAGEMENT_BACKEND.md)
- [Security model](../operations/SECURITY.md)
- [Configuration reference](../reference/CONFIGURATION.md)