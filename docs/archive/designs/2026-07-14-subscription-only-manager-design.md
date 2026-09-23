# Subscription-Only Manager Design
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


## Goal

Run the existing Go management WebUI as a standalone OpenPPP2 subscription publisher without
MySQL, Redis, or a C++ `ppp` `server.backend` connection.

## Startup

- Running the Go executable with no arguments always starts `/admin/`, `/api/v1/*`, and `/sub/*`.
- Subscription management always uses a local `manager-data.json` file and has no external dependency.
- If the existing configuration contains valid MySQL, Redis, and managed-server settings, the same
  process additionally enables WebSocket authentication, accounting, managed users, and online state.
- With no managed configuration, no C++ control link is created and C++ `ppp` configuration is never
  read or modified.
- The existing optional positional configuration-file argument remains supported for old managed
  deployments; it is not required for subscription publishing.

## Local Data

`manager-data.json` stores:

- the generated admin token and public base URL;
- subscription nodes, including `ppp://` address and cryptographic key fields;
- subscription records, including GUID, selected node IDs, profile prefix, options, enabled state,
  and public token.

Writes use a process mutex, a temporary file in the same directory, and atomic rename. A failed
write leaves the previous file intact. The service rejects malformed input and duplicate IDs or
tokens at load time.

## WebUI

The existing `/admin/` frontend is reused.

- Subscription and PPP management live in the same `/admin/` frontend.
- Without managed configuration, Users and managed-node online state are hidden.
- PPP Nodes is labeled Subscription Nodes and edits local node templates when no managed backend is
  configured.
- The subscription editor accepts a GUID directly, selects local nodes, edits mobile options,
  previews the generated document, and rotates the public token.
- The published format remains `openppp2-subscription` version 1.

## HTTP Surface

- `GET /api/v1/status`
- CRUD `/api/v1/servers` for local subscription nodes
- CRUD `/api/v1/subscriptions`
- `POST /api/v1/subscriptions/{id}/rotate-token`
- `GET /api/v1/subscriptions/{id}/preview`
- `GET /sub/{token}`

Admin endpoints keep Bearer-token authentication. Public subscription URLs use their random token.
Managed-only user endpoints return `404` when managed configuration is absent.

## Compatibility

Managed-server protocol commands `1000` through `1003` and legacy `/ppp/*` endpoints are untouched.
Existing managed deployments continue using their current configuration. Default standalone startup
has no effect on old C++ servers because no control link is created.

## Tests

- JSON load, validation, atomic persistence, and reload.
- Node and subscription CRUD.
- GUID and key injection into generated subscriptions.
- Token rotation invalidates the old URL.
- Admin authentication and public subscription access.
- Managed-server Go tests remain green.
- WebUI syntax and mode-specific rendering checks.
