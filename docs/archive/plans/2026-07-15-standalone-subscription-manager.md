# Standalone Subscription Manager Implementation Plan
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Go manager and `/admin/` frontend start without arguments or external services, persist subscriptions locally, and add managed PPP capabilities only when a complete legacy configuration is present.

**Architecture:** `ManagedServer` remains the single HTTP/WebSocket host. A small mutex-protected JSON store backs node templates and subscriptions when MySQL/Redis are absent; existing database paths remain unchanged when managed configuration is complete. Existing API paths are reused so the embedded frontend only switches labels and GUID input based on a `managed` status flag.

**Tech Stack:** Go 1.22 standard library, existing GORM/Redis managed path, embedded HTML/CSS/JavaScript, Go tests.

---

### Task 1: Default startup and local store

**Files:**
- Create: `go/ppp/LocalStore.go`
- Create: `go/ppp/LocalStore_test.go`
- Modify: `go/ppp/Configuration.go`

- [ ] Write failing tests proving a missing config produces standalone defaults and a temporary JSON store survives save/reload with stable admin token, node IDs, subscription IDs, and tokens.
- [ ] Run `go test ./ppp -run 'Test(DefaultStandaloneConfiguration|LocalStore)' -count=1` and confirm failure because the store/default APIs do not exist.
- [ ] Implement `LocalStore` with `sync.Mutex`, versioned JSON, same-directory temporary write, `os.Rename`, input validation, and copy-returning CRUD methods.
- [ ] Change config loading so no file returns `:10000`, `/ppp/webhook`, `/admin/`, and `manager-data.json`; classify absent external settings as standalone and reject partially configured managed storage.
- [ ] Re-run the focused tests and confirm pass.

### Task 2: Optional managed runtime

**Files:**
- Modify: `go/ppp/ManagedServer.go`
- Modify: `go/ppp/Server.go`
- Test: `go/ppp/LocalStore_test.go`

- [ ] Write a failing test for managed-capability detection with empty, complete, and partial database/Redis settings.
- [ ] Run the focused test and confirm failure.
- [ ] Add `managed bool` and `local *LocalStore` to `ManagedServer`; connect Redis/MySQL and start accounting only when managed configuration is complete.
- [ ] Keep the WebSocket listener on the same port in standalone mode but reject `/ppp/webhook` connections before any database access.
- [ ] Re-run focused and full Go tests.

### Task 3: Local admin and subscription APIs

**Files:**
- Modify: `go/ppp/Admin.go`
- Modify: `go/ppp/Subscription.go`
- Modify: `go/ppp/Admin_test.go`

- [ ] Write failing handler/store tests for standalone status, empty users, node CRUD, subscription CRUD, preview generation, public token access, and token rotation invalidating the old token.
- [ ] Run the focused tests and confirm the standalone branches are missing.
- [ ] Branch existing handlers on `my.local != nil`: local status and node/subscription operations use `LocalStore`; user endpoints return an empty list or managed-unavailable response; document generation uses the subscription GUID directly.
- [ ] Preserve current database handlers byte-for-byte where practical and keep admin/public authentication behavior unchanged.
- [ ] Run focused tests, `go test -race ./...`, and `go vet ./...`.

### Task 4: One adaptive WebUI

**Files:**
- Modify: `go/ppp/webui/app.js`
- Modify: `go/ppp/webui/index.html`
- Modify: `go/ppp/webui/app.css`
- Test: `go/ppp/Admin_test.go`

- [ ] Write a failing embedded-asset test asserting the frontend consumes `status.managed` and offers direct GUID input in standalone mode.
- [ ] Run the focused test and confirm failure.
- [ ] Hide Users navigation when unmanaged, relabel PPP Nodes to Subscription Nodes, remove online-state presentation for local templates, and replace the subscription user selector with validated GUID input.
- [ ] Keep the same `/admin/` route, dialogs, preview, copy, edit, delete, and token-rotation interactions.
- [ ] Run the asset test and `node --check go/ppp/webui/app.js`.

### Task 5: Defaults, docs, and end-to-end verification

**Files:**
- Modify: `go/appsettings.json`
- Create: `go/appsettings.managed.json`
- Modify: `docs/MANAGEMENT_BACKEND.md`
- Modify: `docs/MANAGEMENT_BACKEND_CN.md`

- [ ] Make shipped `go/appsettings.json` standalone and move the existing Redis/MySQL example to `go/appsettings.managed.json`.
- [ ] Document no-argument startup, `manager-data.json`, optional managed activation, and unchanged C++ compatibility in English and Chinese.
- [ ] Run `go test -race ./...`, `go vet ./...`, `go build -mod=readonly`, `node --check`, and diff whitespace validation.
- [ ] Start the real standalone binary on an unused local port or the default port, verify `/admin/`, create a subscription through HTTP, fetch `/sub/{token}`, restart, and verify persistence.
