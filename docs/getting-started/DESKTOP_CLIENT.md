# Desktop Client
> Status: Experimental
> Type: Guide
> Last verified: 2026-07-22
>
> **Purpose:** Run and evaluate the repository's Tauri/Svelte client manager against a local `ppp` executable.
> **Audience:** Desktop developers and evaluators.
> **Parent index:** [Getting Started](README.md) · **Chinese:** [桌面客户端](DESKTOP_CLIENT_CN.md)

## Status and boundary

The Desktop Client lives in `desktop/client/` and is an **experimental** Tauri 2 + Svelte surface. Its checked-in Tauri configuration has bundling disabled, so this guide describes source-run evaluation rather than a supported installer or release package.

The client creates a runtime configuration from stored preferences and a selected node, then starts `ppp` with:

```text
--mode=client --config=<runtime appsettings.json> --stats-json=<runtime stats.ndjson>
```

The generated files are placed in the application data runtime directory; do not edit them as a durable source of configuration.

## Prerequisites

- Node.js/npm for the frontend scripts.
- Rust/Cargo and the platform requirements needed by the Tauri shell.
- A built native `ppp` executable from this repository, or another compatible local executable you explicitly select.

The source does **not** search `PATH` when the `pppPath` setting is empty. In that case it looks for `ppp.exe` on Windows or `ppp` elsewhere beside the Desktop Client executable. During source-based development, set `pppPath` in Settings to the actual executable file unless you intentionally arrange that sibling layout.

## Frontend checks and development

From `desktop/client/`:

```bash
npm ci
npm test
npm run build
```

`npm run dev` starts the Vite frontend. The Tauri configuration uses `http://127.0.0.1:1420` as its development URL, so keep an appropriate frontend development server available when evaluating the shell.

```bash
npm run dev
```

## Tauri shell

The package script below is a raw Cargo invocation of the `openppp2-client-app` binary:

```bash
npm run desktop
```

It requires Cargo and does not turn the checked-in Tauri configuration into a packaged application. Treat it as a local development path. The Rust crate also has its own test entry point when Cargo is available:

```bash
cargo test --manifest-path src-tauri/Cargo.toml
```

## Runtime behavior to expect

- Subscription and manual-node data are merged into a generated runtime configuration before connection.
- The process manager discards the child process's standard output and captures standard error for classification; the UI is not a complete process-output console.
- Runtime statistics are read from the generated NDJSON path supplied with `--stats-json`.
- Connecting affects a native client process. Follow the [User Manual](USER_MANUAL.md) and platform/operations documentation before using a non-proxy network mode on a real host.

The repository's primary unit-test workflow does not currently run the Desktop Client's `npm test` or Cargo test commands. Run the relevant local checks when changing this surface.

## Related material

- [User Manual](USER_MANUAL.md)
- [Development](../development/README.md)
- [Testing](../development/TESTING.md)
- [Desktop design notes (Chinese)](../design/SUB_CLIENT_DESIGN_CN.md)
- [Project interface map](../reference/PROJECT_INTERFACE_MAP.md)
