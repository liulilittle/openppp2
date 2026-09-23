# OpenPPP2 desktop client

**Status:** Experimental

**Type:** Tauri 2, Rust, and Svelte desktop client

**Last verified:** 2026-07-22

`desktop/client/` is an experimental graphical client in this OpenPPP2 tree. It is a development surface, not a released installer: `src-tauri/tauri.conf.json` sets `bundle.active` to `false`.

## Architecture

| Layer | Current responsibility |
|---|---|
| `client/src/` | Svelte/Vite UI, routes, client-side runtime state, and Tauri bridge calls. |
| `client/src-tauri/src/` | Rust Tauri commands, subscription/config parsing, preference persistence, process control, latency probing, telemetry parsing, and tray lifecycle. |
| External `ppp` executable | Runs the selected client configuration. It is not bundled by this desktop project. |

The client is not a replacement for the native runtime. It prepares a configuration, starts a separate `ppp` process, and renders the process's stderr telemetry and stats-file output.

## Development commands

From `desktop/client/`, install the JavaScript dependencies recorded by the lock file and run the source checks:

```sh
npm ci
npm test
cargo test --manifest-path src-tauri/Cargo.toml
```

The existing desktop development command is:

```sh
npm run desktop
```

It invokes Cargo with `--no-default-features`; Vite/Cargo/Tauri development behavior remains host-toolchain dependent. `npm run build` produces the frontend distribution used by the Tauri configuration, but this checkout does not define an active application-bundle workflow.

## Runtime requirements and process model

A usable `ppp` executable must be supplied separately. The Rust client resolves it in this order:

1. the user-configured `pppPath` setting; or
2. `ppp` on Unix / `ppp.exe` on Windows beside the desktop executable.

The client writes a runtime `appsettings.json` and `stats.ndjson` under its platform application-data directory, then launches one child process with at least:

```text
--mode=client
--config=<runtime appsettings.json>
--stats-json=<runtime stats.ndjson>
```

Validated launch options can add TUN IP/mask/gateway, DNS, mux/mux-mode, virtual-network, QUIC-blocking, and static-mode arguments. The process manager permits only one active child. On stop it requests SIGTERM on Unix or uses `taskkill` on Windows, waits briefly, then force-kills a still-running process.

The desktop client discards the child stdout stream, reads stderr as telemetry, reads supported records from `stats.ndjson`, and reports exit events to the UI. A visible “connected” state is derived from parsed process events; it is not an independent protocol guarantee.

## Nodes, subscriptions, and preferences

The UI supports manual nodes, favorites, subscription nodes, latency probes, raw configuration, launch options, and tray behavior. Preferences and subscription cache are stored under Tauri's app-data directory rather than in the repository.

Subscription refresh behavior is deliberately constrained:

- only `http` and `https` URLs are accepted;
- fetches use a 15-second timeout and a maximum body size of 2 MiB;
- the document must have `type: "openppp2-subscription"` and `version: 1`;
- each enabled node must provide either a JSON-object configuration or a valid `ppp://` server plus a non-empty key object;
- on a failed refresh, a cached document is usable only when it belongs to the same URL.

The implementation accepts HTTP for compatibility; prefer HTTPS for real subscription endpoints. Subscription and manual-node content can influence the configuration sent to the local `ppp` child, so review it before connecting and do not commit tokens or private endpoints.

## Limitations and security boundary

- There is no bundled `ppp` binary, installer, release packaging, or documented elevation workflow in this directory.
- This client does not make an external `ppp` build compatible; its executable, platform behavior, configuration, and privileges must be validated separately.
- The application data/cache can contain selected node metadata and configuration. Treat that data as sensitive on shared machines.
- HTTP subscription retrieval and process launching are powerful local operations. Use trusted inputs and test with non-production credentials.
- The code and tests describe the current experimental behavior; they do not establish a stable desktop API or production-support guarantee.
