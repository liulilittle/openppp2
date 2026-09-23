# Getting Started
> Status: Active
> Type: Index
> Last verified: 2026-07-22
>
> **Purpose:** Choose a safe, source-backed starting point for the native runtime or the experimental desktop surface.
> **Audience:** Users, operators, and contributors working in this repository.
> **Parent index:** [Documentation](../README.md) · **Chinese:** [快速开始](README_CN.md)

## Choose a path

### Run the native `ppp` runtime

Start with the paired [User Manual](USER_MANUAL.md). It covers the current native command path, configuration discovery, privilege boundary, and the next reference documents to read. The executable defaults to the server role when no `--mode` is supplied.

### Try the Desktop Client

[Desktop Client](DESKTOP_CLIENT.md) documents the Tauri/Svelte manager under `desktop/client/`. It is **experimental**, source-run oriented, and does not currently produce a bundled installer from its checked-in Tauri configuration.

### Build, test, or read the source

- [Development](../development/README.md) — native build prerequisites and contributor entry points.
- [Source Reading Guide](../development/SOURCE_READING_GUIDE.md) — follow the real application startup and runtime paths.
- [Testing](../development/TESTING.md) — choose the standalone, root-CMake, coverage, or component test entry point.

## When you need detail

| Task | Canonical page |
|---|---|
| JSON settings and defaults | [Configuration](../reference/CONFIGURATION.md) |
| Command-line options | [CLI reference](../reference/CLI_REFERENCE.md) |
| Routing and DNS behavior | [Routing and DNS](../guides/ROUTING_AND_DNS.md) |
| Platform constraints | [Platforms](../guides/PLATFORMS.md) |
| Deployment and operations | [Deployment](../operations/DEPLOYMENT.md) · [Operations](../operations/OPERATIONS.md) |

## Documentation boundary

Pages marked **Active** describe the current tree; the Desktop Client is explicitly marked **Experimental**. Dated technical audits in the development section are evidence for review, not current runtime instructions.
