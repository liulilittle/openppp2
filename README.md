# OPENPPP2

> Status: Current
> Type: Navigation
> Last verified: 2026-07-22
> Documentation index: [Documentation by task](docs/README.md) · Chinese: [简体中文](README_CN.md)

English | [简体中文](README_CN.md)

OPENPPP2 is a C++ network runtime. The root CMake project builds the native `ppp` executable and the static `openppp2_lib` library. This page is a concise repository entry point; use the current task pages below for configuration, operation, and implementation detail.

## Start by task

| Need | Start here |
|---|---|
| Build and make a first run | [Getting started](docs/getting-started/README.md) |
| Configure `ppp` or inspect its command line | [Configuration reference](docs/reference/CONFIGURATION.md) · [CLI reference](docs/reference/CLI_REFERENCE.md) |
| Configure routing, DNS, proxy behavior, or a platform | [Guides](docs/guides/README.md) |
| Deploy, observe, or troubleshoot a runtime | [Operations](docs/operations/README.md) |
| Understand runtime structure and lifecycle | [Startup and lifecycle](docs/architecture/STARTUP_AND_LIFECYCLE.md) |
| Read or change the source safely | [Source reading guide](docs/development/SOURCE_READING_GUIDE.md) |
| Check which interfaces are stable, experimental, internal, or incomplete | [Project interface map](docs/reference/PROJECT_INTERFACE_MAP.md) |

## `ppp` startup chain

For a normal runtime invocation, the native process follows this path:

```text
main.cpp
  -> ppp::facade::RunApplication()
  -> PppApplication::GetInstance().Run()
  -> PreparedArgumentEnvironment()
  -> Executors::Run()
  -> RunPreparedApplication()
  -> PppApplication::Main()
```

Argument preparation loads the configuration, resolves the application mode, and prepares the network-interface context. The normal path then enters `Main()`, which performs host preflight and starts the selected client, server, or proxy runtime. See [Startup and lifecycle](docs/architecture/STARTUP_AND_LIFECYCLE.md) for the implementation-level sequence and shutdown behavior.

## Core and companion surfaces

- **Core native runtime:** `main.cpp`, `ppp/`, `common/`, and the Windows, Linux, or Darwin platform sources selected by the root CMake build.
- **Tests:** the root project includes `tests/` only when configured with `-DENABLE_TESTS=ON`; use the [development documentation](docs/development/README.md) for supported test workflows.
- **Separate, platform-specific surfaces:** `go/` and `go/guardian/` are Go modules; `android/` contains the in-tree Flutter application and Android/NDK build files; `ios/` contains a Swift package target; and `desktop/client/` has separate Svelte/Vite and Tauri manifests. Root CMake does not build these surfaces. Read their local documentation and manifests before treating one as a production deployment path.

## Current versus historical documentation

The linked task pages are the current navigation path. Material under `docs/archive/`, `docs/adr/`, and `docs/design/` preserves historical rationale, decisions, and evidence; it is not a substitute for current configuration, CLI, or operations guidance. These navigation pages are an English/Chinese pair; use each current page’s status, language-peer, and parent-index metadata before relying on it.
