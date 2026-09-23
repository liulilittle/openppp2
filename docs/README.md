# Documentation by Task

> Status: Current
> Type: Navigation
> Last verified: 2026-07-22
> Parent index: [Repository README](../README.md) · Chinese: [按任务查找文档](README_CN.md)

[中文版](README_CN.md)

Use this page to choose the current documentation for the native `ppp` tree. Follow the linked category pages instead of treating this index as a configuration or operations reference.

## First-use path

1. [Build and first run](getting-started/USER_MANUAL.md)
2. [Configuration reference](reference/CONFIGURATION.md) and [CLI reference](reference/CLI_REFERENCE.md)
3. [Operational checklist and troubleshooting](operations/OPERATIONS.md)

## Browse by task

| Task | Canonical current page |
|---|---|
| Installation, local build, and first verification | [Getting started](getting-started/README.md) |
| Configuration fields, CLI behavior, errors, and protocol formats | [Reference](reference/README.md) |
| Routing, DNS, proxy mode, management, IPv6, and platforms | [Guides](guides/README.md) |
| Deployment, security, monitoring, and incident response | [Operations](operations/README.md) |
| Runtime, transport, protocol, concurrency, and source-level architecture | [Architecture](architecture/README.md) |
| Source reading, builds, tests, and compatibility | [Development](development/README.md) |
| Interface status, implementation boundaries, and known gaps | [Project interface map](reference/PROJECT_INTERFACE_MAP.md) |

Runtime consumers should also follow the [UI runtime contract](reference/UI_RUNTIME_CONTRACT.md) and its [Chinese peer](reference/UI_RUNTIME_CONTRACT_CN.md).

## Runtime orientation

The normal native startup path is:

```text
main.cpp
  -> ppp::facade::RunApplication()
  -> PppApplication::GetInstance().Run()
  -> PreparedArgumentEnvironment()
  -> Executors::Run()
  -> RunPreparedApplication()
  -> PppApplication::Main()
```

The root CMake project creates `ppp` and `openppp2_lib`; it adds `tests/` only when `-DENABLE_TESTS=ON`. The application preparation step loads configuration and resolves client, server, or proxy mode before the runtime enters `Main()`. See [Startup and lifecycle](architecture/STARTUP_AND_LIFECYCLE.md) before changing bootstrap or shutdown behavior.

`go/`, `go/guardian/`, `android/`, `ios/`, and `desktop/client/` are separately manifest-managed companion or platform surfaces rather than root CMake targets. Their local documentation defines their own build and readiness boundaries.

## Documentation status boundary

Use the current pages above for supported operating guidance. The `archive/`, `adr/`, and `design/` directories retain historical rationale, decisions, plans, and evidence; do not treat them as current configuration or deployment instructions unless a current page explicitly says so. These navigation pages are an English/Chinese pair; check each current page’s status, language-peer, and parent-index metadata before relying on it.
