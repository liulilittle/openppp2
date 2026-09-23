# Source Reading Guide
> Status: Active
> Type: Development guide
> Last verified: 2026-07-22
>
> **Purpose:** Follow the current native application path before relying on design summaries.
> **Audience:** New contributors and reviewers.
> **Parent index:** [Development](README.md) · **Chinese:** [源码阅读指南](SOURCE_READING_GUIDE_CN.md)

## Goal

After this path, you should be able to explain how the process loads configuration, enters the executor, chooses a role, and reaches the client or server runtime in the current tree.

## 1. Start at the executable boundary

Read these files in order:

1. `main.cpp` calls `ppp::facade::RunApplication(argc, argv)`.
2. `ppp/facade/ApplicationBootstrap.cpp` obtains `PppApplication`, calls `Run`, and prints a diagnostic triplet for a nonzero result.
3. `ppp/app/PppApplication.cpp` initializes globals, prepares arguments/configuration, and passes the prepared application into `Executors::Run`.
4. `ppp/threading/Executors.cpp` attaches the default `io_context`, posts the entry callback, runs the loop, and detaches it on exit.
5. `RunPreparedApplication` in `ppp/app/PppApplication.cpp` handles utility/help paths, installs shutdown handling, then calls `PppApplication::Main`.
6. `ppp/app/ApplicationInitialize.cpp` enforces the non-proxy privilege boundary, creates the role/configuration instance lock, starts the console surface, and seeds runtime lifecycle state.
7. `ppp/app/ApplicationMainLoop.cpp` and `ppp/app/runtime/` contain periodic work, shutdown coordination, and runtime snapshots.

The architectural overview is a map, not a substitute for this sequence: [Startup and lifecycle](../architecture/STARTUP_AND_LIFECYCLE.md).

## 2. Read arguments and configuration next

1. `ppp/app/ApplicationMode.cpp` — default role and CLI mode parsing.
2. `ppp/app/ApplicationConfig.cpp` — help handling, configuration candidate order, command-line overrides, rule paths, and runtime statistics output.
3. `ppp/app/ApplicationHelp.cpp` — the emitted option list and platform-specific help rows.
4. `ppp/configurations/AppConfiguration.h` and `.cpp` — JSON loading, defaults, normalization, and security diagnostics.
5. [Configuration](../reference/CONFIGURATION.md) and [CLI reference](../reference/CLI_REFERENCE.md) — reader-facing contracts that should be reconciled with the source above.

## 3. Follow the selected runtime role

### Client

1. `ppp/app/ApplicationClientBootstrap.cpp` — choose proxy stub versus platform TAP setup and start the client runtime.
2. `ppp/app/client/VEthernetNetworkSwitcher.*` — client-level orchestration.
3. `ppp/app/client/VEthernetExchanger.*` — connection and virtual-network state.
4. `ppp/app/client/route/` and `ppp/app/client/dns/` — platform route/DNS coordination.

Use [Client architecture](../architecture/CLIENT_ARCHITECTURE.md) and [Routing and DNS](../guides/ROUTING_AND_DNS.md) as supporting maps.

### Server

1. `ppp/app/ApplicationServerBootstrap.cpp` — server setup and startup.
2. `ppp/app/server/VirtualEthernetSwitcher.*` — server-side switching and listeners.
3. `ppp/app/server/VirtualEthernetExchanger.*` — per-peer exchange behavior.
4. `ppp/app/server/` — peer routing, mapping, and server-specific support.

Use [Server architecture](../architecture/SERVER_ARCHITECTURE.md) for the broader diagram.

## 4. Trace bytes and protocol behavior

1. `ppp/transmissions/ITransmission.*` — transport-facing lifecycle and framing base.
2. `ppp/transmissions/ITcpipTransmission.*` and `ppp/transmissions/IWebsocketTransmission.*` — TCP/WebSocket implementations.
3. `ppp/app/protocol/` — virtual Ethernet information and link-layer messages.
4. `ppp/app/protocol/VirtualEthernetLinklayer.h` — packet action definitions.
5. `ppp/diagnostics/ErrorCodes.def` and `ppp/diagnostics/Error.*` — errors and formatted diagnostic output.

Supporting documents: [Transmission](../architecture/TRANSMISSION.md), [Link-layer protocol](../reference/LINKLAYER_PROTOCOL.md), and [Error handling](../reference/ERROR_HANDLING_API.md).

## 5. Treat optional surfaces as separate investigations

| Surface | Start reading here |
|---|---|
| Terminal UI | `ppp/app/ConsoleUI.cpp`, `ppp/app/tui/TuiRuntimeAdapter.h` |
| MUX | `ppp/app/mux/` |
| P2P | `ppp/p2p/` and `ppp/app/P2PCandidateAdapter.*` |
| Desktop Client | `desktop/client/` and its `src-tauri/` shell |
| Android native bridge | `android/` and `android/CMakeLists.txt` |
| iOS native library | `ios/` and `ios/CMakeLists.txt` |
| Go components | `go/` |

Each surface has its own maturity and build path. Do not infer that an optional or platform-specific surface is part of the root native `ppp` target.

## 6. Read tests alongside changes

Start with [Testing](TESTING.md). The standalone C++ project under `tests/cpp` is intentionally different from root CMake tests enabled by `ENABLE_TESTS`; choose the suite that covers the code you change.
