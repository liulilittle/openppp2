# Startup and Lifecycle
> Status: Active
> Type: Architecture
> Last verified: `main.cpp`, `ppp/facade/`, and `ppp/app/` lifecycle sources, 2026-07-22
>
> **Purpose:** Explain how the native `ppp` process is prepared, bootstrapped, observed, and torn down.
> **Audience:** Contributors and operators debugging lifecycle behavior.
> **Parent index:** [Architecture](README.md) · **Chinese:** [启动与生命周期](STARTUP_AND_LIFECYCLE_CN.md)

## Entry and process owner

```text
main.cpp
  -> ppp::facade::RunApplication(argc, argv)
  -> PppApplication::GetInstance().Run(argc, argv)
  -> PreparedArgumentEnvironment(...)
  -> Executors::Run(...)
  -> RunPreparedApplication(...)
  -> PppApplication::Main(...)
```

`RunApplication()` is an outer error-reporting shell: it runs the application, supplies a generic diagnostic when needed, and prints the resulting error information to standard error. `PppApplication` owns the real startup and shutdown work.

`Run()` initializes global support, prepares arguments and configuration, enters the executor runtime, and releases process-level state after the executor returns. A requested restart is performed after executor exit (`CreateProcessA` on Windows; `execvp` on non-Windows builds).

## Preparation before `Main()`

`PreparedArgumentEnvironment()`:

1. handles early help/statistics-output setup;
2. loads and normalizes configuration;
3. resolves `--mode` to `server`, `client`, or `proxy`;
4. derives the client and proxy role flags;
5. applies proxy-oriented defaults when proxy mode or `client.proxy-only` is set;
6. builds `NetworkInterface` inputs and configures runtime DNS-cache globals;
7. configures telemetry switches and sinks; and
8. configures executor counts from the loaded configuration.

The mode is resolved before proxy defaults. `client.proxy-only` alone does not switch the process out of the default server role; use `--mode=client` or `--mode=proxy` to select a client-family runtime.

## Main bootstrap

`Main()` seeds `RuntimeLifecycle` with the selected role and then requests the early presentation phases. It performs the privilege and single-instance gates before dispatching to a role-specific loopback environment.

| Role | Bootstrap | Notes |
|---|---|---|
| Server | `PrepareServerLoopbackEnvironment()` | Prepares server IPv6 host state, creates `VirtualEthernetSwitcher`, opens it, and starts accept loops. Failure rolls back the host preparation. |
| Client | `PrepareClientLoopbackEnvironment()` | Opens the device, creates `VEthernetNetworkSwitcher`, applies client settings, and opens the client runtime. |
| Proxy | Client bootstrap with proxy mode | Skips the `Main()` privilege gate; it is not merely a spelling of a full client configuration. |

On desktop-style targets, a proxy-only runtime can use `TapStub` instead of a kernel device. That is intentionally a no-injection stub. Android and iOS are excluded from that branch and use their platform integration paths instead.

The terminal UI is optional. It is considered only after successful runtime bootstrap; an unsuitable terminal or a `ConsoleUI::Start()` failure does not make the tunnel bootstrap fail.

## Runtime snapshots and the periodic tick

After bootstrap, `NextTickAlwaysTimeout()` schedules an immediate maintenance call and re-arms at roughly 1000 ms. `OnTick()` is where live runtime facts are projected into `RuntimeLifecycle`:

- a running server requests `connected` using server readiness;
- no client exchanger requests `connecting`;
- a reconnecting exchanger requests `reconnecting`;
- an established exchanger updates client readiness and requests `connected`;
- other client exchanger states request `handshaking`.

Client `connected` is gated by session, adapter, route, DNS, and policy facts. A requested `connected` state can therefore remain externally represented as `applying_policy` until all required facts are ready.

`OnTick()` also samples traffic, MUX and P2P presentation, writes optional `--stats-json` samples, refreshes TUI strings, and evaluates restart and route-refresh policies.

The visible phase flow (`starting` through `connected`, reconnecting, stopping, and an eventual idle/failed result) describes current application behavior. It is not an enforced state-transition grammar: the lifecycle object checks generation and stop ownership and only special-cases the connected readiness gate.

## Shutdown and restart

A shutdown request posts work onto the default executor rather than synchronously destroying the runtime. The posted path calls `Dispose()` and schedules `Executors::Exit()` after one second.

`Dispose()` attempts to claim the current lifecycle generation as the stop owner, stops the TUI, disposes moved server/client runtime objects, clears the tick timer, and flushes/shuts down telemetry. Cleanup completion calls `RuntimeLifecycle::CompleteStop()` with `idle` or `failed`.

Two boundaries matter when diagnosing shutdown:

- `Release()` releases the single-instance guard after the executor has returned; `Dispose()` does not release that guard.
- Do not promise a final snapshot for every failure or exit path. Some startup failures return after `Begin()`, and executor exit is scheduled independently of asynchronous teardown completion.

Restart policy and UI commands ultimately use this same shutdown path; process replacement happens only after the executor exits.

## Source reading order

1. `main.cpp`
2. `ppp/facade/ApplicationBootstrap.cpp`
3. `ppp/app/PppApplication.cpp`
4. `ppp/app/ApplicationConfig.cpp`
5. `ppp/app/ApplicationInitialize.cpp`
6. `ppp/app/ApplicationClientBootstrap.cpp` or `ApplicationServerBootstrap.cpp`
7. `ppp/app/ApplicationMainLoop.cpp`
8. `ppp/app/runtime/RuntimeLifecycle.h`
