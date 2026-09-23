# TUI Design
> Status: Active, optional runtime surface
> Type: Architecture boundary
> Last verified: `ppp/app/ConsoleUI.*`, TUI adapter, and main-loop sources, 2026-07-22
>
> **Purpose:** Describe the native terminal UI without treating it as runtime authority.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [TUI 设计](TUI_DESIGN_CN.md)

## Optional startup

`ConsoleUI::ShouldEnable()` requires a TTY on standard output and rejects a truthy `PPP_NO_TUI` environment flag. The application attempts `ConsoleUI::Start()` only after successful loopback/runtime bootstrap. Failure to initialize the terminal UI records an optional-UI diagnostic and allows the native runtime to continue without it.

`ConsoleUI::Start()` creates separate render and input threads. `Dispose()` stops and joins those threads before network runtime teardown. The source establishes optional/non-fatal behavior; it does not itself label the UI as an experimental product surface.

## Data path and authority

```text
PppApplication::OnTick()
  -> RuntimeLifecycle updates
  -> latest RuntimeSnapshot
  -> tui::BuildStatusLines(snapshot)
  -> ConsoleUI status and info buffers
```

`RuntimeSnapshot.phase`, MUX fields, P2P state, and failure details are primary inputs to the TUI adapter. `OnTick()` also samples traffic, link quality, and environment information separately, then combines text into the displayed status and information lines. The rendered console status is therefore not a direct one-to-one `RuntimePhase` renderer.

Use `RuntimeSnapshot`/`RuntimeLifecycle` as lifecycle authority. Error state and terminal text are diagnostics/presentation, not independent health authorities.

## Commands

Built-in commands are namespaced:

- `openppp2 help`
- `openppp2 restart`
- `openppp2 reload`
- `openppp2 exit`
- `openppp2 info`
- `openppp2 clear`
- `openppp2 telemetry ...`

Unknown bare input is reported as an unknown command; it does **not** fall through to shell execution. `openppp2 info` copies the cached periodic info lines from the UI buffer rather than traversing or serializing the runtime graph on the input thread.

## Operational boundary

The TUI is useful for local observation and requests shutdown/restart through the same application path as other requests. It is not a stable automation API, a lifecycle source of truth, or a guarantee that a process has reached a healthy connected state. Use structured stats/snapshots and source-backed interfaces where automation is required.
