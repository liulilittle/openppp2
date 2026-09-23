# Telemetry and Observability
> Status: Active, optional at runtime
> Type: Architecture boundary
> Last verified: `ppp/diagnostics/Telemetry.*`, configuration, and shutdown sources, 2026-07-22
>
> **Purpose:** Describe the current telemetry implementation and its practical limits.
> **Audience:** Contributors and operators.
> **Parent index:** [Architecture](README.md) · **Chinese:** [可观测性](OTEL_DESIGN_CN.md)

## What exists

The native runtime has two separate diagnostic surfaces:

| Surface | Current role |
|---|---|
| `ErrorCode` / `ErrorHandler` | Typed diagnostics from `ErrorCodes.def`; setting an error updates local/process state and synchronously dispatches registered handlers. |
| `ppp::telemetry` | Runtime-configurable logs, counters, gauges, histograms, and spans through an in-tree facade. |

Neither surface is a replacement for `RuntimeLifecycle` when an operator needs lifecycle state.

## Telemetry enablement

The telemetry facade is always compiled in this tree. Although CMake exposes a `PPP_TELEMETRY` option, `Telemetry.h` defines `PPP_TELEMETRY` to `1` when absent and the implementation has no compile-out no-op branch. Do not document the option as a zero-binary-cost switch.

Master telemetry, counts, and spans default to disabled. Startup applies `telemetry.enabled`, level, count/span, console, endpoint, and file-path configuration through `PreparedArgumentEnvironment()`. The configuration path calls `Configure()` and `SetLogFile()` even when the master flag is disabled, so source does not support a blanket claim that disabled telemetry never creates backend state.

## Backend behavior

When created, the backend owns a worker thread and separate bounded queues for logs, counters, spans, gauges, and histograms. Normal queue limits are 4096 events with batches of up to 256; a full queue drops that event type. Log level filtering occurs before formatting/enqueue and again in the backend.

This design has useful backpressure, but it is not lock-free or allocation-free when enabled: queue and event implementations use mutexes and dynamic string/vector fields. The only clear disabled-path guarantee is a fast runtime return after the relevant atomic enable checks.

`SpanScope` maintains parentage in a thread-local stack. Same-thread nesting is represented; automatic trace-context propagation across Asio callbacks or threads is not implemented by that state.

## Export and shutdown limits

The built-in OTLP-style exporter uses raw HTTP sockets. For an `https://` endpoint it does not send without an externally installed `HttpPostSink`; native TLS collector export is therefore not established by the built-in path. Collector compatibility and delivery guarantees require deployment-specific validation.

`PppApplication::Dispose()` calls `Flush(3000)` and `Shutdown()`. This is best-effort shutdown behavior, not evidence of lossless delivery under all exit paths or load conditions.

## Safe documentation boundary

Telemetry is optional observability. Avoid claiming any of these without new evidence:

- compile-time removal or zero binary cost;
- lock-free/no-allocation enabled hot paths;
- per-module switches, sampling, or rate limiting;
- built-in HTTPS OTLP delivery;
- a stable public OpenTelemetry SDK or collector-interoperability guarantee.

Use errors for diagnostics, runtime snapshots for lifecycle presentation, and telemetry for opt-in event observation.
