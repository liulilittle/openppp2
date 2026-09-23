# UI Runtime Contract

> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer link: [中文](UI_RUNTIME_CONTRACT_CN.md)
> Related: [Diagnostics error system](DIAGNOSTICS_ERROR_SYSTEM.md) · [VMUX validation](VMUX_VALIDATION.md)

This is the version 1 boundary for `RuntimeSnapshot` consumers. The native
surface includes `GetRuntimeSnapshot`, `GetRuntimeSnapshotJson`,
`SubscribeRuntimeSnapshots`, and `UnsubscribeRuntimeSnapshots`.

## Required v1 fields

A valid v1 JSON payload must contain all four fields below. Missing or invalid
required fields fail decoding.

| Field | Requirement |
|---|---|
| `schema_version` | Unsigned value exactly `1`. |
| `generation` | Unsigned 64-bit generation ordering key. |
| `monotonic_ms` | Unsigned 64-bit ordering key within a generation. |
| `phase` | A supported phase string, including the literal `unknown`. |

An unsupported version or an unrecognized phase string also fails decoding.
`unknown` is a valid wire phase; it is distinct from an unrecognized string.

## Optional fields and forward compatibility

All other snapshot fields are optional to the native parser. Unknown optional
root fields and unknown fields inside `traffic` or `last_error` are ignored.
Absent or wrongly typed optional values fall back to their reader defaults;
they do not make an otherwise valid required-field payload fail.

Important shapes and ownership:

| Field/group | Contract |
|---|---|
| `capabilities` | JSON array of strings, not an object. |
| `role`, `server`, `transport` | Optional runtime identity strings. |
| `requested_mux_mode`, `effective_mux_mode`, `mux_receiver_ordering`, `mux_fallback_reason`, `mux_active_links` | Optional MUX state and presentation. |
| `mux_scheduler`, `mux_pool_policy`, `mux_turbo` | Current native serializer extensions; tolerated as unknown optional v1 keys. |
| `p2p_state`, `effective_path` | `effective_path` is derived from `p2p_state` by serializers and is not authoritative input. |
| `traffic`, `connected_monotonic_ms` | Optional cumulative traffic and connected-interval data. |
| `last_error` | Optional producer-provided diagnostic payload. |

## Parse validity and ordering

Decoding validates shape and required fields; it does not decide freshness.
The native publisher and mobile stores apply ordering after a valid snapshot is
available: accept a higher `generation`, or the same generation only when
`monotonic_ms` is strictly greater. Older or duplicate snapshots are rejected.

A consumer that decodes external JSON may turn a decode failure with valid
ordering metadata into an ordered `unknown` presentation. A malformed payload
without valid ordering metadata must not overwrite newer state. Native TUI
adapters receive typed snapshots and do not themselves parse this JSON.

## Lifecycle presentation

The normal producer sequence is:

```text
starting → preparing_host → connecting → handshaking → applying_policy → connected
```

`reconnecting` represents recovery; stop publishes `stopping` and completes as
`idle` or `failed`. This sequence describes normal producer behavior, not a
strict legal-transition table: lifecycle code validates generation/stop
ownership, not every phase-to-phase edge.

A request for `connected` is presented as `applying_policy` until all readiness
facts are true. Leaving `connected` clears `connected_monotonic_ms`; a later
connection begins a new interval.

## Connected readiness gate

The five required facts are:

1. session established;
2. adapter open;
3. route applied, or route explicitly not required;
4. DNS configured and session-active, or DNS explicitly not required;
5. policy negotiated.

Current client wiring derives the policy fact from session establishment. For
server mode, an active listener supplies all five readiness bits; constructing
a server object alone is insufficient.

## `last_error` boundary

`last_error.code` is currently a producer-specific `uint32_t` numeric value.
It is not guaranteed to be a `ppp::diagnostics::ErrorCode` ordinal. Producers
supply its severity, retryability, message key, and diagnostic detail; consumers
must not infer them from the diagnostics catalog.

Successful stop clears `last_error`; a failed stop carries the error supplied
to stop completion. A payload may also represent an error through diagnostic
detail even when its numeric code is zero.

## TUI command safety

Console UI command handling recognizes the `openppp2` command namespace and
reports unknown commands or subcommands locally with help text. Unknown TUI
input is rejected; it is not forwarded to a shell or system-command executor.

## Source references

- `ppp/app/runtime/RuntimeSnapshot.h` and `RuntimeSnapshotJson.h`
- `schemas/runtime-snapshot-v1.schema.json`
- `ppp/app/runtime/RuntimeLifecycle.h` and `RuntimeReadiness.h`
- `ppp/app/runtime/RuntimeError.h`
- `ppp/app/ConsoleUI.cpp`
