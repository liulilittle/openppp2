# Engineering Concepts
> Status: Active
> Type: Architecture vocabulary
> Last verified: current application, diagnostics, and executor sources, 2026-07-22
>
> **Purpose:** Establish small, source-backed terms used by the architecture pages.
> **Audience:** Contributors.
> **Parent index:** [Architecture](README.md) · **Chinese:** [工程概念](ENGINEERING_CONCEPTS_CN.md)

## Ownership vocabulary

| Term | Current owner/boundary |
|---|---|
| Process application | `PppApplication`: configuration, selected runtime, tick scheduling, and `RuntimeLifecycle` |
| Client switcher | `VEthernetNetworkSwitcher`: host-facing virtual Ethernet, routes, DNS policy, local proxies |
| Client exchanger | `VEthernetExchanger`: active client session and client-side tunnel actions |
| Server switcher | `VirtualEthernetSwitcher`: listeners, per-session registration, shared server facilities |
| Server exchanger | `VirtualEthernetExchanger`: one primary client session and session-scoped forwarding state |
| Transmission | `ITransmission`: carrier-facing handshake and frame protection/transforms |
| Link layer | `VirtualEthernetLinklayer`: opcode parsing and `Do*`/`On*` action vocabulary |

`PppApplication` does not directly create every `ITransmission`; connect and accept paths construct the relevant carrier objects.

## State vocabulary

- **Runtime phase** is the process-facing presentation in `RuntimeSnapshot`, owned by `RuntimeLifecycle`.
- **Network state** is the client exchanger’s session state and an input to runtime presentation.
- **Readiness** is the gate that can keep a requested connected state at `applying_policy`.
- **Last error** is diagnostics data. It is not the lifecycle authority and should not be used as a substitute for runtime phase.

## Async vocabulary

- **Default context**, **worker contexts**, and **scheduler context** are `Executors` facilities; they are not interchangeable claims about ownership.
- A **strand** serializes work only for paths that use it.
- **`YieldContext`** is the native stackful coroutine wrapper; VMUX can also use Boost.Asio spawn facilities.
- **`Awaitable`** blocks a calling thread until completion; it is not an asynchronous result type or a cancellation-safe primitive.

Avoid introducing new code around `nullof<YieldContext>()` merely to mimic existing call sites. The implementation uses a null-address reference convention, and this documentation does not treat it as a portability guarantee.

## Diagnostics and telemetry vocabulary

`ErrorCode` values come from `ppp/diagnostics/ErrorCodes.def`. `SetLastErrorCode()` updates thread-local and process-wide diagnostic state and synchronously dispatches registered handlers on the setter’s thread. Registration is intended for initialization-time use; it is not a runtime lifecycle API.

Telemetry is separate and optional at runtime. It records events through an always-compiled facade in this tree; it is not proof of zero binary cost, lock-free operation, or a stable OpenTelemetry SDK surface. See [Telemetry and Observability](OTEL_DESIGN.md).

## Naming and configuration

The code convention distinguishes native client classes (`VEthernet*`) from server classes (`VirtualEthernet*`). Configuration serialization commonly uses kebab-case keys such as `proxy-only` and `backend-key`, while C++ members use repository-style identifiers such as `proxy_only` and `backend_key`.

Use [Reference](../reference/README.md) for externally supported keys and protocol field definitions. Architecture pages explain ownership and boundaries, not a substitute schema.
