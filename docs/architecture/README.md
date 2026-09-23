# Architecture
> Status: Active
> Type: Documentation index
> Last verified: source paths cited by the linked pages, 2026-07-22
>
> **Purpose:** Navigate the source-backed architecture of the native `ppp` runtime.
> **Audience:** Contributors, operators, and reviewers.
> **Current documentation:** Pages in this index describe the current repository source tree unless a page explicitly says otherwise.
> **Parent index:** [Documentation](../README.md) · **Chinese:** [架构](README_CN.md)

Start with [System Architecture](ARCHITECTURE.md) for the process and component map, then follow the path that matches the question:

| Question | Canonical page |
|---|---|
| How does the process start, run, stop, or restart? | [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md) |
| What owns client or server sessions? | [Client Architecture](CLIENT_ARCHITECTURE.md) · [Server Architecture](SERVER_ARCHITECTURE.md) |
| How do carriers, framing, and the handshake fit together? | [Transport and Protected Transmission](TRANSMISSION.md) · [Handshake Sequence](HANDSHAKE_SEQUENCE.md) |
| How do tunnel actions and packets move through the runtime? | [Tunnel Design](TUNNEL_DESIGN.md) · [Packet Lifecycle](PACKET_LIFECYCLE.md) |
| What state is presented to operators and the terminal UI? | [EDSM State Machines](EDSM_STATE_MACHINES.md) · [TUI Design](TUI_DESIGN.md) |
| How do executors, DNS, telemetry, or Linux queues work? | [Concurrency Model](CONCURRENCY_MODEL.md) · [DNS Module Design](DNS_MODULE_DESIGN.md) · [Telemetry and Observability](OTEL_DESIGN.md) · [Linux Multi-Queue Note](MULTIQUEUE_TUN_MODEL.md) |

## Current runtime maps

- [System Architecture](ARCHITECTURE.md) · [中文](ARCHITECTURE_CN.md)
- [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md) · [中文](STARTUP_AND_LIFECYCLE_CN.md)
- [Client Architecture](CLIENT_ARCHITECTURE.md) · [中文](CLIENT_ARCHITECTURE_CN.md)
- [Server Architecture](SERVER_ARCHITECTURE.md) · [中文](SERVER_ARCHITECTURE_CN.md)
- [Transport and Protected Transmission](TRANSMISSION.md) · [中文](TRANSMISSION_CN.md)
- [Tunnel Design](TUNNEL_DESIGN.md) · [中文](TUNNEL_DESIGN_CN.md)
- [Packet Lifecycle](PACKET_LIFECYCLE.md) · [中文](PACKET_LIFECYCLE_CN.md)
- [Handshake Sequence](HANDSHAKE_SEQUENCE.md) · [中文](HANDSHAKE_SEQUENCE_CN.md)
- [EDSM State Machines](EDSM_STATE_MACHINES.md) · [中文](EDSM_STATE_MACHINES_CN.md)
- [Concurrency Model](CONCURRENCY_MODEL.md) · [中文](CONCURRENCY_MODEL_CN.md)
- [TUI Design](TUI_DESIGN.md) · [中文](TUI_DESIGN_CN.md)
- [DNS Module Design](DNS_MODULE_DESIGN.md) · [中文](DNS_MODULE_DESIGN_CN.md)
- [Telemetry and Observability](OTEL_DESIGN.md) · [中文](OTEL_DESIGN_CN.md)
- [Engineering Concepts](ENGINEERING_CONCEPTS.md) · [中文](ENGINEERING_CONCEPTS_CN.md)

## Experimental or design-bound material

[Linux Single Virtual NIC Multi-Queue Model](MULTIQUEUE_TUN_MODEL.md) documents the present Linux implementation and a proposed evolution. It is **not** a completed queue-object architecture or a throughput guarantee. Read its status block before treating it as an operational contract.

For public configuration and protocol fields, use the pages under [Reference](../reference/README.md). For decisions and older rationale, use [ADRs](../adr/README.md), [Design](../design/README.md), and [Archive](../archive/README.md); they are evidence and context, not automatic statements of current behavior.
