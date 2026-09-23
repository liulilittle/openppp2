# Reference
> Status: Active
> Type: Reference index
> Last verified: 8c8a888
> Parent index: [Documentation](../README.md)
> Peer link: [中文](README_CN.md)

This index covers current, source-backed interfaces in this `openppp2/` tree. Read the task-facing pages first; protocol and native C++ pages describe implementation-coupled internals, not a third-party SDK.

## Start or configure `ppp`

- [CLI Reference](CLI_REFERENCE.md) — options, startup order, aliases, and side effects.
- [Configuration Model](CONFIGURATION.md) — accepted JSON shape, normalization, and safe configuration practices.

## Diagnose a running process

- [Diagnostics Error System](DIAGNOSTICS_ERROR_SYSTEM.md) — error-state model and observability limits.
- [Error Codes Reference](ERROR_CODES.md) — catalog authority and lookup rules.
- [Error Handling API](ERROR_HANDLING_API.md) — internal C++ diagnostics API.
- [UI Runtime Contract](UI_RUNTIME_CONTRACT.md) — versioned snapshot consumed by repository UI surfaces.

## Maintain implementation-coupled boundaries

- [Project Interface Map](PROJECT_INTERFACE_MAP.md) — contract inventory, classifications, and known gaps.
- [Link-Layer Protocol Guide](LINKLAYER_PROTOCOL.md) — opcode payloads and dispatch boundary.
- [Packet Formats](PACKET_FORMATS.md) — transport and static-echo packet codecs.
- [Session and Control-Plane Model](TRANSMISSION_PACK_SESSIONID.md) — handshake values and INFO envelopes.
- [VMUX Validation and Rollout Gate](VMUX_VALIDATION.md) — experimental scheduler evidence requirements.

When documentation and source disagree, use the source paths named by the relevant page. Current pages are paired English/Chinese; historical material belongs outside this index.