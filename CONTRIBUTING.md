# Contributing

Use an isolated feature branch, keep commits scoped, and match the style of the files you touch. Native code is
C++17 with four-space indentation. Go changes must be `gofmt` formatted, and Dart changes must pass the existing
Flutter analysis and test gates.

## Boundaries

- `ppp/app/runtime` owns runtime snapshots and lifecycle publication.
- `ppp/app/client/dns` owns client DNS policy and sessions.
- `ppp/app/client/route` owns route state, transactions, and platform route inputs.
- `ppp/app/mux` owns VMUX protocol and scheduling.
- `ppp/p2p` owns direct-channel protocol primitives.
- Platform directories own operating-system calls; Android and iOS presentation code consumes runtime snapshots.

Do not add `.inc` fragments, owner-only `Bind(this)` helpers, UI log parsing, mutable-container pointers in service
interfaces, or protocol-to-client/server reverse includes. Update paired English and Chinese stable documentation
when behavior changes. See [code style](docs/governance/CODE_STYLE.md) and
[documentation style](docs/governance/DOCUMENTATION_STYLE.md).

## Verification

Run the focused tests for the changed subsystem, then the repository architecture and documentation checks. Pull
requests must list the commands run and include platform evidence for platform-specific behavior.
