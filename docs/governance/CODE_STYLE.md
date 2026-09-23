# Code Style and Module Boundaries

> **Purpose:** Define current code placement, dependency, and formatting rules.
> **Audience:** Contributors and reviewers.
> **Status:** Current governance.
> **Last verified against:** Current repository checks and CI rules, 2026-07-22.
> **Parent index:** [Development](../development/README.md) · **Chinese:** [代码风格与模块边界](CODE_STYLE_CN.md)

> Status: Active
> Type: Governance
> Last verified: 8c8a888

Use C++17, four spaces, no tabs, and the surrounding include/order conventions. Formatting applies to new and
changed code; inherited files are not mass-formatted.

| Location | Ownership |
|---|---|
| `ppp/app/runtime` | Runtime contract and lifecycle publication |
| `ppp/app/client/dns` | DNS policy, session lifetime, and reachability projection |
| `ppp/app/client/route` | Route state, transaction coordinator, and immutable plan input |
| `ppp/app/mux` | VMUX protocol, scheduling, and runtime state |
| `ppp/p2p` | Authenticated direct-channel primitives |
| Platform directories | OS calls and concrete adapters |
| `android`, `ios` | Presentation and platform bridges |

Prohibited patterns are enforced by `tools/check_repository_layout.py`: new `.inc` fragments, concrete-host names
in route/DNS public headers, mutable container pointers, reverse protocol dependencies, legacy service locators,
and route managers retaining a Switcher owner.
