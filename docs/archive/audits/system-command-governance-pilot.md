# system()/popen() Command Governance — Phase 1 Pilot
> Status: Archived
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


**Date**: 2026-05-12
**Scope**: `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` (single-file, minimal-invasive pilot)
**Risk level**: Low — no behavioral changes, no failure semantics altered

## Problem Statement

`system()` and `popen()` execute arbitrary commands via `/bin/sh`. If dynamic user
or network-controlled data is interpolated into the command string without
sanitization, this becomes a shell-injection vector. The project uses these calls
extensively for Linux network configuration (ip, ip6tables, sysctl, etc.).

## Inventory (Full Codebase)

| File | `system()` | `popen()` | Notes |
|------|-----------|-----------|-------|
| `common/unix/UnixAfx.cpp` | 0 | 3 | Central `ExecuteShellCommand*` utility layer |
| `ppp/stdafx.cpp` | 2 | 0 | Hardcoded `system("cls")` / `system("clear")` |
| `ppp/app/ConsoleUI.cpp` | 0 | 1 | `_popen`/`popen` platform branching |
| `linux/ppp/tap/TapLinux.cpp` | 3 | 1 | Already well-governed (model pattern) |
| `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp` | 4→1 | 2 | **Pilot target** |
| `linux/ppp/diagnostics/UnixStackTrace.cpp` | 1 | 1 | Diagnostic use |
| `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` | 6 | 2 | Darwin IPv6 management |
| `darwin/ppp/tun/utun.cpp` | 3 | 0 | Darwin TUN setup |
| `windows/ppp/app/client/lsp/PaperAirplaneLspY.cpp` | 1 | 0 | `system("pause")` |
| `windows/ppp/win32/Win32Native.cpp` | 1 | 0 | `system("pause")` |
| **Total** | **~22** | **~10** | |

### Excluded from this pilot (by constraint)

- DNS files (`ppp/app/client/dns/`, `ppp/dns/`)
- Android JNI/Timer files (`android/`)
- atomic_shared_ptr files (none found in codebase)

## What Changed (Pilot)

### 1. Consolidated `RunSystemCommand()` canonical wrapper

**Before**: Two near-identical wrappers:
- `LinuxExecuteCommand()` → `system()` returning `bool`
- `LinuxExecuteCommandWithStatus()` → `system()` returning `int`

Both contained duplicate empty-check + `system()` logic.

**After**: Single canonical `RunSystemCommand()` returning `int`, with both
existing wrappers delegating to it. No caller changes required.

```
RunSystemCommand(command)           ← canonical, returns int
  ├── LinuxExecuteCommand(command)  ← convenience, returns (result == 0)
  └── LinuxExecuteCommandWithStatus(command) ← passthrough, returns int
```

### 2. Routed stray `system()` through wrapper

`ApplyDefaultRouteCommand()` (line ~613) used raw `system(command)` directly,
bypassing the established wrapper. Changed to `RunSystemCommand(command)`.
Arguments were already validated by `IsSafeShellRoute()`.

### 3. Added SECURITY-GOVERNANCE comments

- `RunSystemCommand()`: Documents the contract that all callers must sanitize
  dynamic tokens via `IsSafeShellToken()` before building command strings.
- `ReadSysctlValue()`: Documents why it uses raw `popen()` (needs stdout
  capture) and that input is guarded by `IsSafeSysctlKey()`.
- `ReadDefaultRoute()`: Documents that it uses a hardcoded command literal
  with no dynamic tokens.

## What Did NOT Change (Deliberate Exclusions)

- **Failure semantics**: All return values are identical to before.
- **`ReadSysctlValue()` popen()**: Intentionally kept raw — it captures stdout
  line-by-line, which `system()` cannot do. Governance comment added instead.
- **`ReadDefaultRoute()` popen()**: Hardcoded command literal, no injection risk.
  Governance comment added.
- **Cross-file code movement**: No functions moved between files.
- **`common/unix/UnixAfx.cpp`**: Shared utility layer, changes affect all
  platforms — out of scope for a single-file pilot.

## Safety Analysis

- **No new code paths introduced**: All changes are structural refactoring
  (extracting a shared helper) or annotation-only.
- **No behavioral change**: Every call site produces the same `system()` syscall
  with the same arguments as before.
- **`IsSafeShellToken()` already present**: All call sites in this file already
  validate inputs before building command strings.
- **`IsSafeShellRoute()` already present**: `ApplyDefaultRouteCommand` already
  validates its route argument.

## Recommended Follow-Up (Phase 2)

1. **Darwin mirror**: `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp` has 6 raw
   `system()` calls — apply the same pattern.
2. **Central `IsSafeShellToken`**: The identical function is duplicated in
   `TapLinux.cpp` and `LINUX_IPv6Auxiliary.cpp`. Extract to a shared header.
3. **`UnixAfx::ExecuteShellCommand`**: Add optional audit-logging capability
   (compile-time opt-in) to the central utility layer.
4. **Compiler warning**: Consider `-Wformat-security` or a static analysis
   rule to flag raw `system()`/`popen()` calls outside approved wrappers.
