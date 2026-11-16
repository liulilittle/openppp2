# Error Codes Reference

> Status: Current
> Type: Reference
> Last verified: local workspace, 2026-10-07
> Parent index: [Reference index](README.md)
> Chinese: [中文版本](ERROR_CODES_CN.md)
> Related: [Error handling API](ERROR_HANDLING_API.md) · [Diagnostics error system](DIAGNOSTICS_ERROR_SYSTEM.md)

## Source of truth

`ppp/diagnostics/ErrorCodes.def` is the X-macro source of truth for the
current `ppp::diagnostics::ErrorCode` catalog. Each row has this shape:

```cpp
X(Name, "human-readable message", ErrorSeverity::kError)
```

The same file generates the enum and its count in `Error.h`, and the
name/message/severity descriptor table in `ErrorHandler.cpp`. Consult the
`.def` file for the complete current catalog rather than treating this page as
a hand-maintained enumeration.

## Current catalog

At the local workspace source verified on 2026-10-07, the catalog contains **632** entries. The policy runtime changes are planned for v2.1.7 and are not in v2.1.6; successful publication of v2.1.7 is not confirmed, so this count does not describe those releases.

| Severity | Entries |
|---|---:|
| `kInfo` | 9 |
| `kWarning` | 64 |
| `kError` | 534 |
| `kFatal` | 25 |
| **Total** | **632** |

`ErrorSeverity::kWarn` is the declared enum member and
`ErrorSeverity::kWarning` is its alias; the X-macro catalog uses the alias
spelling. No current catalog row uses `kTrace` or `kDebug`.

## Numeric values and validation

`ErrorCode` is a `uint32_t` enum generated in definition order.
`kErrorCodeCount` is 632 and `kErrorCodeMax` is its exclusive upper bound at
this local workspace revision. Use named enum values when possible. When receiving a raw
integer, validate it with `IsValidErrorCodeValue(int)` before converting it to
`ErrorCode`.

The human-readable forms are available through:

- `FormatErrorString(code)` — message text
- `FormatErrorTriplet(code)` — `<numeric-id> <CodeName>: <message>`
- `GetErrorSeverity(code)` and `GetErrorSeverityName(severity)` — source-defined classification

The numeric order, count, and text are current implementation data. They are
not a wire format, a released compatibility table, or a promise that an
external consumer can persist numeric values across revisions.

## Policy additions in the workspace

The current local `ErrorCodes.def` adds these three enum entries:

| Code | Severity | Meaning |
|---|---|---|
| `ConfigPolicyRuntimeUnavailable` | `kFatal` | The v2 client policy runtime is unavailable or has not been prepared. |
| `ConfigPolicyTcpSniffUnsupported` | `kError` | TUN TCP domain sniffing is unsupported on this platform. |
| `ConfigPolicyUdpIdentityConflict` | `kError` | The v2 client virtual address conflicts with the internal UDP identity range. |
| `ProxyInternetDisabled` | `kError` | Proxy mode runs with `--proxy-internet=no`; only virtual-subnet destinations are allowed. |

The policy CLI and source loader also emit diagnostic strings such as
`E_POLICY_CONFIG`, `E_POLICY_JSON`, `E_POLICY_SOURCE_CONFLICT`,
`E_POLICY_SOURCE_UNAVAILABLE`, `E_POLICY_CAPABILITY_UNSUPPORTED`,
`E_POLICY_ARGUMENT`, and `E_POLICY_STORAGE`. These are JSON report codes, not
members of `ppp::diagnostics::ErrorCode` and have no `ErrorCodes.def` numeric ID.

## Severity boundary

Severity classifies a diagnostic code. In particular, `kFatal` does not by
itself restart or exit the process; a consumer must implement any escalation
policy explicitly.

## Catalog maintenance

When the catalog changes, modify `ErrorCodes.def` as the source of truth and
re-check generated enum/descriptor behavior and the count distribution. Keep
this reference and its Chinese peer aligned with the source; do not preserve a
partial table that can become stale.

## Source references

- `ppp/diagnostics/ErrorCodes.def`
- `ppp/diagnostics/Error.h`
- `ppp/diagnostics/ErrorHandler.cpp`
