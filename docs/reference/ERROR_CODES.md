# Error Codes Reference

> Status: Current
> Type: Reference
> Last verified: 8c8a888
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

At the source verified by this page, the catalog contains **628** entries.

| Severity | Entries |
|---|---:|
| `kInfo` | 9 |
| `kWarning` | 64 |
| `kError` | 531 |
| `kFatal` | 24 |
| **Total** | **628** |

`ErrorSeverity::kWarn` is the declared enum member and
`ErrorSeverity::kWarning` is its alias; the X-macro catalog uses the alias
spelling. No current catalog row uses `kTrace` or `kDebug`.

## Numeric values and validation

`ErrorCode` is a `uint32_t` enum generated in definition order.
`kErrorCodeCount` is 628 and `kErrorCodeMax` is its exclusive upper bound at
this revision. Use named enum values when possible. When receiving a raw
integer, validate it with `IsValidErrorCodeValue(int)` before converting it to
`ErrorCode`.

The human-readable forms are available through:

- `FormatErrorString(code)` — message text
- `FormatErrorTriplet(code)` — `<numeric-id> <CodeName>: <message>`
- `GetErrorSeverity(code)` and `GetErrorSeverityName(severity)` — source-defined classification

The numeric order, count, and text are current implementation data. They are
not a wire format, a released compatibility table, or a promise that an
external consumer can persist numeric values across revisions.

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
