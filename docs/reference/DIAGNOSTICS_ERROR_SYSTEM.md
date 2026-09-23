# Diagnostics Error System

> Status: Current
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Chinese: [中文版本](DIAGNOSTICS_ERROR_SYSTEM_CN.md)
> Related: [Error handling API](ERROR_HANDLING_API.md) · [Error codes](ERROR_CODES.md)

## Architecture

The diagnostics subsystem is the header-visible, implementation-facing C++
facility `ppp::diagnostics`. It is not a separately versioned SDK or an ABI
compatibility promise.

```text
ErrorCodes.def (X-macro catalog)
  ├─ Error.h: ErrorCode enum and count
  └─ ErrorHandler.cpp: descriptor table
       └─ SetLastErrorCode
            ├─ per-thread code and timestamp
            ├─ process-wide code and timestamp atomics
            └─ synchronous keyed callbacks
```

`ErrorCodes.def` is the sole catalog source. At the source verified by this
page, its 628 rows are classified as 9 `kInfo`, 64 `kWarning`, 531 `kError`,
and 24 `kFatal`.

## State model

Each thread has function-local `thread_local` storage for its last code and
last tick value. `GetLastErrorCode()` reads that calling-thread state; the
thread-local tick is not exposed by a free getter.

`SetLastErrorCode()` also publishes a code and tick value to two independent
process-wide atomics using `memory_order_relaxed`. The code is stored before
the tick, but the fields are neither bundled nor versioned. The getters
perform independent loads, so they do **not** return a coherent error record:
a concurrent observer can see a code and tick from different updates.

The global values are best-effort last-writer observations, not an event log
or a synchronization mechanism. Consecutive tick values are not promised to
be strictly increasing.

## Notification dispatch

After updating state, `SetLastErrorCode()` iterates the registered handler
list on the caller's thread:

- dispatch is synchronous and uses the list's current order;
- each callback receives the numeric error value;
- exceptions from a callback are swallowed;
- a thread-local guard blocks recursive callback re-dispatch;
- a nested setter call still publishes its error state before the guard returns.

The handler list has no mutex and is not copied for dispatch. Register all
handlers before concurrent runtime activity, and do not mutate registrations
while dispatch can occur. Registration is keyed: an existing key is replaced,
and a null handler removes an existing key. There is no separate unregister
function.

## Formatting and severity

The descriptor table supplies code name, message, and severity for
`FormatErrorString`, `FormatErrorTriplet`, `GetErrorSeverity`, and
`GetErrorSeverityName`. Setters do not range-check an `ErrorCode` value;
formatting or classification of an invalid raw value uses the implementation's
unknown descriptor/classification fallback.

`kFatal` is a classification only. Diagnostics does not automatically stop,
restart, or otherwise supervise the process, and it exposes no watchdog API.
A caller that needs escalation must own that policy.

## Practical use

- Use a named `ErrorCode` and `SetLastError` helper in a failure path.
- Read `GetLastErrorCode()` in the same thread when propagating that failure.
- Use the process-wide snapshot only for advisory cross-thread presentation.
- Keep callbacks short; they run inline on the error-setting path.
- Do not treat catalog numbers, global snapshots, or callback behavior as an
  external protocol contract.

## Source references

- `ppp/diagnostics/ErrorCodes.def`
- `ppp/diagnostics/Error.h` and `Error.cpp`
- `ppp/diagnostics/ErrorHandler.h` and `ErrorHandler.cpp`
