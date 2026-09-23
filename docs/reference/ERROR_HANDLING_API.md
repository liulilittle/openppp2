# Error Handling API

> Status: Current
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Chinese: [中文版本](ERROR_HANDLING_API_CN.md)
> Related: [Error codes](ERROR_CODES.md) · [Diagnostics error system](DIAGNOSTICS_ERROR_SYSTEM.md)

This page describes the header-visible `ppp::diagnostics` C++ interface
implemented by `ppp/diagnostics/Error.h`, `Error.cpp`, and `ErrorHandler.*`.
It is an implementation interface, not a separately supported public SDK.

## Scope and API boundary

`ErrorCode` definitions, text, and severity are generated from
`ppp/diagnostics/ErrorCodes.def`. `Error.h` declares free functions in
`ppp::diagnostics`; `ErrorHandler` is their singleton-backed implementation,
not an advertised object API or compatibility boundary.

Not provided by the current source:

- `Error::ToString`
- `UnregisterErrorHandler`
- an automatic restart, exit, or watchdog API

## Header-visible functions

| Area | Functions | Meaning |
|---|---|---|
| Validation | `IsValidErrorCode`, `IsValidErrorCodeValue` | Check an enum or raw integer against the current contiguous catalog range. |
| Calling-thread state | `GetLastErrorCode` | Return the calling thread's last code. |
| Process-wide observation | `GetLastErrorCodeSnapshot`, `GetLastErrorTimestamp` | Read advisory global code and tick fields. They are not a coherent record. |
| Publication | `SetLastErrorCode` | Set state and return the supplied `ErrorCode`; it does not range-check the value. |
| Failure-return helpers | `SetLastError` overloads/templates | Set the code and return `false`, `-1`, `NULLPTR`, or a caller-supplied value. |
| Formatting and classification | `FormatErrorString`, `FormatErrorTriplet`, `GetErrorSeverity`, `GetErrorSeverityName`, `IsErrorFatal` | Obtain source-defined presentation metadata. |
| Notifications | `RegisterErrorHandler` | Add, replace, or remove a keyed callback. |

`FormatErrorTriplet(code)` returns `<numeric-id> <CodeName>: <message>`.
Invalid raw values use the implementation's unknown descriptor fallback.

## State and publication semantics

`ErrorHandler` keeps the calling thread's last code and tick in function-local
thread-local storage. `SetLastErrorCode` obtains the tick from
`Executors::GetTickCount()` and also writes a process-wide code atomic and tick
atomic with `memory_order_relaxed`.

The two global fields are separate stores and separate loads. A reader must
not treat `GetLastErrorCodeSnapshot()` and `GetLastErrorTimestamp()` as one
atomic `(code, tick)` event record. They are advisory observations and may
represent different concurrent publications.

Use `GetLastErrorCode()` for a same-thread failure path. Use the global
getters only when a best-effort cross-thread observation is sufficient.

## Callbacks and registration

`SetLastErrorCode` invokes registered callbacks synchronously on the setter's
thread, in registration-list order. Each callback exception is swallowed.
A thread-local recursion guard prevents a callback-triggered nested
`SetLastErrorCode` from dispatching callbacks again; that nested call still
updates the local and global error state.

Registration is intentionally unsynchronized:

- Register handlers before multi-threaded runtime activity begins.
- Reusing a key replaces its handler.
- Passing a null handler for an existing key removes that entry.
- Passing a null handler for an unknown key does nothing.
- Do not register, replace, or remove while callbacks may be dispatched.

## Severity is not process control

`IsErrorFatal(code)` tests whether the source-defined severity is `kFatal`.
That classification alone does not stop the process, schedule a restart, or
change runtime lifecycle state. A consumer may choose its own escalation
policy.

## Source references

- `ppp/diagnostics/ErrorCodes.def` — catalog source
- `ppp/diagnostics/Error.h` — declarations and helpers
- `ppp/diagnostics/ErrorHandler.cpp` — state storage, publication, formatting, and callback dispatch
