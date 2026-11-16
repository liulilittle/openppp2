# ADR 0003: Opt-in corocc L0 Backend

> Status: Experimental
> Type: ADR
> Last verified: 2026-10-29, bfd5b881 + uncommitted corocc implementation

Status: Experimental, default OFF. [Chinese](0003-corocc-coroutine-backend_CN.md).

## Decision

`ENABLE_COROCC=OFF` keeps Boost fcontext. `ContextBackend.h` selects the backend
at compile time. Default make/jump functions and context types alias Boost
directly; Anchor, scheduling, public YieldContext methods and their callers are
unchanged. Only corocc builds add `coroutine_backend: "corocc"` to runtime stats;
default builds preserve the original JSON bytes and omit the field. This is a
deliberate exception to the plan's dual-label telemetry, honoring the stricter
default-behavior compatibility requirement. Backend constants name the default
`boost-fcontext` without adding output.

Only corocc L0 context/stack functions are called. L1 tokens, L2 runtime and L3
scopes do not participate in PPP scheduling. Boost.Context remains linked.
The upstream static archive contains other layers, but the linker need only
extract L0 objects. `tools/prepare_corocc.sh` pins commit
`92502d92d136ea870a857d1578f13c33191b381f`, archive SHA-256
`18042dd1ee9263eb40101e38aa7c72f46fb1502331d08619ab69092fb024f1b5`.

## Transfer Contract

`Jump(target, data)` must deliver `{source, data}` to the target, and eventually
return the equivalent descriptor supplied by its *actual new resumer*. corocc
`coro_ctx_swap(from, to)` instead writes saved frames into stable context objects.
The adapter owns one record per coroutine, plus a borrowed root record per OS
thread. Before swap it writes `target.incoming = {source, data}`. Entry and the
returning swap consume that record. Nothing is inferred from the previous caller.

`Current()` computes the TLS address inside a non-inlined, fenced accessor.
No TLS reference is retained across swap. After migration, the coroutine resets
the current thread's record to itself. Native `back` and adapter `incoming` are
overwritten by every new resumer before execution resumes. This covers nested
coroutines and sequential migration between different io_context worker threads.
It does not move a coroutine to another io_context/shard.

YieldContext owns the initial native context independently of `callee_` (which is
exchanged with null during each handoff). Completion uses `Finish(caller, null)`;
the caller observes null data, destroys the native context, then releases the
stack. The entry trampoline must never return. Exceptions are caught by the
existing noexcept handler before crossing the switching boundary.

## Stacks And Sanitizers

Normal stacks still come from BufferswapAllocator and remain 128 KiB. The pinned
L0 API has no borrowed-range initializer, so the adapter supplies the documented
ABI's `coro_stack.lo/usable` fields without transferring allocation ownership.
This is deliberately tied to the pin and must be re-audited on upgrade.
`PPP_COROCC_GUARD_STACK=ON` instead owns a `coro_stack_alloc` mapping through a
shared_ptr deleter. There is one additional low guard page; usable bytes are
page-rounded by corocc. No guard allocation occurs in the default backend.

TSan uses corocc L0's fiber annotations; the existing YieldContext annotations
are disabled only for corocc to avoid double switching. Coroutine context
destruction retires its fiber; borrowed thread roots are never destroyed through
corocc because their fiber identities belong to the sanitizer runtime. TSan
builds retain the existing larger diagnostic stack allowance.
The backend interface exports `COROCC_TSAN=1` in TSan builds so even a consumer
translation unit without instrumentation sees the same native context layout.

The pinned patch forces both L0 TSan switching helpers inline at every
optimization level. Without this, an out-of-line helper enters on the source
fiber and exits on the destination, corrupting TSan's shadow stack at the first
trampoline entry. The unoptimized Clang 19 suite exposed this; focused retests
exercise the fix. Memory-access instrumentation remains enabled. Function-level
thread-sanitizer exclusions can retain other instrumentation, as explained in
the [Clang TSan documentation](https://clang.llvm.org/docs/ThreadSanitizer.html).

ASan instrumentation covers corocc code but its internal fiber hooks are OFF.
The adapter owns start/finish hooks: each source keeps its own fake-stack handle,
arrival discovers source stack bounds (including the current worker root), and
the terminal switch passes a null save pointer to release the fake stack.
Upstream hooks transfer the source handle to the destination; the adapter instead
keeps the saved handle with its owning fiber, including during migration.
ASan/UBSan and TSan always use separate builds.

## Platforms And Acceptance

The initial whitelist is Linux x86_64/aarch64, macOS x86_64/arm64, Android
x86_64/arm64 and MSVC Windows x64. This is an eligibility list, not a claim of
runtime validation. Other targets warn and disable the option unless
`COROCC_FORCE=ON`; iOS always warns and uses Boost. There is no runtime fallback.
The hand-maintained `ppp.vcxproj` does not enable corocc; use CMake for opt-in
Windows builds. Windows TIB restoration is implemented in upstream assembly and
requires native SEH/stack-bound validation. musl, Windows x86/ARM64 remain
experimental. Platform results are recorded in the validation report.

Correctness gates precede performance: transfer/nesting/migration/completion,
Anchor races and late wakeups, exceptions, stack persistence, worker 1/N, ASan
with stack-use-after-return, TSan, optional guard fault, and duplicate-symbol
inspection. Any correctness failure rejects the backend. A/B uses matching
release binaries, DL/UL P1/P16/P64, interleaved A1/B1/B2/A2 rounds. A cell worse
by over 3%, or variation exceeding the observed difference, is no benefit.
Default remains OFF regardless of throughput. See
[build and validation](../development/COROCC_BACKEND.md).
