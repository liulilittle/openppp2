# Concurrency Model
> Status: Active
> Type: Architecture
> Last verified: `ppp/threading/`, `ppp/coroutines/`, and runtime startup sources, 2026-07-22
>
> **Purpose:** Describe the executor and coroutine mechanisms that current source actually provides.
> **Audience:** Contributors modifying asynchronous code.
> **Parent index:** [Architecture](README.md) · **Chinese:** [并发模型](CONCURRENCY_MODEL_CN.md)

## Scope and non-goals

The native runtime is asynchronous and uses Boost.Asio, but it does not establish one universal session-thread or session-strand model. This page documents the process-wide mechanisms and their limits; it is not a promise of lock-free packet processing, fixed throughput, or one-thread-per-core behavior.

## Executor topology

`ppp::threading::Executors` owns process-wide executor state initialized from global runtime setup.

| Context | Creation and use |
|---|---|
| Default `io_context` | Attached by `Executors::Run()` and driven by the calling thread. The application start callback is posted here. |
| Worker contexts | Created by `SetMaxThreads()`; each has a managed worker thread and a cached buffer. `GetExecutor()` rotates through them and falls back to the default context when none exists. |
| Scheduler context | Created once by `SetMaxSchedulers()` and driven by scheduler threads. Socket migration can bind a socket to a strand on this context. |
| Tick thread | Maintains cached time and periodic low-level work while executor internals remain live. It is detached; source does not demonstrate a joined tick-thread shutdown contract. |

`AppConfiguration::concurrent` defaults to the processor count, but startup does not impose a source-level CPU-count cap. It requests scheduler threads when `concurrent - 1` is positive; worker contexts are requested on non-client startup paths. Treat the resulting topology as configuration-dependent.

Cached buffers are 64 KiB for the default and worker contexts. The scheduler context is not documented by the implementation as having the same cached-buffer registration.

## Asynchrony and serialization

`YieldContext` is the project’s custom stackful coroutine wrapper built on Boost.Context (`make_fcontext` / `jump_fcontext`). Its default stack size is 128 KiB. VMUX also has separate code that uses `boost::asio::spawn`; do not write as if all asynchronous code uses one coroutine mechanism.

A strand serializes handlers only when a caller supplies one. `Executors::Post` and `YieldContext::Spawn` both accept an optional strand. `ShiftToScheduler()` creates a strand while moving an open TCP socket into the scheduler context, but this does not prove that every object, callback, or session in the program is strand-bound.

## Lifecycle implications

- Executor shutdown posts stop operations for known contexts, joins managed worker threads, attempts netstack shutdown, then stops scheduler and default contexts.
- `Executors::Awaitable` is a condition-variable bridge that blocks until `Processed()` is called. It has no cancellation wake-up path in the current implementation.
- `YieldContext` state transitions are guarded internally, but callers still need to preserve the ownership and dispatch requirements of the surrounding object.
- `nullof<T>()` is implemented with a null-address reference convention. It exists in current code, but this documentation makes no portable-safety claim about that convention and does not recommend new uses.

## Practical rules for changes

These are review rules derived from the implementation boundaries, not runtime-enforced guarantees:

1. Do not block a default, worker, or scheduler `io_context` with synchronous I/O or an unbounded wait.
2. Do not assume a raw object pointer remains valid after posting work; follow the local owner’s existing `shared_ptr`/`weak_ptr` pattern.
3. Preserve a supplied strand when extending a serialized path; do not silently infer that every path has one.
4. Keep locks away from operations that can yield or invoke external callbacks unless the local implementation explicitly proves that design safe.
5. Treat `Awaitable::Await()` as a blocking bridge for a caller that can safely block, not as a general coroutine substitute.

## Related boundaries

- [EDSM State Machines](EDSM_STATE_MACHINES.md) explains runtime-state presentation.
- [Startup and Lifecycle](STARTUP_AND_LIFECYCLE.md) explains the default executor ownership.
- [Telemetry and Observability](OTEL_DESIGN.md) documents the optional backend; it is neither lock-free nor a compile-out guarantee in this tree.
- [Engineering Concepts](ENGINEERING_CONCEPTS.md) records shared ownership vocabulary.
