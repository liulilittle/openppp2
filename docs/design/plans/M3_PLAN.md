# M3 Plan: In-Stack Large Segments and Multi-Core

> Status: Implemented (A-stage) / plan snapshot
> Type: Plan
> Last verified: 2026-10-18

Planning snapshot: 2026-10-18. No implementation, build, throughput measurement,
or commit is part of this planning task. The next implementation agent should
work through section 8 in order; proposed APIs, files, switches, and thresholds
below are design decisions, not claims that they already exist.

## 1. Scope, Evidence, and Dependencies

Repository HEAD inspected: `418da99d54360a557d4aaa1e9f5139c86e75cf8b`
(`test(xtcp): assert netem full-duplex echo`). Initial status contained only the
untracked brief. WSL Git requires the brief's `GIT_DIR`/`GIT_WORK_TREE` override.
GitNexus CLI/MCP tools were unavailable; analysis used source, callers, build
definitions, and runner code. No GitNexus impact checks are claimed.

Read-only inputs:

- Main checkout's untracked `docs/design/THROUGHPUT_OPTIMIZATION_PLAN_CN.md`,
  especially WS2 2.3-2.5, WS3 3.3-3.5, and M3 acceptance.
- This tree's `docs/design/XTCP_INTEGRATION_CN.md`, sections 11.4, 11.4.1a/b,
  11.174/175, and the English integration document's output-lanes section.
- `docs/architecture/MULTIQUEUE_TUN_MODEL.md`: a proposal/older implementation
  description, not evidence that explicit CPU/queue affinity exists today.
- The m1b checkout's `build/winplan/rebuild-windows.cmd`, read only. Its embedded
  worktree/output paths must never be used for an M3 build.

The allowed `tools/prepare_xtcp.sh` was run only in this worktree to inspect the
pinned, patched vendor source. Current pin is `e79db8fd10a1ee39be2dc3a9361727fcad79d04c`,
patches 0001-0034. The prepared source/cache are ignored local inputs.

What the latest evidence actually establishes:

| Finding | Consequence for M3 |
| --- | --- |
| Historical 1512-byte Timestamp retransmit rejection fixed by option-aware payload sizing; current fixed-cell tests passed | Preserve the strict 1500-byte ordinary-output guard and exact retransmit bytes |
| P64 wedge not reproduced on the current revision; old reproducing binary unavailable | Retain P64 regressions; do not attribute its disappearance to an unproven patch |
| Two shards serialized through one coalescer; per-shard lanes removed that serialization | Keep lanes and their per-FD readers; do not rebuild the old shared coalescer |
| WSL2 P16 DL cap32: 3129 -> 4919 Mbps for 1 -> 2 shards; P64 DL: 3005 -> 4571 | Directional scaling evidence, only two rounds, not a remote B-board acceptance |
| WSL2 P1 DL cap32: 497 -> 390 Mbps for 1 -> 2 shards | Auto-sharding needs a P1 regression gate; more shards do not parallelize one TCP flow |
| Default coalescer cap now 32; explicit cap 1-48; opt-in DL profile still 48 | Freeze cap32/100us for primary M3 comparisons; avoid redoing PR #94 |
| cap48 stall stress passed 20 rounds each at shards1/2; cap32 stress, lane+ledger, lane+NDI TSO, and latency unverified | These are distinct required validation cells, not inherited passes |

External dependencies, without editing or duplicating their work:

- M2 stage 1 owns WS1 1.4 direct low rounds and WS2 2.2 GRO 13-16 KiB cliff.
  Request its frozen revision, raw results, ACK/rwnd/credit timeline, allocation
  failures, and `resume_requested/effective` explanation. Early evidence that
  12-16 KiB all use the same 32 KiB tier rules out a simple tier-boundary theory;
  it does not rule out pool exhaustion, credit timing, or ACK/window effects.
- M1 1.5 owns rebase to upstream `77d4558`, dropping 0016-0022/0024/0030 as
  appropriate. Do not perform that rebase here. Record actual resolved pin and
  ordered patch hashes before implementation validation. Any M3 vendor change
  is a new patch after the stack present at that time (currently next is 0035),
  never an unrecorded edit solely in `third-party/xtcp`. Revalidate after rebase.
- WS3 3.1 batching and 3.2 earlier-deadline timer behavior already exist here:
  preserve them. WS3 3.6 three-thread single-flow pipeline is outside M3.

## 2. Current Call Paths and Ownership

TAP -> stack:

```text
TapLinux::{AsynchronousReadPacketLoops,LaneReadLoop,Ssmt}
  -> TapLinux::OnInput -> ITap::OnInput -> VEthernet packet-input dispatch
  -> VEthernetNetworkSwitcher::OnPacketInput(ip_hdr*,...)
  -> XtcpRuntime::SubmitIPv4Tcp -> Impl::Submit
  -> per-Shard handoff vector + handoff_sync + handoff_posted
  -> asio::post(shard.strand) -> DrainIngress -> ProcessIngress -> backend.Inject
```

`Submit` routes SYN and subsequent packets by the same four-tuple hash. Invalid
parses route to shard0 for existing validation/drop behavior. Laboratory two-shard
source-port routing is not a production balancing policy. GRO splitting reserves
all subitems before publishing the batch. Current ingress limits per shard are
1024 items/8 MiB; overrides allow items 1024-65536 and bytes 8 MiB-1 GiB.

Stack -> second leg (upload, including the production direct bridge):

```text
Impl::OnReceive (owning shard strand)
  -> XtcpUploadBudget::TryReserveFor
  -> XtcpSecondLegHooks::SendToPeer
  -> VEthernetNetworkTcpipConnection::SendToPeer
  -> VirtualEthernetTcpipConnection::SendDirectToPeer
  -> direct_upload_queue_ under direct_sync_
  -> OnReceive/FlushDeferredIngressWork -> FlushPeerSend -> FlushDirectPeerSend
  -> StartDirectUploadWriterIfNeeded -> StartDirectUploadWriter
  -> Executors::Post(context_,strand_) -> RunDirectUpload -> SendBufferToPeer
```

Production hooks already return `BatchesPeerSend()==true`. The writer already
wakes once per ingress batch, gathers payloads, and retains upload credit through
carrier completion. Current local cap is 4096 packets/32 MiB per connection, with
half-cap low watermarks; runtime-wide upload bytes default to 32 MiB. Connector
fallback instead uses `Flow::write_queue`, `StartWrite`, and socket completion on
the shard strand: there is no new cross-thread SPSC to insert into that path.
Direct download uses `RunDirectDownload`, reservation/completion identity,
`OnSecondLegPayload`, and a separate direct-read queue; WS2 2.5 owns that change.

Current shard count is 1 unless `OPENPPP2_XTCP_SHARDS` parses within 1-8. Invalid
values fall back to 1 (`atol` currently accepts numeric prefixes). With count>1,
all shard strands share one `own_context_` and N `xtcp-io` threads. Any shard may
run on any worker. A strand is a serialized execution domain, not a fixed TID.
With count1, runtime uses the external context and creates no private worker.

`TapOutputLaneScope(i)` wraps owning/borrowed/retained output from shard i when
N>1. `TapLinux::CurrentGsoOutputLane/CreateGsoOutputLane/OpenSecondaryQueue` lazily
open a queue FD, coalescer, timer, descriptor, and read buffer. All current lane
read descriptors/timers use `TapLinux::GetContext()`, not the shard executor.
Lanes require active GSO merge and no SSMT for creation; GSO-off is not currently
a first-class per-shard input-queue configuration. Maximum lane slots is 16,
distinct from the runtime's 8-shard limit. On disable, existing lanes flush then
write unmerged on their original FD. Kernel automq return steering makes keeping
every live lane reader essential.

## 3. WS3 3.4: Bounded SPSC Handoff and Wake Protocol

### 3.1 Component and API

Add a C++17 header-only `ppp/threading/SpscHandoff.h`, keeping the queue independent
of sockets, Asio, XTCP, and packet formats. Check existing Boost availability
before implementation: prefer `boost::lockfree::spsc_queue` for established ring
storage where its type/lifetime API fits the move-only ingress item. Otherwise
use a small move-aware fixed-storage ring; do not force copies of `BufRef` merely
to fit an API. The protocol below is required whichever storage is chosen.

Proposed surface (names may follow local conventions):

```cpp
enum class PushResult { Accepted, Full, Closed };
enum class DrainResult { Item, Empty, Closed };
// Configured capacity, no per-push allocation inside the ring.
SpscHandoff<T>(size_t capacity, uint64_t epoch);
PushResult TryPush(T&& item);       // failure leaves item/credit with caller
PushResult TryPushBatch(T* items, size_t count); // all-or-none publication
DrainResult TryPop(T& item);        // exactly one logical consumer
bool CommitWake();                 // flush batch; requests adapter wake if needed
bool ArmWaitAndRecheck();           // consumer only; true means it must yield
void RequestClose();               // orderly control signal, wakes empty consumer
void Abort();                      // reject producers, arrange consumer cleanup
// Counters/snapshots do not expose unsynchronized slots.
```

Separate the scheduling gate from storage if that makes tests simpler; supply
an Asio adapter with `PostDrain(epoch)` and a serialized-producer adapter for
ingress. Require nothrow moves/destruction. Close/abort never free storage while
producer, consumer, callback, or carrier write still owns it. No reset/reuse until
both sides quiesce; allocate a fresh epoch for restart.

**Producer cardinality is an implementation gate.** Multiple TUN readers/SSMT
can call `Submit` concurrently. Replacing `Shard::handoff` with an unguarded
single ring would be incorrect. For the first patch use one ring per shard and
a short producer-side mutex covering capacity reservation, batch publication,
and wake commitment. The consumer never takes this mutex. This is a serialized
producer adapter around SPSC, not a lock-free MPSC claim. It preserves the
current per-shard publication order even if a flow's input queue changes. A
mutex-free producer fast path is permitted only when setup proves all ingress
calls use one serialized executor, not by observing one TID in a benchmark.
Do not switch between adapters on a live ring.

The second-leg ring is one per direct connection, allocated lazily at bridge
start, with producer = owning shard strand and consumer = exactly one carrier
writer coroutine. Shard worker migration is allowed because the strand orders
producer operations. All test hooks and alternate callers must obey the same
serialization or use the producer adapter. Finalize/Dispose are control callers,
never an extra thread that pops or clears the live ring.

### 3.2 Memory Ordering and No-Lost-Wakeup Argument

Ring storage contract: producer owns tail and free slots; consumer owns head and
occupied slots. Construct items before tail publication (`release`); consumer
loads tail with `acquire` before reading. Destroy/move items before publishing
head (`release`); producer loads head with `acquire` before reuse. Own-index loads
may be relaxed. Use monotonic unsigned indices with a documented wrap invariant
(capacity < half the index range), bounded-distance arithmetic, and separate
cache-line storage for head/tail. Publish a GRO batch with one tail release only
after every slot is ready. Padding is a cache consideration, not synchronization.

Use an atomic scheduling gate with states `Running`, `Waiting`, `Scheduled`,
`Closed`, initially `Waiting`. `Waiting` means no consumer execution or pending
I/O is responsible for checking the queue; `Scheduled` means exactly one drain
callback is committed. Serialize drain callbacks on the consumer executor.

1. After publishing, `CommitWake` performs an **acq_rel RMW even when Running**:
   CAS Running->Running or Scheduled->Scheduled, retrying on interference;
   Waiting->Scheduled wins the obligation to post one drain. Do not replace the
   same-state RMW with a relaxed load/early return. That RMW is part of the
   publication-versus-wait handshake. Closed rejects new work under the lifetime
   protocol. One batch calls CommitWake once; single sends commit immediately.
2. The posted callback validates epoch and claims Scheduled->Running with an
   acq_rel CAS. Stale/duplicate callbacks do nothing. Drain a bounded quantum.
3. When apparently empty, consumer changes Running->Waiting with an acq_rel RMW,
   then rechecks tail with acquire **and checks close/control state**. If work is
   present, reclaim Waiting->Running and continue. If it instead finds Scheduled,
   return and let the already committed callback run. Never overwrite Scheduled
   with Waiting or start a second coroutine.
4. If the last producer RMW preceded the consumer's arm RMW, the acquire side of
   the arm observes the earlier publication (possibly through the RMW chain),
   and the recheck finds work. If publication/commit follows the arm, the producer
   transitions Waiting->Scheduled and posts. If publication is between arm and
   recheck, either consumer reclaims Running or leaves the Scheduled callback in
   charge. There is always a drain owner for a committed nonempty queue.
5. While `Write(y)` or an intentional gather timer is outstanding, leave the
   consumer Running: that completion is its wake source. New data needs no extra
   post. When a quantum expires with work remaining, consumer itself changes
   Running->Scheduled and posts one continuation; this is a fairness yield,
   not an idle notification. Always flush deferred peer sends before yielding.

The batch API must make wake commitment unavoidable on every scope exit that
published accepted items (RAII batch guard is suitable). Existing
`BatchesPeerSend/FlushPeerSend` remain the public batch boundary; close also
commits any accepted tail. Uncommitted work may wait only until that synchronous
batch ends, never until a timer or a future unrelated packet.

Asio `post` is the first production adapter; it matches both existing consumers
and works on Windows/Android. No blocking wait on an Asio worker and no spinning
until a producer arrives. A failed post cannot leave Scheduled latched forever:
mark the endpoint terminal, reject admissions, and schedule teardown via its
existing lifetime owner; retain ownership until cleanup can drain/discard it.
If scheduling itself is unavailable, an explicit quiescent owner must reclaim
after in-flight producer/consumer references have ended. Test this failure path.

Linux eventfd is an optional adapter only if later profiling justifies it:
NONBLOCK+CLOEXEC, write only on Waiting->Scheduled, drain reads to EAGAIN, retry
EINTR, and treat write EAGAIN as an already pending readable notification. Keep
one asynchronous descriptor wait and the same gate/epoch protocol. A condition
variable is appropriate only for a dedicated blocking consumer: predicate and
wait registration under its mutex; a bare notify plus atomic empty test is not
sufficient. Neither adapter is required for the initial patch; test them only
if implemented. C++20 atomic wait is unavailable in this C++17 project.

### 3.3 Capacity, Backpressure, Ownership, and Fairness

- Ingress ring usable capacity equals the configured item limit (default 1024;
  non-power-of-two overrides retain their logical limit even if backing storage
  rounds upward). Retain `XtcpIngressBudget` byte/item admission. Reserve all GRO
  split slots and credits before moving any items, or reject the entire batch.
  Full means the existing counted packet-drop/fail-closed behavior, never a
  blocking TAP callback, silent fallback to native, or unbounded overflow deque.
  Release admission on dispatch, rejection, and abandoned epochs exactly once.
- Ingress quanta start at 64 packets or 256 KiB, whichever is first; check an
  optional 100us time budget when diagnostics are enabled. Flush deferred writer
  and timer work at each quantum; repost once if more work remains. Numbers
  are starting experimental bounds, not throughput claims.
- Direct ring capacity starts at the existing 4096-item limit. Preserve 32 MiB
  local bytes and the runtime-wide `XtcpUploadBudget`, including retained
  in-flight chunks: freeing a ring slot must not release payload credit early.
  Full returns Backpressured before copying borrowed bytes. Keep half-cap low
  watermarks, release payload/reservations after carrier completion, then notify
  the existing `OnSecondLegWritable/AttemptResume` path. Test capacity-wait
  registration racing a release even if byte limits are not exhausted.
- Consumer gathers by popping into a bounded local in-flight vector; preserve
  the existing gather cap/wait settings and same-budget credit merge semantics.
  No random access to producer-owned ring slots. Do not increase gather delays
  or chunk sizes in the queue patch.
- Close means stop admissions, drain accepted payload, wait for pending carrier
  bytes/items, then ShutdownSend once. Abort may discard, but releases every
  queued/in-flight reservation exactly once and completes every waiter terminally.
  Close/control is out-of-band and cannot be blocked by a full data ring. Protect
  callback registration and close state with the existing small control mutex;
  removing all `direct_sync_` uses is not a goal.
- Lazy 4096-slot per-flow rings cost approximately `4096*sizeof(slot)` even when
  little data is queued. At 16 bytes/slot this is 64 KiB per active direct flow,
  4 MiB at P64, 256 MiB at 4096 flows, before payloads. Measure actual slot sizes;
  add a bounded runtime descriptor-memory admission pool (proposed 16 MiB initial
  budget), separate from payload credit. If exhausted, select the existing
  bounded mutex/deque backend **before that flow starts**; no live backend switch
  and no unbounded allocation. Report which backend was active. Revisit ring
  capacity only as a separate measured policy change.

### 3.4 Exact Edit Boundaries and Deterministic Tests

Implementation file/function list:

| File | Planned changes |
| --- | --- |
| `ppp/threading/SpscHandoff.h` (new) | Move-aware storage, scheduling gate, serialized producer adapter, epoch/lifetime contract |
| `ppp/app/client/xtcp/XtcpRuntime.cpp` | `Shard` handoff members; both `Submit` split/ordinary branches; `DrainIngress`; preserve `FlushDeferredIngressWork`, `OnReceive`, readiness, `Stop`, `DoStopShard/DoStopFinalize` cleanup |
| `ppp/app/client/xtcp/XtcpRuntimePolicy.h` | Only necessary admission integration; retain generation and byte/item limits |
| `ppp/app/protocol/VirtualEthernetTcpipConnection.{h,cpp}` | Direct queue state, `StartDirectBridge`, `SendDirectToPeer`, `StartDirectUploadWriterIfNeeded`, `FlushDirectPeerSend`, `RunDirectUpload`, `CloseDirectSend`, `Finalize` |
| `ppp/app/client/VEthernetNetworkTcpipConnection.{h,cpp}` and `xtcp/XtcpFirstLegHooks.h` | Preserve SendToPeer/FlushPeerSend/BatchesPeerSend contract; only required ownership/wake API plumbing |
| `ppp/app/runtime/RuntimeXtcpStats.h`, stats serializer/tests | Add bounded queue/wake counters and backend selection without removing old fields |
| `tests/cpp/CMakeLists.txt`, `ppp.vcxproj`/filters if needed | Register tests and new shared headers using existing conventions |

Verify the actual production direct queue, not only the synthetic DirectSecondLeg
in `xtcp_runtime_bridge_test`. Extract a narrow queue-state helper used by the
production connection and unit tests, or link a focused production-backed test;
test duplication that never invokes production queue logic is insufficient.

New focused targets: `spsc_handoff_test`, `xtcp_handoff_lifecycle_test`,
`xtcp_direct_handoff_test` (proposed). Extend existing
`xtcp_runtime_adapter_test`, `xtcp_runtime_bridge_test`, `xtcp_upload_budget_test`,
`yield_context_test`, and Windows lifecycle coverage where applicable.

Use C++17 barrier/latch helpers and a fake scheduler with explicit step hooks,
not sleeps to arrange races. Bound all waits with diagnostic watchdogs. Cases:

1. Capacity 1/2, non-power-of-two logical limits, wrap/reuse, move-only payloads,
   exact FIFO sequence, payload checksum, constructor/destructor counts.
2. Producer publishes (a) before arm, (b) between arm and recheck, (c) after final
   empty recheck, (d) while Scheduled, (e) during drain, (f) while Write is pending.
   Require eventual consumption with no additional traffic/timer, one scheduled
   drain owner, no duplicate writer, and no notification for busy-only batches.
3. Explicitly force Running->Running producer RMW before the consumer arm; model
   all bounded gate/publish interleavings. Tests do not by themselves prove all
   weak-memory executions: retain the happens-before argument above, then run
   on ARM64 when available. TSan detects data races, not lost-wakeup correctness.
4. Two serialized ingress producers targeting the same shard; mixed GRO and
   ordinary packets; exact publication FIFO; all-or-none split failure; caller
   retains items on rejection. Exercise a single flow arriving on different FDs.
5. Full data ring with close/abort, consumer parked with close, stop during post,
   post throw/failure, stale callbacks after restart, delayed carrier completion,
   teardown on own worker, worker migration. No use-after-free or stale budget
   release into a new epoch; all counters/credits return to zero.
6. Credit-release-before-wait-registration and registration-before-release;
   low-water resume is neither lost nor duplicated; gather preserves bytes,
   credit, FIN ordering, and failure cleanup. Include descriptor-budget fallback.
7. Quantum continuation under a continuously publishing producer; a second flow
   and timer both progress within a bounded number of deterministic dispatches.

Run these normally and under a separate TSan build; run ownership/lifetime cases
under separate ASan/UBSan too. Do not suppress a new handoff race to get a pass.

## 4. WS3 3.3: Default Shards, Fairness, and Scaling

Implement a pure policy helper, proposed `xtcp/XtcpShardPolicy.h`, plus tests.
Initial candidate on Linux desktop:

```text
effective_cpus = max(1, min(online CPUs intersect startup allowed affinity,
                            effective cpuset, floored CPU quota when available))
auto_shards = clamp(floor(effective_cpus / 2), 1, 8)
```

Use process-allowed CPUs, not `hardware_concurrency()` alone or host `/proc/cpuinfo`
count. Treat missing topology/quota discovery conservatively and report the
inputs; fractional quotas below one yield one. The halving reserves capacity
for vnet/carrier/other work; it is a candidate policy, not proof of physical
core availability. Prefer distinct physical cores for experimental mappings,
but record SMT topology and keep explicit 1-8 overrides supported.

Configuration precedence: explicit `OPENPPP2_XTCP_SHARDS=1..8` wins; exact `auto`
or unset selects the platform default. Add
`OPENPPP2_XTCP_AUTO_SHARDS=0` as a clear rollback to 1 when no explicit count is
set. Parse entire strings; invalid nonempty values warn and choose 1. Read once
at startup, never in packet hot paths. No live re-sharding: hash modulus,
generation tags, queued work, and flow state remain fixed until a complete stop.
Report requested/effective policy, CPU inputs, shard count, worker count, and
fallback reasons in stable runtime metadata. The existing environment surface
is sufficient for M3; persistent JSON schema/UI changes are unnecessary.

Rollout: implement auto policy behind an opt-in first; promote the unset Linux
default only after section 7 gates pass. Windows and Android retain unset=1
pending their platform baselines; explicit 1-8 remains supported. One-core/strict
A runs must explicitly select 1. Native/lwIP never create XTCP workers because
of this option. Startup must account for runner affinity **before** computing
auto count: the current cpuset profile pins after startup and must be fixed or
given an explicit startup CPU envelope, otherwise auto sees the whole host.

Do not add load-dependent live flow migration or change the four-tuple hash in
the default-policy patch. Diagnose skew first; P1 necessarily uses one shard.
Preserve the 16 lane slots and lazy per-shard lane fallback. Enabling N shards
does not enable GSO; if GSO is off/unsupported or lanes are disabled, record that
condition and evaluate scaling separately. A failed lane must keep its current
shared fallback and must not steal an established flow's FD.

Collect low-cost per-shard cumulative packets/bytes, active/data-bearing flows,
enqueue/dispatch/drop counts, queue items/bytes/highwater, wake posts/coalesces,
batch sizes, and deferred writer flushes. Current perf already exposes some
enqueued/dispatched/injected/dropped and queue-delay data; extend, do not duplicate.
Sample strand-owned state on that strand (as `WriteShardFlowPerfLine` already does).
For diagnostics add queue-delay p50/p95/p99, poll lateness, shard handler CPU-time
or sampled service time, assigned CPU/current TID, budget wait age, and lane
fallback/FD/write/merge counts. Worker CPU usage is not automatically shard CPU
usage under the shared pool. Keep detailed timing default-off.

Report per-flow min/p10/p50/p90/max, zero-rate count, retransmits when actually
available, and Jain fairness `(sum x)^2/(n*sum x^2)`. Report per-shard active-flow
distribution, max/mean bytes and service time, and coefficient of variation.
Exclude idle shards from work-skew interpretation but show them in occupancy.
At P1 or P4 with 8 shards, imbalance is expected and is not a hashing defect.
P64 diagnosis must separate hash occupancy skew from per-flow congestion/rwnd
effects. No rebalance just because byte totals differ.

## 5. WS3 3.5: Linux Queue and CPU Affinity

### 5.1 Execution Mapping and Configuration

Affinity remains opt-in and applies only to this runner's PPP process/threads.
Never pin host processes, ksoftirqd, physical IRQs, or another agent's PPP.
Proposed startup-only knobs:

- `OPENPPP2_XTCP_AFFINITY=off|workers|queues` (default off).
- `OPENPPP2_XTCP_IO_CPUS=<ordered distinct CPU IDs>`: exactly N for strict
  per-shard queue mode; worker mode may use an explicitly documented shared set.
- `OPENPPP2_TAP_LANE_RX_CPUS=<ordered IDs>`: optional per-lane mapping, initially
  required to equal the shard worker map in queue mode. Do not create another
  N reader threads just to honor a different map in M3.
- `OPENPPP2_XTCP_AFFINITY_STRICT=1`: requested mapping failure aborts startup;
  non-strict mode reports degraded/unpinned behavior. The measurement runner
  always uses strict mode and records the effective mapping.

Reject offline, duplicate (strict one-per-shard), malformed, or out-of-envelope
CPU IDs. Validate against a captured startup affinity envelope and quota; do
not reinterpret a single already-pinned thread mask as the whole allocation.
No changes to cgroups, host cpusets, governor, Turbo, or system proxy.

Stage A, smaller patch: pin the existing `xtcp-io` **worker pool** with
`pthread_setaffinity_np` before `run()`. Name workers with indices for evidence.
Pin the common vnet/lane-read executor to a chosen runner-owned CPU, leaving
the application/carrier CPU allocation explicit. This measures pool affinity
only; all lane readers still share an executor, so do not label it per-shard
or per-queue affinity. Read back every affected TID.

Stage B, required to claim true queue affinity: opt-in queue mode gives each
shard its own single-worker `io_context`, work guard, and strand. Bind that
shard's stack callbacks, connector sockets, retry/resume/poll timers, and budget
wakes to it. Update `Flow` construction in `StartFlow`, timer construction in
`SchedulePoll`, `InitializeUploadBudget`, perf aggregation, and all stop/failure
paths; do not just pin the shared pool and assume shard i stays on TID i.
Runtime-wide telemetry can use shard0 for coordination, with snapshots posted
to the other owners. Keep the count1 external-context behavior unless queue
mode is explicitly requested and its lifecycle contract is tested.

Expose a narrow startup binding hook through `XtcpRuntime.h` and
`ClientConnectionOpener.cpp` so `TapLinux` can obtain lane i's executor and
lifetime token. Register before traffic/ready. `CreateGsoOutputLane` constructs
its descriptor and hold timer on that executor; `LaneReadLoop` executes on that
pinned worker. `OpenSecondaryQueue` still attaches only to the same named TUN;
the executor binding must not create a new interface or configure host routes.
Keep lane index separate from kernel rx-N/tx-N number and record real queue
inventory; never assume FD lane index equals a kernel sysfs queue index.

Moving `OnInput` wholesale onto these workers would change policy, fragments,
UDP/ICMP, and switcher concurrency. Preserve its current owner: copy/retain each
read envelope before rearming the FD, then pass it through a bounded
serialized-producer handoff to the existing vnet executor, where `OnInput` and
all policy checks run in their original order. Reuse section 3's component, with
a global 1024-item/8 MiB staging bound initially, round-robin reader service,
explicit full/drop counters, and credits held until parsing dispatch. This
extra read->vnet->shard hop is a measurable cost of the conservative queue-mode
prototype. Do not bypass business-policy checks for a supposedly fast TCP path.
Only a later audited change may dispatch eligible TCP directly on a queue owner.

This mode adds an executor per shard, not per flow. Keep all FD readers active,
including after GSO disable. SSMT and explicit queue-affinity mode are mutually
exclusive initially: reject the combination explicitly; normal SSMT behavior
continues with affinity off. Preserve ordinary output fallback and ordering.
Queue mode initially requires multi-queue/VNET/GSO lane capability; GSO-off
scaling uses Stage A/off, and unavailable queue mode is recorded as unsupported,
never silently scored as successfully pinned.

Teardown order: close admissions; cancel reads/timers on their owner executors;
drain their completion handlers and vnet envelopes; close descriptors; detach
lane bindings; stop stacks/backends; release work guards only when no external
completion can post more work; join workers from a non-self owner (retain the
existing safe self-destruction behavior). Partial startup unwinds only created
objects. A failed queue open affects its shard and is an explicit qualification
failure when strict queue mode was requested.

### 5.2 Kernel Steering and Measurement

RPS/XPS is **runner configuration**, not application startup behavior. Extend
`tools/datapath_cpu_isolation.py`, runner metadata/qualifier, and their tooling
tests to map the actual TUN/veth queue inventory to the selected CPUs. Act only
on interfaces proven to belong to the current cell's netns. Enter that netns
and mount a namespace-correct sysfs view in its private mount namespace before
resolving `/sys/class/net/...`; `ip netns exec` alone is not sufficient proof
that an inherited sysfs mount exposes the intended namespace.

Snapshot -> apply -> readback before formal start, and again after lazy lane
creation; compare-and-restore in reverse before interface deletion. Apply only
to actual rx-*/rps_cpus and tx-*/xps_cpus files. Missing features are unsupported,
not imaginary successful writes. Record FD/lane and kernel queue maps separately;
if the kernel cannot establish a correspondence, use an explicit cell CPU-set
mask and label that as device-wide steering rather than invented per-lane RPS.

`/proc/irq/*/smp_affinity` is host-global even inside netns. Never write it. TUN
and veth normally have no hardware IRQ; record N/A. If an associated physical
IRQ unexpectedly appears, stop that affinity experiment rather than touching
it. The existing helper supports IRQ writes, so the M3 path must explicitly
disable those writes; namespace entry does not make them safe. No global RPS
socket-flow tuning, irqbalance, physical NIC changes, or host sysctl tuning.

Compare affinity off, Stage A worker pinning, and Stage B queue pinning with
identical shards/CPU budget/GSO settings. Measure p50/p95/p99 handoff and loaded
latency, migrations/context switches, process task-clock ns/B, selected CPU
non-idle, throughput, per-queue reads/drops/writes, coalescer segments/write,
poll lateness, and queue skew. Changing reader executors may cost more than it
saves; retain the opt-out and reject a regression. Test CPU-list parsing and
mock pin failures without touching network state, then validate real mappings
only on the remote runner's processes.

## 6. Deferred WS2 Items: Explicit Start Rules

These remain separate changes after M2 evidence and M1 patch-stack convergence.
They are part of full M3 acceptance, but they must not block the independent
queue/policy unit-test work. None is justified merely by finishing WS3.

| Item | Design sketch | Required M2 evidence and decision to start |
| --- | --- | --- |
| 2.3 bounded 64 KiB pool tier and large ingress | Add a capped pool tier and update `kMaxPoolPayload`, GSO ingress/segment views, admission, and retained ownership. Preserve logical MSS segments for ACK/SACK/RTO accounting; a larger processing buffer is not a larger ordinary wire packet. | M2 2.2 must explain/remove the 13-16 KiB collapse and provide a stable >12 KiB sweep, allocation/credit/window attribution, and per-segment CPU cost. Start only if segmentation/copy or the actual 32752-byte payload ceiling remains material after that fix and fixed-byte A/B predicts benefit. If ACK/window/credit is still the bottleneck, fix that first and defer the tier. |
| 2.4 NDI TSO | Trace direct and buffered `TcpConnection` TSO gates, emitted supersegments, MSS fallback, loss/recovery, and `XtcpNdiBackend`/`TapLinux::OutputGsoLane`. Design recoverable logical segment views for multiple outstanding TSO ranges before relaxing any gate. | Needs accepted 2.3, M2 stable baseline/no low-round anomaly, and gate telemetry showing outstanding/recovery fallback dominates the negative TSO result. Start only if it identifies a concrete avoidable cost; if window/cwnd/pacing dominates, do not relax recovery gates. Keep `OPENPPP2_XTCP_NDI_TSO_TX` off until loss/reorder/PMTU/FIN/RST and lane+TSO validation plus repeated product benefit. |
| 2.5 direct download larger blocks/multiple in-flight | Retain reservation identity `(runtime_generation, flow_generation, sequence, length)`, add bounded in-flight byte/item credits, separate producer-credit release from TCP rwnd reopening, and preserve FIFO and exactly-once completion across partial Send/close. | M2 1.4 must account for low rounds and `resume_effective=0`; provide byte/time/credit/rwnd timelines and stable P1/P64. Start only if the receiver can replenish producer credit without waiting on a window update dependent on that same credit, and residual handoff stalls are measured. Otherwise do not repeat the rejected four-credit/window=2 experiments. |

Specific 2.3 anchors: patched `third-party/xtcp/src/buf/bufref.cpp` has pool sizes
2048/4096/32768 and counts 8192/4096/128; large-tier TLS cache cap is zero.
`include/xtcp/buf/bufref.h` has a 16-byte block header, so the current maximum
usable payload is **32752**, not 32768. A 65536-byte block provides 65520 usable
bytes, still short of a maximum-size 65535-byte IPv4 packet. Choose and document
either segmentation at that boundary or an aligned block size that accommodates
the full L3 frame plus pool header; never claim all 64 KiB frames fit without
checking. Account for packet headers, not just TCP payload size.

Bound the new tier by a configurable global byte/block ceiling and upload/ingress
reservations; example starting budget 8 MiB = 128 64-KiB blocks, **process-wide**,
not per shard, with actual charged allocation size including headers. Preserve
32-KiB fallback if admission fails and it can preserve semantics. Do not let TLS
caches hoard sparse large blocks. Tests cover tier boundaries/exhaustion,
cross-thread final release, restart leases, fragments/options, ACK/FIN ordering,
RTO exact bytes, PMTU, and fairness/pacing for short flows. Rewrite this sketch
against the post-M1.5 pool implementation before adding a new vendor patch.

Specific 2.4 anchors: `third-party/xtcp/src/core/tcp_fsm.cpp` direct and buffered
TSO paths require an empty retransmit queue and no fast recovery; stack capability
selection is in `src/core/stack.cpp`. The single-flight restriction protects
recovery. Diagnose using existing direct/flush gate counters before changing it.

Specific 2.5 anchors: `VirtualEthernetTcpipConnection::RunDirectDownload`,
`DirectReadWaiterState.h`, `XtcpRuntime::OnSecondLegPayload`, reservation helpers,
`StartRead` and direct-read completion paths. Current default chunk is 16 KiB,
optional 32 KiB; direct-flow pending bytes are capped at 32 KiB and runtime direct
reads at 32 MiB. First change credit semantics under deterministic unit tests;
only then screen larger chunks/windows with constant total byte budget. Measure
extra memory and short-flow latency separately. Historical 32-KiB window=2 was
rejected; it is not an approved starting optimization.

## 7. Future Build, Validation, and Measurement Commands

### 7.1 Location and Isolation Contract

**Do not execute this section during the planning task.** Heavy Linux builds,
unit tests, and all measurements go to `<lab-user>@<lab-host>:/home/ppp-m2/m3/` only.
No writes/builds in `/home/openppp2` or any other agent's directory, and no
dependency installs or process termination outside the run's own PIDs. An
existing populated `m3` directory must be inspected/preserved; use a unique
run subdirectory rather than replacing it. Stage this worktree's source with
`rsync`/archive excluding `.git`, all private/runtime configs, credentials,
existing build/bin/artifacts, vendor caches, and platform application-data
backups. Use an explicit reviewed source manifest; do not copy ignored local
files indiscriminately and do not use `rsync --delete`. Record source diff hash,
HEAD, dirty filenames, patch hashes, and archive manifest because the source is
uncommitted. Keep private logs/config artifacts under the run directory with
restricted permissions; summaries must not print connection URLs or secrets.

Discover remote tools/versions, CPU topology/allowed set/quota, compiler/TSan
support, and native dependencies read-only first. Do not assume `/root/dev` or
the local machine's libraries exist remotely. Provision no missing packages
as part of this plan; record a concrete environment blocker if required.

The existing matrix and E2E scripts create veth pairs in their caller namespace
before moving them and use `/etc/netns` plus temporary state. Therefore wrap
**the entire runner** in a fresh outer network AND mount namespace, not just PPP.
Create a private propagation tree, bind separate run-local empty `etc-netns` and
`run-netns` directories onto `/etc/netns` and `/run/netns`, and mount sysfs for
the isolated network view. The host mountpoint directories must already exist;
do not create them on the host as an implicit setup step. All backing files are
prepared under the run directory; existing mountpoint paths are overmounted
only inside the private mount namespace. Set `TMPDIR` there. Both namespace
registration files and their bind mounts then remain private: mount propagation
alone would not isolate filesystem creation below a shared `/run/netns`.
Preflight support before spawning PPP; if unsupported,
fix the runner to create links directly inside its owned netns instead of
weakening this boundary. No PPP/iperf server outside the inner cell netns.

Use the shared lock for **every** measurement, including standalone component
throughput, fault-suite benchmarks, latency, and stress/NetEm regression. Do not
unlink/recreate another agent's lock. Compilation can happen without this lock
but use limited jobs and coordinate resource-heavy builds so they do not
contaminate another agent's formal measurements. All descendants must finish
before the lock releases. Cleanup only recorded PIDs and owned namespaces.

Future wrapper shape, to implement/review inside M3 (proposed script name):

```bash
# Remote shell; RUN is an existing unique directory below /home/ppp-m2/m3.
cd "$RUN/src"
flock /tmp/ppp-m2-measure.lock \
  bash "$RUN/src/tools/run_m3_isolated.sh" --run-dir "$RUN" -- \
  bash tools/run_datapath_linux_matrix.sh <validated arguments below>
```

`run_m3_isolated.sh` is not present yet. It must perform the outer `unshare
--net --mount` setup above, namespace/TID ownership checks, private mounts, and
cleanup checks, with mocked command tests asserting no link/route/DNS/sysctl
mutation is issued in the initial host namespace. Add the same wrapper to E2E
commands. Do not paste an unwrapped runner command into a remote root shell.

### 7.2 Remote Offline Checks and Builds

Example future commands inside a reviewed staged source tree. `RUN`, `SRC`,
`NATIVE_DEPS`, and `JOBS` are task-specific variables; `JOBS=2` is a reasonable
initial shared-machine limit. Resolve absolute paths and assert all output
directories are beneath `$RUN` before executing. Dependencies may be read from
a verified installed location; nothing there is modified.

```bash
cd "$SRC"
bash tools/check_include_boundaries.sh
bash tools/check_vcxproj_sources.sh
XTCP_SOURCE_DIR="$SRC/third-party/xtcp" bash tools/prepare_xtcp.sh

cmake -S tests/cpp -B "$RUN/build/unit" -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_XTCP_TESTS=ON \
  -DXTCP_SOURCE_DIR="$SRC/third-party/xtcp"
cmake --build "$RUN/build/unit" --parallel "$JOBS"
ctest --test-dir "$RUN/build/unit" --output-on-failure --no-tests=error

cmake -S tests/cpp -B "$RUN/build/tsan" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_XTCP_TESTS=ON \
  -DENABLE_TSAN=ON -DENABLE_SANITIZERS=OFF
cmake --build "$RUN/build/tsan" --parallel "$JOBS"
TSAN_OPTIONS="suppressions=$SRC/tests/cpp/tsan_suppressions.txt halt_on_error=1" \
  ctest --test-dir "$RUN/build/tsan" --output-on-failure --no-tests=error \
  -R '^(spsc_handoff|xtcp_handoff_lifecycle|xtcp_direct_handoff|xtcp_runtime_adapter|xtcp_runtime_bridge|xtcp_upload_budget|yield_context)_test$'

cmake -S tests/cpp -B "$RUN/build/asan" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_XTCP_TESTS=ON \
  -DENABLE_SANITIZERS=ON -DENABLE_TSAN=OFF
cmake --build "$RUN/build/asan" --parallel "$JOBS"
ctest --test-dir "$RUN/build/asan" --output-on-failure --no-tests=error \
  -R '^(spsc_handoff|xtcp_handoff_lifecycle|xtcp_direct_handoff|xtcp_runtime_bridge)_test$'

cmake -S . -B "$RUN/build/release" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_XTCP=ON \
  -DENABLE_SIMD=ON -DENABLE_SSEA_SIMD=OFF \
  -DTHIRD_PARTY_LIBRARY_DIR="$NATIVE_DEPS" \
  -DPPP_OUTPUT_DIR="$RUN/bin/candidate"
cmake --build "$RUN/build/release" --target ppp --parallel "$JOBS"

PYTHONDONTWRITEBYTECODE=1 python3 tests/tooling/test_datapath_linux_matrix.py
```

The new target names in regexes are proposed and must be registered before these
commands; check `ctest -N` for every required target, since one regex match does
not prove all requested tests exist. Root shared-production queue tests may
need a dedicated linked target in addition to standalone tests. The convenience
`scripts/run-cpp-tests.sh`/`run-cpp-tsan-tests.sh` default to standalone suites
without `ENABLE_XTCP_TESTS`; they alone do not validate this change. Confirm
vendor objects are TSan-instrumented too for cross-library race claims; otherwise
report that limitation. Runtime TSan startup failures are not passing tests.

Upstream correctness: configure `third-party/xtcp` in a separate build directory
with `XTCP_BUILD_TESTS=ON`, `XTCP_BUILD_BENCH=ON`, `XTCP_BUILD_SAMPLES=OFF`,
`XTCP_BUILD_PLUGINS=OFF`, `XTCP_BUILD_LWIP=OFF`, `XTCP_BUILD_CC_PLUGINS=ON`, and
`XTCP_CHECKSUM_VALIDATE=ON`; build and run its full CTest suite, preserving the
counts/failures for the actual M1.5 patch stack. Any registered test that runs a
throughput/load benchmark also requires the measurement lock, even if selected
through CTest; keep those tests out of an unlocked offline subset. The existing
alternative below
also runs `bench_throughput`, so it belongs to the **locked measurement queue**:

```bash
XTCP_SOURCE_DIR="$SRC/third-party/xtcp" \
XTCP_FAULT_BUILD_DIR="$RUN/build/xtcp-fault" XTCP_FAULT_JOBS="$JOBS" \
  flock /tmp/ppp-m2-measure.lock bash tools/run_xtcp_fault_suite.sh --full
```

Build an independent control binary from the reviewed pre-M3 snapshot under
`$RUN/control-src` with identical toolchain/options/dependencies and its own
build/output directories. Never use a stale binary from another worktree as
the matched control. Record both SHA-256 values, compiler, resolved vendor pin,
patch stamp, CMake cache flags, AES dispatch, and all experimental environment.

### 7.3 Local Windows and Android Impact

When shared code changes, run local Windows x64 MSBuild from an adapted M3-only
script modeled on the read-only m1b reference. Prepare the vendor library in
this worktree, `/MT`, VS2022 `-A x64 -T host=x64`, tests/benches disabled for
the production vendor build, CC plugins/checksum validation enabled. Verify
the installed `x64-windows-static` triplet; do not invoke vcpkg install.

```bat
rem From the configured x64 VS developer environment, M3 worktree only.
MSBuild ppp.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 ^
 /p:PreferredToolArchitecture=x64 /p:VcpkgTriplet=x64-windows-static ^
 /p:PppEnableXtcp=true ^
 /p:PppXtcpLibrary=<worktree>\build\winplan\xtcp-win\Release\xtcp_static.lib ^
 /p:VcpkgEnableManifest=false /p:VcpkgManifestInstall=false ^
 /p:OutDir=build\winplan\msbuild\ /p:IntDir=build\winplan\msbuild-int\ /m:2
```

Adapt every absolute path, `WORKTREE`, output, and log directory in the reference
into M3; do not run that other checkout's script. Drivers remain packaging
inputs only: no install, launch, adapter, DNS, or active-binary replacement.
The brief puts heavy unit-test execution remotely; use Windows compile/link
checks here and Linux executions remotely. If Windows-specific runtime behavior
requires its lifecycle tests, document it as unverified under this task's
location rule rather than silently running local unit tests.

Shared queue/policy headers must compile on Windows and Android without eventfd,
pthread/Linux-affinity includes leaking into common code. Windows has no Linux
multi-queue TUN lanes; keep its external-context count1 and cubic behavior,
explicit shard override, and tested loopback bridge fallback. Android normally
uses one VpnService FD, no validated multi-queue TUN; retain default1, packet
ownership/protect behavior, and battery/thermal constraints. Cross-compile ARM64
shared code remotely only when a complete existing NDK/Boost/OpenSSL/Flutter
dependency set is available under the authorized output layout; otherwise list
the missing prerequisite. No Android dependency installation or device launch
is authorized here. ARM memory-order correctness and mobile throughput/energy
remain required later platform evidence, not inferred from x86 TSan.

### 7.4 Locked Regressions and B-Board Experiments

Use the isolation wrapper from 7.1 for every matrix/E2E command. Illustrative
runner arguments below exist today; proposed policy/affinity knobs require new
runner options that clear inherited environment, inject values only into owned
client/server processes as intended, and save requested/effective values. Never
let a parent shell setting silently select lanes, shard routing, or GRO size.

Initial regressions, through the wrapper:

```bash
# Existing E2E, including NetEm, byte integrity, tail FIN, RST, churn, and soak.
PPP_BIN="$RUN/bin/candidate/ppp" \
OPENPPP2_NAMESPACE_ARTIFACT_DIR="$RUN/artifacts/e2e" \
  bash tests/integration/linux/xtcp_tap_netns_e2e.sh

# Repeat for --xtcp-shards 1,2,4,8; cap32 then diagnostic cap48.
bash tools/run_datapath_linux_matrix.sh \
  --ppp-bin "$RUN/bin/candidate/ppp" --artifacts "$RUN/artifacts/stall-s2-cap32" \
  --stacks xtcp --parallel 16 --directions dl --tap-gso on \
  --tap-gso-segments 32 --xtcp-shards 2 --xtcp-memory-bridge \
  --rounds 20 --duration 10 --omit 2 --iperf-timeout 42
```

Follow with P64 DL GSO off/on 30s+2s, at least five rounds, shards1/2/4/8;
lane+ledger diagnostic cells; close/stop/restart under load; bounded queue
overflow; mixed short/long flows; delayed/loss/reorder/MTU NetEm inside cell
interfaces. Do not turn on NDI TSO for primary runs. Run lane+TSO only after
section 6 gates or as an explicitly opt-in compatibility diagnostic, never as
an implied acceptance of 2.4. Every test must prove payload/tunnel path, not
merely observe a process or startup log. Qualification failures retain artifacts.

**B-board primary matrix:** P1/P4/P16/P64 x DL/UL x shards1/2/4/8, paired native
comparator, GSO off and on. Freeze GSO-on cap32/100us, memory bridge explicitly
on, client.concurrent=1, AES-256-CFB, CC fixed, and a single M2-approved GRO,
sndbuf/chunk/gather profile. First test existing defaults (including current
gather wait); evaluate any tuned profile in a separately labeled matrix.
For each resource budget K=1/2/4/8 allowed client CPUs, sweep all shard counts;
mark S>K as oversubscription diagnostics, never evidence of core scaling. Also
report operational budgets large enough for S workers plus a vnet/carrier CPU,
up to S+1 CPUs when available. If fewer CPUs are allowed, do not invent the
missing eight-core scaling data.

Use `client-cpuset` for multicore B data. Existing `client-vnet-isolated` both
pins non-vnet threads onto a residual CPU set and enforces approximately one
PPP process core; it is unsuitable unchanged for general multicore acceptance.
Preserve that historical profile; extend the B cpuset runner/qualifier instead.
In queue-affinity experiments its generic TID pinning must not overwrite the
application's per-worker mapping. Capture startup/formal-start/formal-end and
late-created lane workers, verify masks, and require all TIDs remain within the
allocated envelope. Cross-CPU migrations are permissible in an unpinned cpuset
run; pinned per-queue runs require effective per-TID mappings.

Example one budget/shard slice, only through the outer wrapper and after the
runner startup-mask/mapping changes described above:

```bash
bash tools/run_datapath_linux_matrix.sh \
  --ppp-bin "$RUN/bin/candidate/ppp" --artifacts "$RUN/artifacts/b-k4-s2" \
  --stacks native,xtcp --parallel 1,4,16,64 --directions dl,ul \
  --tap-gso off,on --tap-gso-segments 32 --tap-gso-hold-us 100 \
  --xtcp-shards 2 --xtcp-memory-bridge --client-concurrent 1 \
  --cpu-profile client-cpuset --affinity-cpus "$M3_CPU_LIST" \
  --process-perf-stat --system-cpu-stat \
  --rounds 3 --duration 45 --omit 2 --paired-performance-gate off
```

`M3_CPU_LIST` must contain four verified CPUs for this example, selected from
the remote allocation, not copied from WSL history. Add an auto/unset-policy
slice separately; explicit `--xtcp-shards` cannot validate automatic selection.
The fixed native/XTCP canonical order rotates between rounds, but interleave
control/candidate configurations ABBA and rotate shard/budget slice order too.
Screen at 15s x2 before the full 45s x3 matrix; advance only viable candidates.
Keep profiling/ledger-on runs separate from low-overhead scoring. A 4-budget,
4-shard, 4-P, 2-direction, 2-GSO, 2-stack, 3-round matrix is 1536 cells before
controls/affinity modes: queue campaigns incrementally, not one unattended run.

Every cell records binary/revision/source-diff fingerprint, actual effective
shards, workers/queues/backend, allowed and assigned CPUs/topology/quota, flow
hash policy, GSO requested/active/cap/hold, bridge/NDI flags, formal interval,
payload bytes, goodput, process cores, task-clock ns/B, selected non-idle ns/B,
RSS/highwater, per-flow and per-shard fairness, queue/wake counters, and cleanup.
System-wide selected task-clock is capacity, not busy CPU and not a CPU ranking.
Keep server/target capacity and CPU placement stable and record them; if either
saturates, classify the cell bottleneck rather than blaming client scaling.
DL iperf JSON may omit retransmits: obtain sender TCP_INFO/ss in diagnostic
runs or report unavailable, never substitute zero.

Predeclare proposed promotion criteria before formal runs:

- All cells pass Route3 stack/GSO/payload/affinity/restore/MTU invariants, no
  watchdog, no zero-rate flows, no accepted-byte loss, leaked credits, or leaked
  namespaces. Missing lane/pinning/runtime proof invalidates the relevant claim.
- For P16/P64 within available resources, report speedup G(K)/G(1), marginal
  G(2K)/G(K), Mbps per allocated CPU and per used process core. Candidate target:
  at least 1.5x at two client CPUs and 2x at four in DL, with a positive eight-CPU
  increment unless independently identified peer/carrier capacity saturates.
  Do not assert linear scaling; report UL separately and retain regressions.
- Auto policy must keep paired P1 UL/DL and already-good cells within 5% of the
  matched count1 control in each formal round, and improve the intended multi-
  flow cells beyond observed control MAD/noise. The documented P1 DL regression
  can block promotion: keep default1/opt-in auto if it persists. Raising the
  global default is not a substitute for improving single-flow DL.
- Jain fairness must not fall by more than 0.02 versus matched control for P>=4;
  per-flow p10 must stay within 5% unless total throughput/fairness tradeoffs are
  explicitly reviewed. P64 excessive active-shard skew triggers diagnosis,
  not a silent discard of the round.
- Idle and loaded 512-byte TCP_NODELAY ping-pong plus short transfers: p95/p99
  no more than 10% worse than matched control (apply a predeclared absolute
  noise floor from the control), no starvation. Measure alongside bulk traffic
  only inside the owned cell netns. Add a runner latency probe if no suitable
  existing one covers this; throughput alone cannot qualify wake batching.
- Full M3 requires reproducible P1 DL improvement: proposed >=10% goodput over
  matched pre-M3 control in each of three 45s rounds and consistent ABBA direction
  with bounded CPU/memory/latency cost. Use section 6's gated large-unit work if
  WS3 alone cannot deliver it. Otherwise report WS3 complete but M3 acceptance
  pending; never declare the entire milestone achieved from multi-flow results.

These proposed percentages make the next experiment decidable; they are not
historical requirements already measured. If control noise exceeds a threshold,
improve isolation/repeat a predeclared campaign before choosing a winner. Never
drop a failed or low round simply because a median looks favorable.

## 8. Ordered Checklist for the Implementation Agent

### A. Code and Offline Tests, No Throughput Measurement Required

1. [ ] Re-read current branch/status/brief/instructions; preserve local files.
   Confirm M1.5/M2 evidence by read-only coordination; do not modify their trees.
   Recheck callers/impact with GitNexus if available/current, otherwise rg.
2. [ ] Stage reviewed source/dependency fingerprints into a unique remote
   `/home/ppp-m2/m3/<run>/`; verify tools, dependencies, and output boundaries.
3. [ ] Implement storage + scheduling gate + serialized-producer adapter and
   deterministic race tests. Review the RMW/arm/recheck proof before integration.
4. [ ] Replace per-shard ingress vector in both Submit branches; preserve GRO
   atomic admission, generation checks, batch-end hooks, and cooperative drain.
5. [ ] Replace the production direct-upload data handoff; preserve control lock,
   gathered writes, byte/item credits, close barriers, and bounded descriptor
   memory/fallback. Test actual production helper and stale/failure paths.
6. [ ] Add pure CPU/shard policy, strict parsing, runtime metadata, rollback, and
   fairness counters. Keep Linux auto opt-in and Windows/Android unset=1.
7. [ ] Implement Stage A worker pinning and parser/mock-affinity tests. Then
   implement opt-in Stage B executor/lane binding plus bounded read-envelope
   handoff and stop/start failure tests; do not claim shard affinity before it.
8. [ ] Implement reviewed outer namespace/mount wrapper and runner startup masks,
   per-queue RPS/XPS ownership checks, IRQ-write prohibition, new env scrubbing,
   metadata and cpuset qualification. Mock-test no host mutations and cleanup,
   including private `/run/netns` registration and `/etc/netns` DNS backing files.
9. [ ] Run remote focused normal/TSan/ASan tests, standalone suite with XTCP
   enabled, full upstream correctness tests excluding throughput invocation,
   tooling tests and source-boundary checks. Run local M3-only Windows MSBuild
   for shared changes. Record Android compile feasibility and all missing checks.
10. [ ] Review diffs against source fingerprints and secrets/artifact boundaries.
    Freeze matched control/candidate binaries. No commit. Hand off a queued
    measurement manifest with exact flags, counts, CPU budget, and success gates.

### B. Measurements and Runtime Regressions, Shared Lock Required

1. [ ] Acquire `/tmp/ppp-m2-measure.lock` for each campaign, after other agents.
   Reverify CPU allocation/namespace support and no contaminated build load.
2. [ ] Run isolated E2E and cap32/cap48 stall stress, P64 DL wedge, lane+ledger,
   close/churn/backpressure and NetEm gates. Reject correctness failures first.
3. [ ] Run component handoff diagnostics (including `xtcp_runtime_bridge_test
   --throughput` if useful) remotely under lock; use them only as C-board evidence.
   Run the fault-suite helper's benchmark under this same serialization rule.
4. [ ] Screen fixed shards1/2/4/8 x P1/P4/P16/P64 x DL/UL, GSO off/on with native
   comparators and matched CPU budgets; collect skew and loaded latency. Test
   affinity off/Stage A/Stage B separately on viable slices.
5. [ ] Formal 45s x3 and ABBA comparisons for surviving policies/configurations;
   preserve every round, qualification, memory and fairness/latency metric.
6. [ ] Evaluate the auto-policy promotion gate, including startup CPU count,
   late-thread affinity, memory and P1 regression. Keep opt-in if it fails.
7. [ ] Consume M2 results and the final M1.5 patch stack. Apply section 6's start
   rules independently to 2.3, then 2.4, and 2.5. New vendor patches follow the
   current stack; each has offline correctness tests before queued measurements.
8. [ ] Repeat affected product/correctness cells after vendor rebase or large-unit
   changes. Demonstrate P1 DL reproducibility; if deferred gates remain closed,
   record partial WS3 delivery and the exact remaining M3 dependency.
9. [ ] Produce the result table and recommended defaults with platform limits,
   fingerprints, artifacts, failing cells, and unverified items. Verify all owned
   processes/namespaces are gone and restoration passed. Do not commit or deploy.

## 9. Risks and Completion Boundaries

Main correctness risks are treating multiple ingress producers as SPSC, weak
memory wake races, concurrent ring cleanup, early credit release, lost terminal
signals on full queues, post failure, and private-executor teardown. Main
performance risks are a remaining producer mutex, always-on atomic RMW cost,
larger fixed ring memory, too-long drain quanta, cache bouncing from shared
workers, extra queue->vnet->shard dispatch, hash skew, and affinity concentrating
carrier/ACK work. Keep CPU quota, SMT, NUMA, thermal and shared-host contention
visible; namespace isolation does not provide dedicated CPUs.

Large segments risk latency/pacing bursts and incorrect MSS/retransmit semantics;
multiple download credits risk receiver-window deadlock. Platform-specific
queue/affinity paths stay conditional; shared ownership/wake semantics must work
on ARM and Windows even when Linux queue mode is unavailable.

This planning task creates only this plan as a new reviewable document, plus
the explicitly permitted ignored XTCP preparation inputs. It does not alter the
brief or tracked source, run builds/tests/measurements/PPP, change host network
state, install drivers, modify another worktree, or make a commit. Future work
must report checks actually executed and all unverified runtime/platform behavior.
