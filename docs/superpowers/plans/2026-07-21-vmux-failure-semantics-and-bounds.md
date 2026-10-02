# VMUX Failure Semantics and Resource Bounds Implementation Plan

> Status: Historical
> Type: Plan
> Last verified: 6b2e915

> **Purpose:** Preserve the worktree-specific VMUX failure-semantics and resource-bounds plan.
> **Audience:** Maintainers investigating the recorded VMUX design and implementation sequence.
> **Status:** Historical worktree-specific execution record; not a current implementation contract.
> **Last verified against:** Saved `fix/vmux-failure-semantics-bounds` plan record, 2026-07-21; historical boundary reviewed 2026-07-22.
> **Parent index:** [Working Plan and Specification Records](../../archive/plans/README.md)

> **Verification warning:** This plan names an isolated worktree and records packages, source paths, test results, and completion states as of that record. Confirm the current checkout and rerun applicable tests before relying on any implementation claim.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-subagent-driven-development (recommended) or superpowers-executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make VMUX failure and resource behavior explicit and safe: no silent stream corruption, no unbounded memory, no multi-link single-point session death without a designed policy—without inventing new scheduler modes.

**Architecture:** Keep competition send + orthogonal ordering. Fix receive semantics first (gap = explicit fail, not skip). Cap session-level reorder/flow resources second. Only then redesign base-link failure isolation together with per-link byte credit. P1/P2 are follow-on plans, not bundled into the P0 PR series.


## Recorded implementation progress (worktree)

- Worktree: `/tmp/openppp2-vmux-p0` (symlink: `openppp2/.worktrees/vmux-failure-semantics-bounds`)
- Branch: `fix/vmux-failure-semantics-bounds`
- Last green: `./bin/vmux_receive_semantics_test` → `ok` (10/10, 2026-07-21)
- Packages landed: **P0-Doc/A/B/C**, **P1-lite**, **P2-1..P2-4**, **P2-6**, **P2-2/3 presentation+caps**
- Remaining: P2-5 deeper strand migration beyond snapshot (optional); P1 full DRR landed
- Note: main checkout on other branches may not contain these commits — use this worktree.

**Tech Stack:** C++17, Boost.Asio strand, existing `ppp/app/mux/*`, Boost.Test under `tests/cpp`, config in `AppConfiguration`, docs EN+CN where paired.

---

## Agent operating rules (mandatory)

### Before starting ANY priority package (P0-Doc, P0-A, P0-B, P0-C, P1, P2)

Re-invoke in this order:

1. **superpowers** (`superpowers-using-superpowers` → then the skill for the phase):
   - design/spec unclear → `superpowers-brainstorming`
   - plan needs rewrite → `superpowers-writing-plans`
   - executing tasks → `superpowers-executing-plans` or `superpowers-subagent-driven-development`
   - before claiming done → `superpowers-verification-before-completion`
2. **ponytail** (`full` unless user says otherwise): ladder, shortest diff, no new modes, no speculative abstractions.
3. Re-read **this plan’s package section** and the **current code** at the listed paths (do not trust memory).
4. If code drifted from this plan, **stop and update the plan** before coding.

### Per-task rules

- One package = one PR series of scoped commits (Conventional Commits: `fix(vmux):`, `feat(vmux):`, `docs(vmux):`, `test(vmux):`).
- TDD: failing test first for every semantic change.
- Do **not** implement P1/P2 while P0-A/B are open unless a P0 task explicitly needs a one-line observability hook.
- Do **not** add a new `mux_mode`.
- Do **not** reintroduce affinity binding.

### Package dependency graph

```text
P0-Doc (resource model doc fix)
    ↓
P0-A (receive state machine) ──→ P0-B (resource bounds)
    ↓                              ↓
    └──────────→ P0-C (link failure + byte credit, joint design)
                      ↓
                    P1 (fairness / turbo / observability)
                      ↓
                    P2 (hygiene / capability / dead code)
```

---

## File map (expected touch set)

| Area | Paths |
|------|--------|
| Core | `ppp/app/mux/vmux_net.h`, `ppp/app/mux/vmux_net.cpp` |
| Socket | `ppp/app/mux/vmux_skt.h`, `ppp/app/mux/vmux_skt.cpp` (reset path, open barrier) |
| Reorder | `ppp/app/mux/MuxFlowReorderBuffer.h` (only if API needs session accounting hooks) |
| Runtime | `ppp/app/mux/MuxRuntimeState.h` (optional later P2 fields) |
| Config | `ppp/configurations/AppConfiguration.h`, `AppConfiguration.cpp` |
| CLI | `ppp/app/ApplicationConfig.cpp` (only if new knobs need CLI) |
| Tests | `tests/cpp/vmux_*.cpp`, new `tests/cpp/vmux_receive_semantics_test.cpp`, `tests/cpp/vmux_resource_bounds_test.cpp` |
| Docs | `docs/archive/designs/MUX_PERFLOW_DELIVERY_DESIGN_CN.md` (+ EN if present), `docs/reference/VMUX_VALIDATION.md` + `_CN.md`, this plan |

---

## Locked product decisions (from analysis)

| Topic | Decision |
|-------|----------|
| Send policy | Competition remains default; no per-connection sticky binding |
| Gap under flow_v2 | **Reset/close that flow only** — never `force_advance` then deliver |
| Gap under compat | Explicit timeout → **session rebuild** (not silent forever stall) |
| Unknown-cid PUSH (flow_v2) | Bounded pre-open **or** immediate drop+metric; never unbounded `flows_[cid]` |
| Multi-link HA | Not claimed; base-link death policy redesigned in P0-C, not “pretend nothing happened” |
| CID epoch | P2 only (wrap risk real, probability low) |
| New modes | Out of scope |

---

# Package P0-Doc — Fix resource model documentation

> **Before coding:** invoke superpowers + ponytail. This package is docs-only.

### Task D1: Correct per-flow memory model in design doc

**Files:**
- Modify: `docs/archive/designs/MUX_PERFLOW_DELIVERY_DESIGN_CN.md` (around the “最坏 max_connections × reorder.bytes” claim)
- Modify: paired EN file if it exists under the same designs folder
- Create/update: short note in `docs/reference/VMUX_VALIDATION.md` + `VMUX_VALIDATION_CN.md` that session reorder bounds are a hard gate once implemented

- [x] **Step 1: Replace wrong bound language**

Wrong (current idea):

```text
worst case = max_connections × flow.reorder.bytes
```

(`max_connections` is **carrier link count**, not logical flow count.)

Correct model to document:

```text
per_flow_reorder_bytes   = mux.flow.reorder.bytes
max_open_flows           = (new) mux.flow.max_open   // logical connections + pre-open
session_reorder_bytes    = (new) mux.flow.session_reorder.bytes
unknown_cid_budget       = (new) mux.flow.unknown_cid.max

worst_case_reorder ≈ min(
  session_reorder_bytes,
  max_open_flows × per_flow_reorder_bytes
)
```

State explicitly:

- `flows_` is keyed by `connection_id`, not by carrier id.
- `flow_evict_expired` must **not** be described as releasing flow entries if it only advances gaps (current code).
- After P0-A, gap timeout **resets flow**, does not skip bytes.

- [x] **Step 2: Add failure-semantics section (short)**

Document three outcomes only:

1. Deliver in-order contiguous data.
2. Drop duplicate/stale frames.
3. **Fail the flow or session** when a gap cannot be recovered (no silent hole).

- [x] **Step 3: Commit** (`b0a051e`)

```bash
git add docs/archive/designs/MUX_PERFLOW_DELIVERY_DESIGN_CN.md docs/reference/VMUX_VALIDATION.md docs/reference/VMUX_VALIDATION_CN.md
git commit -m "docs(vmux): correct flow reorder resource model and failure semantics"
```

---

# Package P0-A — Receive state machine

> **Before coding:** invoke superpowers + ponytail full. Re-read:
> - `vmux_net.cpp` `packet_input_flow`, `flow_force_advance`, `flow_evict_expired`, `packet_input_unorder`, `packet_input_read`, `active`
> - `vmux_skt.cpp` close/input paths

**Goal of package:** One coherent receive policy: **no silent corruption**.

### Task A1: Define flow reset primitive

**Files:**
- Modify: `ppp/app/mux/vmux_net.h`
- Modify: `ppp/app/mux/vmux_net.cpp`
- Modify: `ppp/app/mux/vmux_skt.h` / `vmux_skt.cpp` if local socket needs hard close
- Test: `tests/cpp/vmux_receive_semantics_test.cpp` (create)

- [x] **Step 1: Write failing tests for gap → reset (not deliver)**

Create `tests/cpp/vmux_receive_semantics_test.cpp` using the same Boost.Test style as `vmux_flow_reorder_test.cpp` / integration access patterns from `vmux_net_churn_integration_test.cpp`.

Required cases:

1. flow_v2: receive DSN 1, then 3 (gap 2) past timeout → **connection closed/reset**, **DSN 3 not delivered to skt**.
2. flow_v2: reorder buffer overflow while gap open → same as (1), no hole delivery.
3. flow_v2: single frame larger than per-flow cap → reset or drop-with-fail, **not** advance-and-continue.
4. Telemetry: count `mux.rx.flow.reset` (or chosen name) increments; `mux.rx.flow.evict` must **not** mean “skipped bytes delivered”.

If full `vmux_net` is too heavy for unit tests, extract a testable helper (only if needed; ponytail prefers testing existing entry points via `vmux_net_test_access` friend, as churn test does). Prefer friend test access over new abstraction.

- [x] **Step 2: Run tests — expect FAIL**

```bash
cd openppp2 && bash scripts/run-cpp-tests.sh
# or: ctest --test-dir build/test -R vmux_receive_semantics_test --output-on-failure
```

Expected: FAIL (reset API missing / force_advance still delivers).

- [x] **Step 3: Implement `reset_flow` / `fail_flow`**

In `vmux_net` (strand-affine):

```cpp
// Pseudocode — match local style; names may be reset_flow / fail_connection
void fail_flow(uint32_t connection_id, const char* reason) noexcept {
    // 1) erase flows_[cid] and tx_flow_seq_[cid]
    // 2) if skt exists: skt->close() (sends cmd_fin if still linked — verify current close())
    // 3) telemetry Count("mux.rx.flow.reset", 1) + Log reason
    // 4) do NOT deliver buffered out-of-order payloads for that cid
}
```

Wire protocol note (P0 minimum):

- Prefer **local fail** of the logical connection (close skt + send `cmd_fin` if appropriate).
- Optional new `cmd_flow_reset` is **out of scope for P0-A** unless close/fin is insufficient; if needed, schedule as A1b with peer handling. Ponytail default: use existing fin/close.

- [x] **Step 4: Replace `flow_force_advance` delivery**

Change `flow_force_advance` / callers:

| Caller | New behavior |
|--------|----------------|
| `flow_evict_expired` | `fail_flow(cid, "gap_timeout")` |
| reorder overflow loops in `packet_input_flow` | `fail_flow(cid, "reorder_overflow")` |
| oversize frame path | `fail_flow(cid, "frame_oversize")` |

Delete or gut the “jump `flow_rx_next_` and `deliver_one`” path.

- [x] **Step 5: Tests PASS + commit**

```bash
git add ppp/app/mux/vmux_net.h ppp/app/mux/vmux_net.cpp ppp/app/mux/vmux_skt.* tests/cpp/vmux_receive_semantics_test.cpp
git commit -m "fix(vmux): reset flow on unrecovered gap instead of skipping bytes"
```

### Task A2: Unify `active()` on receive

**Files:**
- Modify: `ppp/app/mux/vmux_net.cpp` (`packet_input_unorder` reorder branch ~801–829)

- [x] **Step 1: Failing test**

Case: compat mode, only future seq frames arrive (gap open) → session `last_` / inactivity clock still advances (or document explicit policy). **Chosen policy:** receiving **any valid framed traffic** (including OOO) proves peer liveness → call `active(now)` on reorder insert path, matching flow_v2.

- [x] **Step 2: Implement**

In `packet_input_unorder` future-seq branch after successful insert (and on duplicate-insert policy), call `active(now)` and `linklayer_update(linklayer)` consistently with in-order path.

- [x] **Step 3: Commit**

```bash
git commit -m "fix(vmux): treat out-of-order frames as session activity in compat"
```

### Task A3: Unknown-cid / pre-SYN data (flow_v2)

**Files:**
- Modify: `vmux_net.cpp` `packet_input_flow`, `packet_input_read`, possibly `process_rx_connecting`
- Config: add `mux.flow.unknown_cid.max` and `mux.flow.preopen.bytes` if buffering chosen

**Policy (pick one in task; default is ponytail-cheap):**

**Default (recommended for P0):**

1. Do **not** create long-lived `flows_[cid]` for unknown cid without a skt.
2. If `cmd_push`/`cmd_fin` arrives and `get_connection(cid)==null` and no pending SYN state:
   - metric `mux.rx.unknown_cid`
   - **do not** prime DSN into a permanent flow entry
   - drop payload
3. Optional small pre-open buffer **only if** SYN is expected soon: cap entries and bytes; on overflow fail that cid; on SYN attach and drain in DSN order; on timeout fail.

**Send-side barrier (preferred complement):**

- In `vmux_skt`, until local open complete (`syn_ok` observed), either:
  - queue first PUSH on same path as SYN with no competition striping, or
  - block data post until `syn_ok` (simple, slight latency).

Ponytail default: **block data post until syn_ok** on initiator; server still needs unknown-cid defense.

- [x] **Step 1: Tests**

1. flow_v2 PUSH to unknown cid does not grow `flows_` unbounded across 10k random cids.
2. Initiator does not post PUSH before syn_ok (if barrier chosen).
3. SYN then PUSH in-order still works.

- [x] **Step 2: Implement + commit**

```bash
git commit -m "fix(vmux): bound unknown-cid receive and open barrier for first data"
```

### Task A4: Compat gap timeout (explicit session fail)

**Files:**
- Modify: `vmux_net.cpp` `update()` maintenance + `packet_input_unorder`
- Config: reuse `mux.flow.reorder.timeout` or add `mux.rx.gap.timeout` (prefer one knob; document)

- [x] **Step 1: Tests**

compat: inject gap, wait past timeout → `close_exec` / disposed, metric `mux.rx.compat.gap_timeout`.

- [x] **Step 2: Implement**

Track oldest buffered OOO tick for global `rx_queue_` (mirror flow_v2’s `oldest_buffered_tick_`). On timeout: log + `close_exec()`.

- [x] **Step 3: Commit**

```bash
git commit -m "fix(vmux): time out unrecovered global reorder gaps in compat"
```

### Task A5: Package A verification

- [x] Run full vmux test filter:

```bash
ctest --test-dir build/test -R 'vmux_' --output-on-failure
```

- [x] Update `docs/reference/VMUX_VALIDATION.md` + `_CN.md`: gap policy is fail, not skip.
- [x] Commit docs if not already.
- [x] Invoke `superpowers-verification-before-completion` before marking package done.

---

# Package P0-B — Resource bounds

> **Before coding:** invoke superpowers + ponytail. Confirm P0-Doc model and P0-A fail semantics landed.

### Task B1: Config knobs

**Files:**
- Modify: `ppp/configurations/AppConfiguration.h` (`mux.flow` nested struct)
- Modify: `ppp/configurations/AppConfiguration.cpp` (defaults, JSON load/save, `Loaded()` clamps)
- Optional CLI: `ApplicationConfig.cpp` only if project already exposes mux flow knobs that way

Suggested defaults (adjust to existing `PPP_MUX_*` macros if present):

```text
mux.flow.reorder.bytes          // existing per-flow
mux.flow.reorder.timeout        // existing
mux.flow.session_reorder.bytes  // new, e.g. 8–32 MiB class default
mux.flow.max_open               // new, hard cap on skts_ + preopen
mux.flow.unknown_cid.max        // new, small
mux.tx.ctrl.budget_frames       // new, e.g. 32 per drain turn
mux.tx.ctrl.budget_bytes        // new, optional
```

- [x] **Step 1: Tests for normalization** (invalid ≤0 → default).
- [x] **Step 2: Implement + commit** `feat(vmux): add session flow resource limit config`

### Task B2: Enforce session reorder + max open

**Files:**
- Modify: `vmux_net.cpp` `packet_input_flow`, `process_rx_connecting`, pre-open path

Rules:

1. Before buffering a future frame, if `session_reorder_bytes + length > cap` → `fail_flow` on the worst offender (oldest gap or largest buffer)—**not** whole session unless policy says so.
2. Before creating skt / flow context, if open count ≥ `max_open` → reject SYN / fail.
3. Unknown-cid path uses `unknown_cid.max` separately and strictly.

- [x] **Step 1: Failing tests** in `vmux_resource_bounds_test.cpp`
- [x] **Step 2: Implement**
- [x] **Step 3: Commit** `fix(vmux): enforce session reorder and open-flow caps`

### Task B3: Control vs data drain fairness

**Files:**
- Modify: `vmux_net.cpp` `process_tx_ctrl_packets`, `process_tx_all_packets`

Change strict “drain entire `tx_ctrl_queue_` first” to budgeted drain:

```text
each process_tx_all_packets invocation:
  send up to ctrl_budget frames/bytes from tx_ctrl_queue_
  then drain data under mode policy
  if ctrl remains and links free, next completion re-enters
```

- [x] **Step 1: Test** — inject many keep_alived/syn-like ctrl frames; ensure at least one data frame sends per N ctrl under artificial single-link credit.
- [x] **Step 2: Implement + commit** `fix(vmux): budget control-queue priority so data is not starved`

### Task B4: Package B verification

- [x] `ctest -R 'vmux_'` + tooling tests if config JSON round-trip covered.
- [x] Docs: resource model numbers match config keys.
- [x] superpowers verification skill before done.

---

# Package P0-C — Link failure isolation + byte credit (joint design)

> **Status: LANDED** (code + tests + design spec `docs/superpowers/specs/2026-07-21-vmux-p0c-link-credit-design.md`)

> **Before coding:** **mandatory** re-run `superpowers-brainstorming` then refresh this package’s plan section if design changes. This is the largest package; do not start from memory.

### Design constraints (inputs)

1. Today base link `forwarding` end → `close_exec()` (`vmux_net.cpp` ~2020–2027).
2. Runtime turbo grow links already best-effort remove without killing session (~1960–1970).
3. `underlyin_sent` completion = local transmission write finished, **not** peer VMUX ACK.
4. Without P3 replay window, **in-flight frames on a dead link are lost** → must **fail affected flows or session**, not silently continue.

### Target policy (proposed; re-confirm in brainstorming)

```text
On link death:
  if remaining non-retiring established links == 0:
      close_exec()  // unavoidable
  else:
      remove_linklayer(dead)
      for each flow with unconfirmed data that was only on that link:
          // P0 without ACK: cannot know precisely
          // pragmatic P0: fail ALL open flows OR rebuild session
      preferred P0 pragmatic choice (pick one, document):
          A) rebuild session (simple, matches current reliability model)
          B) keep session, fail all logical skts (faster reconnect of carriers only)
          C) (P3 only) replay unacked frames on other links
```

**Ponytail P0 recommendation:**  
If any **base** carrier dies: **session rebuild** (A) but **only after** draining accounting; if a **turbo extra** carrier dies: remove link only (already).  
Improve vs today: **do not** treat every base link death as immediate `close_exec` from the forwarding coroutine without distinguishing turbo extras (already partial)—ensure **N-1 base links still up ⇒ do not kill session** only if reliability model allows data loss; if not, still rebuild.  
**Honest P0:** multi-link is for throughput/latency, not HA. Document that. Code change: **turbo extras never call `close_exec`** (done); **base pool: if links remaining ≥ 1, optional continue with session-level fail of all skts** vs rebuild—choose in brainstorming.

**Byte credit (must ship with isolation):**

Per link:

```cpp
queued_bytes
// optional: ewma_write_completion_ms
```

Send only if `queued_bytes + packet_length <= per_link_high_water`.  
On write complete: `queued_bytes -= length`.  
Selection among free links: prefer lowest `queued_bytes` (still competition, not affinity).

### Task C1: Spec freeze

- [x] Brainstorm + write short design addendum under `docs/archive/designs/` or update defects ledger.
- [x] Commit docs only.

### Task C2: Per-link byte credit

- [x] Tests with mock transmission delaying completion.
- [x] Implement counters in `vmux_linklayer` / drain path.
- [x] Commit `feat(vmux): per-link outstanding byte credit`

### Task C3: Link death policy

- [x] Tests: one of two base links dies → assert chosen policy (session rebuild **or** remain with skts failed).
- [x] Tests: turbo extra dies → session remains.
- [x] Implement.
- [x] Commit `fix(vmux): isolate turbo link death; define base-link failure policy`

### Task C4: Package C verification + validation doc

- [x] Update `VMUX_VALIDATION.md` gates for link death policy.
- [x] superpowers verification.

---

# Package P1 — Controllability (after P0)

> **Status: DONE (P1-lite + full DRR)** — turbo dual-threshold hold, turbo select by queued_bytes, per-flow DRR (`tx_flows_`/`active_tx_flows_`), finalize residual metric. Soft single-queue quantum removed.

> **Before coding each task:** superpowers + ponytail.

| Task | Intent | Primary files |
|------|--------|----------------|
| P1-1 | Per-flow TX queues + byte DRR into session ready queue | `vmux_net` TX path, `vmux_skt` post |
| P1-2 | Turbo dual-threshold + hold times; stop using depth-only | `turbo_controller_tick` |
| P1-3 | Heartbeat RTT / write-queue delay signals for first packet | heartbeat path, `select_turbo_linklayer` |
| P1-4 | Observability: queue delay, gap resets, early-ACK residual on rebuild | telemetry + runtime snapshot optional |
| P1-5 | Document acceleration early-ACK as best-effort; metric residual `tx_queue_` on `finalize` | `finalize`, docs |

Do **not** start P1-1 until P0-A/B done (fairness on a broken gap model is wasted).

Each P1 task: own failing tests, own commit series, own verification skill run.

---

# Package P2 — Hygiene (after P1 or parallel if zero behavior change)

> **Before coding each task:** superpowers + ponytail.

| Task | Intent |
|------|--------|
| P2-1 DONE | Delete dead affinity API/state (`select_affinity_*`, `select_balanced_*`, `affinity_links_`) and all cleanups |
| P2-2 DONE | Split runtime presentation: scheduler × ordering × pool (UI/TUI snapshot fields); keep user presets |
| P2-3 DONE | Negotiate `supported_caps` vs `requested` features (not “non-compat ⇒ advertise”) |
| P2-4 DONE | CID epoch or session-local non-reuse policy + wrap tests |
| P2-5 | Strand-owned mutability audit; snapshot for cross-thread reads |
| P2-6 DONE | Harden `cmd_mux_mode_set` (default off, rate limit); forbid hot ordering switch without session rebuild |

P2-1 is safe early **only** as a pure delete PR with compile + tests green—may land after P0-A if it reduces confusion (ponytail: yes, delete early).

---

# Test matrix (minimum)

| Case | Package |
|------|---------|
| flow_v2 gap timeout → no hole delivery | A1 |
| flow_v2 overflow → reset | A1 |
| compat OOO refreshes activity | A2 |
| unknown cid cannot grow flows unbounded | A3 |
| compat gap timeout closes session | A4 |
| session reorder cap enforced | B2 |
| max open flows enforced | B2 |
| ctrl budget allows data progress | B3 |
| turbo link death ≠ session death | C3 |
| base last link death → session death | C3 |
| negotiation old peer still falls back | existing `vmux_negotiation_test` must stay green |
| carrier churn 100-cycle | existing churn test stays green |

Commands:

```bash
cd openppp2
bash scripts/run-cpp-tests.sh
# focused:
ctest --test-dir build/test -R 'vmux_' --output-on-failure
```

---

# Explicit non-goals

- New `mux_mode_*`
- Full SACK / multi-link lossless migration (post-P0, optional P3)
- QUIC transport
- Changing production default away from `compat`
- Reintroducing affinity

---

# Suggested PR series

1. `docs(vmux): resource model + failure semantics` (P0-Doc)
2. `fix(vmux): gap fails flow` (P0-A1)
3. `fix(vmux): compat OOO activity + gap timeout` (P0-A2/A4)
4. `fix(vmux): unknown-cid bounds + open barrier` (P0-A3)
5. `feat(vmux): session resource limits + ctrl budget` (P0-B)
6. `feat(vmux): link death policy + byte credit` (P0-C)
7. P1/P2 PRs as separate series

---

# Self-review (writing-plans checklist)

| Spec item | Task coverage |
|-----------|----------------|
| No silent gap delivery | A1 |
| compat slow-death / activity inconsistency | A2, A4 |
| unknown-cid / SYN barrier | A3 |
| unbounded memory / wrong doc model | P0-Doc, B1–B2 |
| ctrl starve data | B3 |
| multi-link session kill | C3 |
| credit = local write | C2 + docs |
| no new modes / keep competition | Non-goals + all packages |
| re-invoke superpowers+ponytail per P | Agent operating rules |

Placeholder scan: no TBD implementation steps; P0-C retains a **forced design confirmation** step (intentional—must re-brainstorm).

---

# Execution handoff

Plan saved to:

`openppp2/docs/superpowers/plans/2026-07-21-vmux-failure-semantics-and-bounds.md`

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task; between tasks re-run review; **each new P package starts with superpowers + ponytail**.
2. **Inline Execution** — `superpowers-executing-plans` in this session with checkpoints after each package.

**Which approach?**

When implementing, for every package header above, the worker must literally:

```text
1) Skill: superpowers-using-superpowers (+ phase skill)
2) Ponytail full
3) Re-read package section + current code
4) Then execute tasks
```


## Progress notes (2026-07-21)

- Full per-flow byte DRR replaces session-global `tx_queue_` (`enqueue_flow_tx` / `drr_pop_next` / `drr_requeue_front`).
- P2-5 snapshot: `runtime_snapshot_` published under mutex/strand; `get_runtime_state()` prefers atomic load.
- Verified: `vmux_receive_semantics_test` (includes DRR yield after quantum).
