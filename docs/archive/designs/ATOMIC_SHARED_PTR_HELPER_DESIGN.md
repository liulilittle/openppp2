# Atomic Shared-Pointer Helper — Design Document
> Type: Archive
> Last verified: 63fc030

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md) · **Chinese:** [`std::atomic_load/store(shared_ptr*)` 兼容 Helper 设计文档](ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


[中文版本](ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md)

> ID: S-4-HELPER
> Status: **Phase 1 implemented (helper header + docs, no call-site migration)**
> Design date: 2026-05-11
> Implementation date: 2026-05-12
> Related audit: `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4, §16
> Related design: `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` §3.3, §4
> Language standard: C++17
> Implementation: `ppp/net/AtomicSharedPtr.h` (header-only, no .cpp)

---

## 1. Background and Motivation

### 1.1 Current State

The project is locked to C++17 (`set(CMAKE_CXX_STANDARD 17)` in `CMakeLists.txt`). To protect the control-block integrity of `shared_ptr` members during cross-strand/thread concurrent read-write access, the following sites already use `std::atomic_load/store` free functions:

| Member | File | Protection |
|--------|------|------------|
| `WebSocket::socket_` | `ppp/transmissions/templates/WebSocket.h` | `std::atomic_load/store` |
| `ITcpipTransmission::socket_` | `ppp/transmissions/ITcpipTransmission.cpp` | `std::atomic_load/store` |
| `ITransmission::protocol_` | `ppp/transmissions/ITransmission.cpp` | `std::atomic_load/store` |
| `ITransmission::transport_` | `ppp/transmissions/ITransmission.cpp` | `std::atomic_load/store` |
| `VEthernet::fragment_` | `ppp/ethernet/VEthernet.cpp` | `std::atomic_exchange/load` |
| `VEthernet::netstack_` | `ppp/ethernet/VEthernet.cpp` | `std::atomic_exchange/load` |
| `VNetstack::TapTcpLink::socket` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_exchange/load/store` |
| `VNetstack::sync_ack_byte_array_` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_load/store` |
| `VNetstack::sync_ack_tap_driver_` | `ppp/ethernet/VNetstack.cpp` | `std::atomic_load/store` |

Future Firewall RCU rule snapshots (`docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`) will also use this pattern.

### 1.2 Why Not `std::atomic<std::shared_ptr<T>>`

| Dimension | C++17 free functions | C++20 `std::atomic<std::shared_ptr<T>>` |
|-----------|----------------------|------------------------------------------|
| Standard status | Available in C++17 | Available from C++20 |
| C++20 deprecation | Free functions marked `[[deprecated]]` | N/A |
| C++26 removal | **Free functions planned for removal** | N/A |
| Project baseline | ✅ Usable | ❌ Not available |
| CAS support | ✅ `atomic_compare_exchange_*` free functions | ✅ `compare_exchange_weak/strong` |
| Atomic exchange | ✅ `atomic_exchange` free function | ✅ `exchange()` |
| Lock-free | ❌ Global spinlock table | Lock-free on some platforms |

**Conclusion:** The project baseline is C++17; `std::atomic<std::shared_ptr<T>>` is unavailable. Free functions must be used. Introducing a compatibility helper is the lowest-cost preparation for a future C++20 migration.

---

## 2. C++20/C++26 Migration Risk

### 2.1 Deprecation Timeline

| C++ Standard | Free function status | Project impact |
|--------------|---------------------|----------------|
| C++17 | Fully available | ✅ Current baseline |
| C++20 | `[[deprecated]]` | Compiler warnings (`-Wdeprecated-declarations`) |
| C++23 | `[[deprecated]]` | Same; some compilers may default `-Werror` |
| C++26 | **Planned removal** | Compile errors |

### 2.2 Risk Assessment

- **Short-term (C++17 baseline unchanged):** Zero risk.
- **Medium-term (if upgrading to C++20):** Compiler warnings. Suppressible with `-Wno-deprecated-declarations`, or migrate to `std::atomic<std::shared_ptr<T>>`.
- **Long-term (C++26):** If the project upgrades to C++26 without migrating, compile errors will occur.

### 2.3 Compiler Implementation Differences

| Compiler | `atomic_load/store(shared_ptr*)` implementation | Lock-free | Performance |
|----------|-------------------------------------------------|-----------|-------------|
| libstdc++ (GCC) | Global spinlock table (hash table of mutexes) | ❌ | ~20-50 ns/call |
| libc++ (Clang) | Global spinlock table | ❌ | ~20-50 ns/call |
| MSVC STL | Global spinlock table | ❌ | ~20-50 ns/call |

All three major implementations use a global spinlock table, not lock-free. High-frequency paths (per-packet read/write) may experience spinlock contention, but current usage frequency is well below the contention threshold.

---

## 3. Helper API Design

### 3.1 Design Goals

1. **Zero behavioral change:** Existing call patterns are preserved; functions are wrapped by name.
2. **Minimal invasion:** Single header file, zero runtime overhead (inline expansion), no new dependencies.
3. **Grep-friendly migration:** Unified naming allows `grep -r _compat` to locate all call sites for C++20 migration.

### 3.2 API Surface

> **Implementation note:** Phase 1 expanded the API to cover the C++17 `shared_ptr` atomic
> load/store/exchange/CAS free functions needed by this project's migration; it does not wrap
> `std::atomic_is_lock_free`.
> The original design only included `atomic_load_compat` / `atomic_store_compat`. Upon evaluation,
> wrapping `exchange` and `compare_exchange` has near-zero marginal cost (pure inline delegation)
> while the unified naming provides higher grep-searchability and C++20 migration convenience.
> See §3.3 for the updated decision record.

Implementation file: `ppp/net/AtomicSharedPtr.h`

10 inline template functions:

| Function | Standard counterpart | Purpose |
|----------|---------------------|---------|
| `atomic_load_compat` | `std::atomic_load` | Atomic read |
| `atomic_load_explicit_compat` | `std::atomic_load_explicit` | Atomic read (explicit memory order) |
| `atomic_store_compat` | `std::atomic_store` | Atomic write |
| `atomic_store_explicit_compat` | `std::atomic_store_explicit` | Atomic write (explicit memory order) |
| `atomic_exchange_compat` | `std::atomic_exchange` | Atomic swap |
| `atomic_exchange_explicit_compat` | `std::atomic_exchange_explicit` | Atomic swap (explicit memory order) |
| `atomic_compare_exchange_weak_compat` | `std::atomic_compare_exchange_weak` | CAS (weak, spurious failures allowed) |
| `atomic_compare_exchange_weak_explicit_compat` | `std::atomic_compare_exchange_weak_explicit` | CAS weak (explicit memory order) |
| `atomic_compare_exchange_strong_compat` | `std::atomic_compare_exchange_strong` | CAS (strong, no spurious failures) |
| `atomic_compare_exchange_strong_explicit_compat` | `std::atomic_compare_exchange_strong_explicit` | CAS strong (explicit memory order) |

### 3.3 Exchange / CAS Wrapping Decision

> **Design change (2026-05-12):** The original design decided NOT to provide `atomic_exchange_compat`.
> Phase 1 re-evaluation changed the decision to "provide", for these reasons:

1. **Zero additional risk:** Wrappers are pure inline delegates; behavior is identical to direct standard free-function calls.
2. **Unified migration surface:** All `shared_ptr` atomic accesses use the `_compat` naming convention; `grep -r _compat` locates all call sites for C++20 migration.
3. **Exchange semantics are clear:** `atomic_exchange` is a single atomic operation with genuine atomic-swap semantics, fundamentally different from `load + store` (see §4).
4. **CAS future-proofing:** RCU snapshot publishing, lock-free queues, and similar scenarios may require CAS; providing wrappers avoids re-inventing per scenario.
5. **Documentation warnings:** §4 documents the `load + store ≠ exchange` semantic difference and ABA considerations (shared_ptr control-block addresses are typically stable, lowering ABA risk).

| Original rationale | Re-evaluation |
|--------------------|---------------|
| Avoid expanding API surface | 10 inline templates have negligible maintenance cost |
| Exchange call sites need per-site audit | Correct — but this does not prevent providing the wrapper; audit still occurs during call-site migration (phase 2) |
| load+store ≠ exchange | Correct — but providing an exchange wrapper does not mislead; it makes it easier to associate documentation |

### 3.4 Base/Derived Explicit Conversion Rules

When `shared_ptr<Derived>` must be stored into a `shared_ptr<Base>` atomic member, `std::atomic_store` template deduction fails. The helper preserves the same signature constraint — no implicit conversion:

```cpp
// ❌ Compile error: deduction conflict
std::atomic_store(&base_ptr, derived_ptr);

// ✅ Correct: explicit conversion first
std::shared_ptr<Base> base_compatible = derived_ptr;
std::atomic_store(&base_ptr, base_compatible);
```

---

## 4. Take-and-Clear Pattern Limitations

### 4.1 Current Pattern

```cpp
// WebSocket.h Finalize()
std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
std::atomic_store(&socket_, std::shared_ptr<IWebsocket>());

// VEthernet.cpp ReleaseAllObjects()
std::shared_ptr<IPFragment> fragment = std::atomic_exchange(&fragment_, std::shared_ptr<IPFragment>());
```

### 4.2 `atomic_load` + `atomic_store({})` ≠ `atomic_exchange`

The `atomic_load` + `atomic_store({})` pattern is **two independent atomic operations** and does NOT guarantee exactly-once take semantics:

```
Thread A                         Thread B
───────────────────────────────  ───────────────────────────────
local_A = atomic_load(&ptr)     local_B = atomic_load(&ptr)
  // local_A = X                  // local_B = X (same object!)
atomic_store(&ptr, {})          atomic_store(&ptr, {})
  // ptr = null                   // ptr = null
local_A->Dispose()              local_B->Dispose()
  // double-Dispose! ⚠️
```

### 4.3 Why Current Code Is Safe

All take-and-clear patterns are currently protected by external synchronization:

1. **WebSocket::Finalize():** `disposed_.exchange(true, acq_rel)` guarantees one-shot entry.
2. **VEthernet::ReleaseAllObjects():** Executed under strand protection.
3. **VNetstack::TapTcpLink:** Executed under strand protection.

The helper does NOT wrap a pseudo-exchange based on `load + store({})`.

---

## 5. Replacement Scope

### 5.1 Call Sites for Replacement (Phase 2, not yet implemented)

| Call site | File | Replace with |
|-----------|------|-------------|
| `std::atomic_load(&socket_)` | `WebSocket.h` (6 sites) | `ppp::net::atomic_load_compat(&socket_)` |
| `std::atomic_store(&socket_, ...)` | `WebSocket.h` (2 sites) | `ppp::net::atomic_store_compat(&socket_, ...)` |
| `std::atomic_load(&socket_)` | `ITcpipTransmission.cpp` (4 sites) | `ppp::net::atomic_load_compat(&socket_)` |
| `std::atomic_store(&socket_, ...)` | `ITcpipTransmission.cpp` (1 site) | `ppp::net::atomic_store_compat(&socket_, ...)` |
| `std::atomic_load(&protocol_)` | `ITransmission.cpp` (3 sites) | `ppp::net::atomic_load_compat(&protocol_)` |
| `std::atomic_load(&transport_)` | `ITransmission.cpp` (3 sites) | `ppp::net::atomic_load_compat(&transport_)` |
| `std::atomic_store(&protocol_, ...)` | `ITransmission.cpp` (2 sites) | `ppp::net::atomic_store_compat(&protocol_, ...)` |
| `std::atomic_store(&transport_, ...)` | `ITransmission.cpp` (2 sites) | `ppp::net::atomic_store_compat(&transport_, ...)` |
| `std::atomic_load(&snapshot_)` | Firewall RCU (future) | `ppp::net::atomic_load_compat(&snapshot_)` |
| `std::atomic_store(&snapshot_, ...)` | Firewall RCU (future) | `ppp::net::atomic_store_compat(&snapshot_, ...)` |

### 5.2 Exchange Call Sites (ready for helper, future standalone migration)

These sites can use `atomic_exchange_compat`, but they should be migrated as a separate small batch because they often carry exactly-once take-and-clear semantics and require per-site external-synchronization and lifetime review.

| Call site | File | Replace with |
|-----------|------|-------------|
| `std::atomic_exchange(&fragment_, ...)` | `VEthernet.cpp` | `ppp::net::atomic_exchange_compat(&fragment_, ...)` |
| `std::atomic_exchange(&netstack_, ...)` | `VEthernet.cpp` | `ppp::net::atomic_exchange_compat(&netstack_, ...)` |
| `std::atomic_exchange(&socket, ...)` | `VNetstack.cpp` | `ppp::net::atomic_exchange_compat(&socket, ...)` |

---

## 6. Testing Requirements

- **Compile verification:** Header-only addition; must compile on all platforms (Linux/macOS/Windows/Android).
- **Behavioral equivalence:** Wrapper calls are identical to direct `std::atomic_*` calls (guaranteed by inline delegation).
- **Concurrency correctness:** No automated tests exist (`AGENTS.md`: "There are zero tests"). Correctness is by code review only.
- **C++20 migration:** Replace `*_compat` → `member.load()/store()/exchange()/compare_exchange_*()`; delete header.

---

## 7. Implementation Plan

### Phase 1: Add helper header ✅ Completed (2026-05-12)

1. ✅ Created `ppp/net/AtomicSharedPtr.h` (header-only, 10 inline templates).
2. ✅ Covers `atomic_load`, `atomic_store`, `atomic_exchange`, `atomic_compare_exchange_weak/strong` and `_explicit` variants.
3. ✅ Did NOT modify `ppp/stdafx.h` (include on demand at usage sites).
4. ✅ Created English design doc `docs/ATOMIC_SHARED_PTR_HELPER_DESIGN.md`.
5. ✅ Updated this document's status and implementation notes.
6. ✅ No call-site migration (deferred to Phase 2).

### Phase 2: Replace call sites (medium risk, not yet implemented)

### Phase 3: C++20 migration (future)

### Rollback

Each phase is independently rollable. The helper header is a pure addition — deleting it restores the original state.

---

## 8. Related Documentation

| Document | Relation |
|----------|----------|
| `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4 | Predecessor; S-4 proposed the `atomic_load_compat` wrapper |
| `docs/openppp2-deep-code-audit-cn.md` §16 | `shared_ptr` concurrency spec; §3.4 and §4 supplement Base/Derived and exchange constraints |
| `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md` §3.3, §4 | RCU snapshot uses the same `atomic_load/store` pattern |
| `docs/CONCURRENCY_MODEL_CN.md` | Concurrency model overview; this document supplements `shared_ptr` atomic access constraints |

---

## 9. Decision Log

### 9.1 Provide `atomic_load_compat` / `atomic_store_compat`

**Decision:** Provide. Rationale:
- Lowest-cost C++20 migration preparation.
- Unified naming enables grep-based migration.
- Pure wrapper, zero runtime overhead.

### 9.2 Provide `atomic_exchange_compat` / `atomic_compare_exchange_*_compat`

> **Decision change (2026-05-12):** Original decision was "do not provide"; Phase 1 re-evaluation changed to "provide".

**Decision:** Provide. Rationale:
- Zero additional risk (pure inline delegation).
- Unified `_compat` naming enables grep-based C++20 migration.
- `atomic_exchange` has genuine atomic swap semantics; the wrapper does not introduce ambiguity.
- CAS wrappers future-proof for RCU snapshots, lock-free queues, etc.

**Retained constraints:**
- Future standalone exchange/CAS call-site migration still requires per-site external-sync and lifetime audit.
- No pseudo-exchange wrapper based on `load + store({})`.

### 9.3 No Implicit Base/Derived Conversion

**Decision:** Do not provide. Preserves standard `atomic_store` signature constraints.

### 9.4 No `static_assert(__cplusplus >= 202002L)` Error

**Decision:** Do not add. C++20 migration should delete the helper entirely, not trigger static assertions.

---

*Created: 2026-05-11 | Implemented: 2026-05-12*
*Related audit: `docs/openppp2-deep-code-audit-cn.md` §14.6 S-4, §16*
*Related design: `docs/FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`*
*Governance item: S-4 (atomic_load/store(shared_ptr*) compatibility helper)*
