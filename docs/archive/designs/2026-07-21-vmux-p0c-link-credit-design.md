# VMUX P0-C Link Exit + Byte Credit Design

> Status: Archived
> Type: Design
> Last verified: 6b2e915

> **Purpose:** Preserve the P0-C link-exit and byte-credit design snapshot.
> **Audience:** Maintainers investigating VMUX design history.
> **Status:** Archived worktree-specific design evidence; not current runtime guidance.
> **Last verified against:** Preserved 2026-07-21 worktree record and archive placement, 2026-07-22.
> **Parent index:** [Archived Designs](README.md) · **Related working record:** [status-bound specification](../../superpowers/specs/2026-07-21-vmux-p0c-link-credit-design.md)

> **Archive notice:** Branch, worktree, implementation, and test claims below are historical evidence. Confirm the current checkout and tests before relying on them.

**Recorded status (2026-07-21):** Approved for implementation (plan lock + user: implement through P1)
**Recorded branch/worktree:** `fix/vmux-failure-semantics-bounds` @ `/tmp/openppp2-vmux-p0`

## Goals

1. Multi-link is **throughput/latency**, not HA. Document that.
2. A carrier exit must **not** always kill the session if other live carriers remain.
3. Track **per-link outstanding bytes** so credit is not only “one async write slot”.
4. Write-complete remains local socket acceptance, not peer ACK (unchanged truth).

## Link exit policy

```text
on_link_exit(link):  // vmux strand
  remove_linklayer(link)
  dispose connection if present
  if count(active links: handshake_complete && !retiring) == 0:
      close_exec()
  else:
      metric mux.link.exit.isolated
      process_tx_all_packets()  // continue on survivors
```

- **Base** and **turbo-extra** use the same rule (simpler than dual policy).
- Runtime-grow path already isolated; unify base `process` lambda to call `on_link_exit` instead of unconditional `close_exec()`.
- Send completion `!ok`: treat as link failure → `on_link_exit`, not always session death.

## Byte credit

Per `vmux_linklayer`:

- `queued_bytes_` — bytes with in-flight writes
- `total_sent_bytes_` — lifetime sent (selection tie-break)

Constants:

- `PPP_MUX_LINK_BYTE_HIGH_WATER` (default 256 KiB)

Rules:

- Refuse `underlyin_sent` if `queued_bytes_ + packet_length > high_water`
- On successful queue: `queued_bytes_ += length`, `total_sent_bytes_ += length`
- On complete/abort: `queued_bytes_ -= length` (clamp)
- Free-link pick: lowest `queued_bytes_`, then lowest `total_sent_bytes_`

Single-flight list model stays: link leaves `tx_links_` while one write is outstanding unless under high-water re-credit is safe; P0 uses single-flight + accounting for observability and future pipelining.

## Explicit non-goals (P0-C)

- No multi-link replay / SACK
- No lossless migration of in-flight frames
- Gaps after link loss: existing flow_v2 `fail_flow` / compat gap timeout

## P1 (same delivery, minimal)

- Turbo: dual threshold + hold time (grow/shrink hysteresis)
- `select_turbo_linklayer`: prefer low `queued_bytes_`, then recency
- Finalize: log/count residual `tx_queue_` depth (early-ACK window observability)
- Light TX fairness: skip head-of-line same-cid burst beyond a byte quantum when another cid is queued
