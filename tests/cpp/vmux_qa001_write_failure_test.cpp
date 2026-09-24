#define BOOST_TEST_MODULE vmux_qa001_write_failure_test
#include <boost/test/included/unit_test.hpp>

/**
 * @file vmux_qa001_write_failure_test.cpp
 * @brief VMUX-QA-001: Partial / sync-fail / async-fail write completion semantics.
 * @license GPL-3.0
 *
 * Tests the interaction of three components that together form the
 * "underlyin_sent" write path in vmux_net:
 *
 *   1. MuxLinkDrainState   — per-link inflight accounting (BeginWrite / CompleteWrite / AbortWrite / BeginRetire)
 *   2. tx_completion       — exactly-once finish callback (mutex + finished_ flag)
 *   3. The write-state machine that ties them together:
 *        BeginWrite → (success: CompleteWrite + finish(true|false)) | (reject: AbortWrite + finish(false))
 *
 * Because vmux_net itself cannot be instantiated in the standalone test
 * suite (it requires the full third-party dependency tree), we replicate
 * the EXACT logic of underlyin_sent / transmission_write / finish_tx_completion
 * using the real MuxLinkDrainState and a faithful re-implementation of
 * tx_completion (the class is defined inside vmux_net.h which pulls in
 * too many headers; the one-shot semantics are trivially equivalent).
 *
 * Invariants verified across all scenarios:
 *   - Every write settles exactly once (tx_completion is one-shot).
 *   - Every drain ticket is consumed exactly once (compare_exchange guard).
 *   - inflight_ never underflows.
 *   - A retired link rejects new writes (BeginWrite returns empty ticket).
 *   - A late completion after retire is safely consumed or ignored.
 *   - A late completion after session close is idempotent.
 *   - Re-injection after original completion does not double-deliver.
 */

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <ppp/app/mux/MuxLinkDrainState.h>

namespace mux = ppp::app::mux;

// ---------------------------------------------------------------------------
// Faithful re-implementation of vmux_net::tx_completion (one-shot finish).
// The real class lives in vmux_net.h but pulling that header into the
// standalone test suite would drag in the entire Boost / ASIO / OpenSSL
// dependency tree. The semantics are trivial: mutex + finished_ flag +
// move-callback-out-under-lock + invoke-after-unlock.
// ---------------------------------------------------------------------------
class TxCompletion final {
public:
    explicit TxCompletion(std::function<void(bool)> cb) noexcept
        : callback_(std::move(cb)) {}

    void Finish(bool successed) noexcept {
        std::function<void(bool)> callback;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (finished_) {
                return;
            }
            finished_ = true;
            callback = std::move(callback_);
            callback_ = nullptr;
        }
        if (callback) {
            callback(successed);
        }
    }

    bool finished() const noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        return finished_;
    }

private:
    mutable std::mutex mutex_;
    bool finished_ = false;
    std::function<void(bool)> callback_;
};

using TxCompletionPtr = std::shared_ptr<TxCompletion>;

// ---------------------------------------------------------------------------
// Simulated write outcome — mirrors ITransmission::Write contract:
//   posted=false  → write rejected synchronously, callback NOT invoked
//   posted=true   → write accepted; callback invoked with ok=true|false
// ---------------------------------------------------------------------------
struct WriteOutcome {
    bool posted = false;       // Did the transport accept the write?
    bool ok = false;           // Completion result (only meaningful when posted && async)
    bool async = true;         // If false, callback fires synchronously during Send()
};

// ---------------------------------------------------------------------------
// Minimal link mock: just the drain state + queued_bytes counter.
// Mirrors vmux_linklayer's drain_ and queued_bytes_ fields.
// pending_callbacks holds deferred async completions (FIFO order).
// ---------------------------------------------------------------------------
struct FakeLink {
    mux::MuxLinkDrainState drain;
    std::atomic<std::size_t> queued_bytes{0};
    std::atomic<std::uint64_t> total_sent_bytes{0};
    std::vector<std::function<void()>> pending_callbacks;

    // Trigger the oldest pending async callback.
    void trigger_oldest() {
        if (!pending_callbacks.empty()) {
            auto cb = std::move(pending_callbacks.front());
            pending_callbacks.erase(pending_callbacks.begin());
            cb();
        }
    }

    // Trigger all pending async callbacks in FIFO order.
    void trigger_all() {
        while (!pending_callbacks.empty()) {
            auto cb = std::move(pending_callbacks.front());
            pending_callbacks.erase(pending_callbacks.begin());
            cb();
        }
    }

    // Trigger the Nth pending callback (0-based), preserving order.
    void trigger_at(std::size_t index) {
        if (index < pending_callbacks.size()) {
            auto cb = std::move(pending_callbacks[index]);
            pending_callbacks.erase(pending_callbacks.begin() +
                static_cast<std::ptrdiff_t>(index));
            cb();
        }
    }
};

// ---------------------------------------------------------------------------
// Simulated session state: close flag + pending completion list.
// Mirrors vmux_net::close_requested_ + pending_tx_completions_.
// ---------------------------------------------------------------------------
struct FakeSession {
    std::atomic<bool> closed{false};
    std::mutex tx_mutex;
    std::vector<TxCompletionPtr> pending;

    bool close_requested() const noexcept {
        return closed.load(std::memory_order_acquire);
    }

    // Mirrors vmux_net::begin_close — swap and fail all pending.
    void begin_close() {
        std::vector<TxCompletionPtr> old;
        {
            std::lock_guard<std::mutex> scope(tx_mutex);
            if (closed.load(std::memory_order_relaxed)) {
                return;
            }
            closed.store(true, std::memory_order_release);
            old.swap(pending);
        }
        for (auto& c : old) {
            c->Finish(false);
        }
    }

    // Mirrors vmux_net::finish_tx_completion — remove from pending, then finish.
    void finish_completion(const TxCompletionPtr& c, bool ok) {
        {
            std::lock_guard<std::mutex> scope(tx_mutex);
            for (auto it = pending.begin(); it != pending.end(); ) {
                if (*it == c) {
                    it = pending.erase(it);
                } else {
                    ++it;
                }
            }
        }
        c->Finish(ok);
    }

    void register_pending(const TxCompletionPtr& c) {
        std::lock_guard<std::mutex> scope(tx_mutex);
        pending.push_back(c);
    }
};

// ---------------------------------------------------------------------------
// Simulated underlyin_sent: the core write state machine.
// Returns false if the write was rejected (drain full, session closed, etc.).
// The completion is finished exactly once: either in the callback path or
// in the rejection fallback.
// ---------------------------------------------------------------------------
static bool simulated_write(
    FakeSession& sess,
    FakeLink& link,
    int packet_length,
    const TxCompletionPtr& completion,
    WriteOutcome outcome) {

    // Pre-checks: disposed / closed.
    if (sess.close_requested()) {
        completion->Finish(false);
        return false;
    }

    // BeginWrite: returns empty ticket if retiring.
    const mux::MuxLinkDrainState::WriteTicket ticket = link.drain.BeginWrite();
    if (!ticket) {
        completion->Finish(false);
        return false;
    }

    link.queued_bytes.fetch_add(static_cast<std::size_t>(packet_length));
    link.total_sent_bytes.fetch_add(static_cast<std::uint64_t>(packet_length));

    if (!outcome.posted) {
        // Synchronous rejection: transmission_write returned false.
        // Abort the ticket and finish(false). Callback is NOT invoked by transport.
        link.drain.AbortWrite(ticket);
        link.queued_bytes.fetch_sub(static_cast<std::size_t>(packet_length));
        sess.finish_completion(completion, false);
        return false;
    }

    // Register as pending so begin_close can fail it.
    sess.register_pending(completion);

    auto do_complete = [&, ticket, packet_length](bool ok) {
        // CompleteWrite consumes the ticket (compare_exchange guard).
        if (!link.drain.CompleteWrite(ticket)) {
            // Already consumed (e.g. by retire path). Just finish.
            sess.finish_completion(completion, ok);
            return;
        }

        std::size_t cur = link.queued_bytes.load();
        while (cur >= static_cast<std::size_t>(packet_length)) {
            if (link.queued_bytes.compare_exchange_weak(
                    cur, cur - static_cast<std::size_t>(packet_length))) {
                break;
            }
        }

        sess.finish_completion(completion, ok);

        // If session closed during the callback, do not re-schedule.
        if (sess.close_requested()) {
            return;
        }

        // If link retiring, would trigger process_tx_all_packets here.
        // (Simulated — no actual scheduler to drive.)
    };

    if (outcome.async) {
        // Asynchronous completion: defer to caller.
        // Store the lambda for later invocation.
        // We do this by storing in a std::function captured by the test.
        // For the test harness, we return the do_complete via an out-param.
        // Instead, we'll use a different approach: the test calls
        // trigger_async_completion() which is stored.
        // For simplicity, we store the completion function in the link.
        // This is a test-only mechanism.
        link.pending_callbacks.push_back([do_complete, ok = outcome.ok]() {
            do_complete(ok);
        });
    } else {
        // Synchronous completion.
        do_complete(outcome.ok);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------
static TxCompletionPtr make_completion(std::vector<bool>& results) {
    return std::make_shared<TxCompletion>([&results](bool ok) {
        results.push_back(ok);
    });
}

// ===========================================================================
// Scenario 1: Synchronous rejection (DoWriteBytes returns false / posted=false)
//              Frame must NOT be counted as sent. Ticket must be aborted.
//              Completion must fire with false.
// ===========================================================================

BOOST_AUTO_TEST_CASE(sync_rejection_aborts_ticket_and_fails_completion) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    bool posted = simulated_write(sess, link, 100, completion,
        WriteOutcome{ /*posted=*/false, /*ok=*/false, /*async=*/false });

    BOOST_TEST(!posted);
    BOOST_TEST(results == (std::vector<bool>{false}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
    BOOST_TEST(completion->finished());
}

// ===========================================================================
// Scenario 2: Asynchronous failure (posted=true, async=true, ok=false)
//              Drain ticket completed normally, completion finishes with false.
//              Inflight returns to 0 after callback.
// ===========================================================================

BOOST_AUTO_TEST_CASE(async_failure_completes_ticket_and_fails_completion) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    bool posted = simulated_write(sess, link, 200, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/false, /*async=*/true });

    BOOST_TEST(posted);
    BOOST_TEST(results.empty());   // No callback yet — async.
    BOOST_TEST(link.drain.inflight() == 1);
    BOOST_TEST(link.queued_bytes.load() == 200);

    // Trigger the async completion.
    link.trigger_oldest();

    BOOST_TEST(results == (std::vector<bool>{false}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
    BOOST_TEST(completion->finished());
}

// ===========================================================================
// Scenario 3: Asynchronous success (posted=true, async=true, ok=true)
//              Normal happy path: ticket completed, completion finishes true.
// ===========================================================================

BOOST_AUTO_TEST_CASE(async_success_completes_normally) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    bool posted = simulated_write(sess, link, 150, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    BOOST_TEST(posted);
    BOOST_TEST(link.drain.inflight() == 1);

    link.trigger_oldest();

    BOOST_TEST(results == (std::vector<bool>{true}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
}

// ===========================================================================
// Scenario 4: Synchronous success (posted=true, async=false, ok=true)
//              Callback fires inline during Send().
// ===========================================================================

BOOST_AUTO_TEST_CASE(sync_success_completes_inline) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    bool posted = simulated_write(sess, link, 80, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/false });

    BOOST_TEST(posted);
    BOOST_TEST(results == (std::vector<bool>{true}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
}

// ===========================================================================
// Scenario 5: Completion before link close → BeginRetire → reapable
//              After completion, inflight=0. BeginRetire sets retiring.
//              reapable() returns true.
// ===========================================================================

BOOST_AUTO_TEST_CASE(completion_then_retire_makes_link_reapable) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    simulated_write(sess, link, 120, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    BOOST_TEST(link.drain.inflight() == 1);
    BOOST_TEST(!link.drain.retiring());
    BOOST_TEST(!link.drain.reapable());

    // Complete the write.
    link.trigger_oldest();
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(!link.drain.retiring());
    BOOST_TEST(!link.drain.reapable()); // Not retiring yet.

    // Retire the link.
    link.drain.BeginRetire();
    BOOST_TEST(link.drain.retiring());
    BOOST_TEST(link.drain.reapable());  // Retiring + inflight==0.
}

// ===========================================================================
// Scenario 6: Link retire BEFORE completion arrives
//              BeginRetire sets retiring=true. The pending async completion
//              can still fire: CompleteWrite succeeds (ticket not yet consumed).
//              After completion, inflight→0, reapable=true.
//              New writes are rejected (BeginWrite returns empty ticket).
// ===========================================================================

BOOST_AUTO_TEST_CASE(retire_before_completion_then_late_callback) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    simulated_write(sess, link, 100, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    BOOST_TEST(link.drain.inflight() == 1);

    // Retire while write is in-flight.
    link.drain.BeginRetire();
    BOOST_TEST(link.drain.retiring());
    BOOST_TEST(!link.drain.reapable()); // Still inflight.

    // New writes must be rejected.
    auto completion2 = make_completion(results);
    bool posted2 = simulated_write(sess, link, 50, completion2,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });
    BOOST_TEST(!posted2);
    BOOST_TEST(results == (std::vector<bool>{false})); // completion2 failed.

    // Late completion of the original write.
    link.trigger_oldest();
    BOOST_TEST(results == (std::vector<bool>{false, true}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.drain.reapable());
}

// ===========================================================================
// Scenario 7: Session close after write is posted, before callback fires
//              begin_close swaps pending list and fails all with false.
//              Late callback then hits finish_completion → Finish is idempotent.
// ===========================================================================

BOOST_AUTO_TEST_CASE(session_close_fails_pending_then_late_callback_idempotent) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    simulated_write(sess, link, 100, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    BOOST_TEST(link.drain.inflight() == 1);
    BOOST_TEST(!results.empty() == false);

    // Session close: fails all pending completions with false.
    sess.begin_close();
    BOOST_TEST(sess.close_requested());
    BOOST_TEST(results == (std::vector<bool>{false}));

    // Late async callback fires. The drain CompleteWrite succeeds (ticket
    // was not consumed by close). finish_completion tries to Finish again
    // but it's already finished → idempotent no-op.
    link.trigger_oldest();

    // Still exactly one result (the close-induced false). The late callback's
    // Finish(true) was suppressed by the finished_ flag.
    BOOST_TEST(results == (std::vector<bool>{false}));
    BOOST_TEST(link.drain.inflight() == 0);
}

// ===========================================================================
// Scenario 8: Re-injection (second completion attempt) is idempotent
//              A frame completes, then a duplicate callback arrives.
//              tx_completion must not fire twice.
// ===========================================================================

BOOST_AUTO_TEST_CASE(duplicate_completion_is_idempotent) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    simulated_write(sess, link, 100, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    // First completion.
    link.trigger_oldest();
    BOOST_TEST(results == (std::vector<bool>{true}));
    BOOST_TEST(link.drain.inflight() == 0);

    // Directly call Finish again (simulates duplicate callback).
    completion->Finish(true);
    completion->Finish(false);

    // Still exactly one result.
    BOOST_TEST(results.size() == 1);
}

// ===========================================================================
// Scenario 9: Multiple concurrent writes, one fails, others succeed
//              Verifies drain accounting is correct across multiple writes.
// ===========================================================================

BOOST_AUTO_TEST_CASE(mixed_success_failure_accounting) {
    FakeSession sess;
    FakeLink link;

    std::vector<bool> r1, r2, r3;
    auto c1 = make_completion(r1);
    auto c2 = make_completion(r2);
    auto c3 = make_completion(r3);

    // Write 1: async success
    simulated_write(sess, link, 100, c1, { true, true, true });
    // Write 2: sync rejection
    bool posted2 = simulated_write(sess, link, 200, c2, { false, false, false });
    // Write 3: async failure
    simulated_write(sess, link, 300, c3, { true, false, true });

    BOOST_TEST(!posted2);
    BOOST_TEST(r2 == (std::vector<bool>{false}));     // Sync rejection fired immediately.
    BOOST_TEST(r1.empty());
    BOOST_TEST(r3.empty());

    BOOST_TEST(link.drain.inflight() == 2);  // c1 and c3 in flight.
    BOOST_TEST(link.queued_bytes.load() == 400); // 100 + 300 (200 was refunded).

    // Complete c1 (success) — it was queued first, so it's at index 0.
    link.trigger_oldest();
    BOOST_TEST(r1 == (std::vector<bool>{true}));
    BOOST_TEST(r3.empty());
    BOOST_TEST(link.drain.inflight() == 1);
    BOOST_TEST(link.queued_bytes.load() == 300);

    // Complete c3 (failure) — now the oldest remaining.
    link.trigger_oldest();
    BOOST_TEST(r3 == (std::vector<bool>{false}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
}

// ===========================================================================
// Scenario 10: BeginRetire rejects new writes, existing write completes,
//              then drain is reapable. No UAF, no underflow.
// ===========================================================================

BOOST_AUTO_TEST_CASE(retire_rejects_new_writes_existing_completes_cleanly) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    // One write in flight.
    simulated_write(sess, link, 64, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });
    BOOST_TEST(link.drain.inflight() == 1);

    // Retire.
    link.drain.BeginRetire();

    // New write rejected.
    auto c2 = make_completion(results);
    BOOST_TEST(!simulated_write(sess, link, 32, c2,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true }));
    BOOST_TEST(results == (std::vector<bool>{false}));

    // Existing write completes successfully.
    link.trigger_oldest();
    BOOST_TEST(results == (std::vector<bool>{false, true}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.drain.reapable());
}

// ===========================================================================
// Scenario 11: Session close BEFORE any write is posted
//              All writes immediately fail. No tickets created.
// ===========================================================================

BOOST_AUTO_TEST_CASE(close_before_write_immediately_fails) {
    FakeSession sess;
    FakeLink link;
    std::vector<bool> results;
    auto completion = make_completion(results);

    sess.begin_close();

    bool posted = simulated_write(sess, link, 100, completion,
        WriteOutcome{ /*posted=*/true, /*ok=*/true, /*async=*/true });

    BOOST_TEST(!posted);
    BOOST_TEST(results == (std::vector<bool>{false}));
    BOOST_TEST(link.drain.inflight() == 0);
    BOOST_TEST(link.queued_bytes.load() == 0);
}

// ===========================================================================
// Scenario 12: tx_completion is one-shot even under concurrent Finish calls
//              Two threads call Finish simultaneously. Exactly one wins.
// ===========================================================================

BOOST_AUTO_TEST_CASE(concurrent_finish_is_one_shot) {
    std::vector<bool> results;
    std::mutex results_mutex;
    auto completion = std::make_shared<TxCompletion>([&](bool ok) {
        std::lock_guard<std::mutex> scope(results_mutex);
        results.push_back(ok);
    });

    std::thread t1([completion]() { completion->Finish(true); });
    std::thread t2([completion]() { completion->Finish(false); });
    t1.join();
    t2.join();

    BOOST_TEST(results.size() == 1);
    BOOST_TEST(completion->finished());
}

// ===========================================================================
// Scenario 13: WriteTicket compare_exchange prevents double-consume
//              CompleteWrite then AbortWrite on same ticket → second is no-op.
// ===========================================================================

BOOST_AUTO_TEST_CASE(ticket_double_consume_prevented) {
    FakeLink link;
    auto ticket = link.drain.BeginWrite();
    BOOST_TEST(static_cast<bool>(ticket));
    BOOST_TEST(link.drain.inflight() == 1);

    // First consume succeeds.
    BOOST_TEST(link.drain.CompleteWrite(ticket));
    BOOST_TEST(link.drain.inflight() == 0);

    // Second consume on same ticket fails.
    BOOST_TEST(!link.drain.AbortWrite(ticket));
    BOOST_TEST(link.drain.inflight() == 0); // No underflow.
}

// ===========================================================================
// Scenario 14: Multiple retire calls are idempotent
// ===========================================================================

BOOST_AUTO_TEST_CASE(multiple_retire_calls_idempotent) {
    FakeLink link;
    BOOST_TEST(!link.drain.retiring());

    link.drain.BeginRetire();
    BOOST_TEST(link.drain.retiring());

    link.drain.BeginRetire(); // Second call: no-op, still retiring.
    BOOST_TEST(link.drain.retiring());
    BOOST_TEST(link.drain.reapable()); // inflight==0 and retiring.
}
