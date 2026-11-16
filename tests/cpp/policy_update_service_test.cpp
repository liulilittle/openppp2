#define BOOST_TEST_MODULE policy_update_service_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/policy/PolicyUpdateService.h>

#include <chrono>
#include <condition_variable>
#include <atomic>
#include <map>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
using namespace ppp::app::client::policy;

class FakeStore final : public DurablePolicyBundleStore {
public:
    enum class CommitFailure { None, BeforePointerChange, AfterPointerChange };

    std::unique_ptr<DurablePolicyWriterLock> AcquireWriterLock(std::string&) override {
        return std::make_unique<DurablePolicyWriterLock>();
    }

    DurablePolicyLoad LoadCurrent(const std::string&) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return LoadUnlocked(current_);
    }
    DurablePolicyLoad LoadPrevious(const std::string&) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return LoadUnlocked(previous_);
    }

    bool Commit(const DurablePolicyBundle& bundle, std::string& error) override {
        {
            std::unique_lock<std::mutex> lock(commit_mutex_);
            if (block_commit_) {
                commit_entered_ = true;
                commit_cv_.notify_all();
                commit_cv_.wait(lock, [&] { return release_commit_; });
            }
        }
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (commit_failure_ == CommitFailure::BeforePointerChange) {
            commit_failure_ = CommitFailure::None;
            error = "injected persistence failure before pointer change";
            return false;
        }
        if (!current_.empty()) previous_ = current_;
        current_ = Save(bundle);
        if (commit_failure_ == CommitFailure::AfterPointerChange) {
            commit_failure_ = CommitFailure::None;
            error = "injected persistence failure after pointer change";
            return false;
        }
        return true;
    }

    bool RefreshCurrent(const DurablePolicyBundle& bundle, std::string& error) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (current_.empty()) { error = "no current pointer"; return false; }
        current_ = Save(bundle);
        return true;
    }

    bool RestorePreviousAsCurrent(const std::string&, std::string&) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        current_ = previous_;
        return true;
    }

    bool ClearCurrent(const std::string&, std::string&) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        current_.clear();
        return true;
    }

    bool CapturePointerState(const std::string&, DurablePolicyPointerState& state, std::string&) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        state.current_present = !current_.empty();
        state.current_bytes = current_;
        state.previous_present = !previous_.empty();
        state.previous_bytes = previous_;
        return true;
    }

    bool RestorePointerState(const std::string&, const DurablePolicyPointerState& state, std::string& error) override {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (fail_pointer_restore_) {
            fail_pointer_restore_ = false;
            error = "injected durable pointer rollback failure";
            return false;
        }
        current_ = state.current_present ? state.current_bytes : std::string();
        previous_ = state.previous_present ? state.previous_bytes : std::string();
        return true;
    }

    void SeedCurrent(const DurablePolicyBundle& bundle) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        current_ = Save(bundle);
    }

    void SeedPrevious(const DurablePolicyBundle& bundle) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        previous_ = Save(bundle);
    }

    void FailCommit(FakeStore::CommitFailure failure) { commit_failure_ = failure; }
    void FailNextPointerRestore() { fail_pointer_restore_ = true; }

    DurablePolicyPointerState Pointers() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return {!current_.empty(), current_, !previous_.empty(), previous_};
    }

    void BlockCommit() {
        std::lock_guard<std::mutex> lock(commit_mutex_);
        block_commit_ = true;
    }

    bool WaitForCommit() {
        std::unique_lock<std::mutex> lock(commit_mutex_);
        return commit_cv_.wait_for(lock, std::chrono::seconds(3), [&] { return commit_entered_; });
    }

    void ReleaseCommit() {
        std::lock_guard<std::mutex> lock(commit_mutex_);
        release_commit_ = true;
        commit_cv_.notify_all();
    }

private:
    std::string Save(const DurablePolicyBundle& bundle) {
        const auto key = "bundle-" + std::to_string(++next_id_);
        bundles_[key] = bundle;
        return key;
    }

    DurablePolicyLoad LoadUnlocked(const std::string& pointer) const {
        DurablePolicyLoad result;
        const auto found = bundles_.find(pointer);
        if (found != bundles_.end()) {
            result.bundle = found->second;
            result.found = true;
        }
        return result;
    }

    mutable std::mutex state_mutex_;
    std::map<std::string, DurablePolicyBundle> bundles_;
    std::string current_;
    std::string previous_;
    std::size_t next_id_ = 0;
    CommitFailure commit_failure_ = CommitFailure::None;
    bool fail_pointer_restore_ = false;
    std::mutex commit_mutex_;
    std::condition_variable commit_cv_;
    bool block_commit_ = false;
    bool commit_entered_ = false;
    bool release_commit_ = false;
};

class ScriptedFetcher final : public PolicyUpdateFetcher {
public:
    bool Fetch(const PolicyFetchRequest& request, PolicyFetchResponse& response) override {
        urls.push_back(request.url);
        etags.push_back(request.etag);
        if (request.cancelled && request.cancelled->load(std::memory_order_acquire)) {
            response.diagnostic = "cancelled";
            return false;
        }
        if (fail) {
            response.diagnostic = "scripted fetch failure";
            return false;
        }
        response.status = status;
        if (status == 304) return true;
        response.body = bodies.at(next_body++);
        response.etag = "etag-" + std::to_string(next_body);
        response.effective_url_redacted = "https://rules.example/list";
        return true;
    }

    bool fail = false;
    int status = 200;
    std::vector<std::string> bodies{"domain:first.example.test\n", "domain:second.example.test\n"};
    std::vector<std::string> urls;
    std::vector<std::string> etags;

private:
    std::size_t next_body = 0;
};

class FakeClock final : public PolicyUpdateClock {
public:
    explicit FakeClock(std::chrono::system_clock::time_point now) : now_(now) {}

    std::chrono::system_clock::time_point Now() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return now_;
    }

    void WaitUntil(std::condition_variable& cv, std::unique_lock<std::mutex>& lock,
        std::chrono::system_clock::time_point deadline, const std::function<bool()>& interrupted) override {
        {
            std::lock_guard<std::mutex> clock_lock(mutex_);
            wake_cv_ = &cv;
            wait_mutex_.store(lock.mutex(), std::memory_order_release);
            ++wait_count_;
        }
        changed_.notify_all();
        cv.wait(lock, [&] { return interrupted() || Now() >= deadline; });
    }

    void Advance(std::chrono::system_clock::duration amount) {
        std::unique_lock<std::mutex> wait_lock;
        if (auto* wait_mutex = wait_mutex_.load(std::memory_order_acquire))
            wait_lock = std::unique_lock<std::mutex>(*wait_mutex);
        std::condition_variable* wake = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            now_ += amount;
            wake = wake_cv_;
        }
        if (wake) wake->notify_all();
    }

    bool WaitForWaitCount(std::size_t count) {
        std::unique_lock<std::mutex> lock(mutex_);
        return changed_.wait_for(lock, std::chrono::seconds(3), [&] { return wait_count_ >= count; });
    }

    std::int64_t NowMillis() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(Now().time_since_epoch()).count();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::chrono::system_clock::time_point now_;
    std::condition_variable* wake_cv_ = nullptr;
    std::atomic<std::mutex*> wait_mutex_{nullptr};
    std::size_t wait_count_ = 0;
};

class ScheduledFetcher final : public PolicyUpdateFetcher {
public:
    explicit ScheduledFetcher(std::vector<bool> successes = {}, bool block_first = false)
        : successes_(std::move(successes)), block_first_(block_first) {}

    bool Fetch(const PolicyFetchRequest& request, PolicyFetchResponse& response) override {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto call = ++calls_;
        changed_.notify_all();
        if (block_first_ && call == 1) {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!release_first_ && !(request.cancelled && request.cancelled->load(std::memory_order_acquire)) &&
                std::chrono::steady_clock::now() < deadline)
                changed_.wait_for(lock, std::chrono::milliseconds(10));
        }
        if (request.cancelled && request.cancelled->load(std::memory_order_acquire)) {
            response.diagnostic = "cancelled";
            return false;
        }
        const bool success = call > successes_.size() || successes_[call - 1];
        if (!success) {
            response.status = 500;
            return true;
        }
        response.status = 200;
        response.body = "domain:scheduled.example.test\n";
        response.etag = "scheduled-etag";
        response.effective_url_redacted = "https://rules.example/list";
        return true;
    }

    bool WaitForCalls(std::size_t count) {
        std::unique_lock<std::mutex> lock(mutex_);
        return changed_.wait_for(lock, std::chrono::seconds(3), [&] { return calls_ >= count; });
    }

    std::size_t Calls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return calls_;
    }

    void ReleaseFirst() {
        std::lock_guard<std::mutex> lock(mutex_);
        release_first_ = true;
        changed_.notify_all();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::vector<bool> successes_;
    std::size_t calls_ = 0;
    bool block_first_ = false;
    bool release_first_ = false;
};

bool WaitForScheduledAttempt(PolicyUpdateService& service, std::int64_t expected_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (service.Status().next_attempt_ms == expected_ms) return true;
        std::this_thread::yield();
    }
    return service.Status().next_attempt_ms == expected_ms;
}

PolicySource Source() {
    PolicySource source;
    source.config_path = "/tmp/policy-update.json";
    source.base_path = "/tmp";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n[proxy]\nset:remote\n";
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    auto& remote = source.rule_sets["remote"];
    remote.format = "geosite-text";
    remote.url = "https://test-user:test-password@rules.example/list?token=test-token";
    remote.tag = "stable";
    return source;
}

DurablePolicyBundle Bundle(const std::string& identity, std::string bytes, std::string rules = {}) {
    DurablePolicyBundle bundle;
    bundle.identity_fingerprint = identity;
    bundle.rules = rules.empty() ? "default proxy\ndns direct local\ndns proxy remote\n[proxy]\nset:remote\n" : std::move(rules);
    DurablePolicySource remote;
    remote.name = "remote";
    remote.format = "geosite-text";
    remote.tag = "stable";
    remote.url_fingerprint = PolicySha256(Source().rule_sets.at("remote").url);
    remote.url_redacted = "https://rules.example/list";
    remote.bytes = std::move(bytes);
    bundle.rule_sets.emplace(remote.name, std::move(remote));
    return bundle;
}

PolicySource CompetingRuntimeSource() {
    PolicySource source;
    source.rules_text = "default reject\ndns direct local\ndns proxy remote\n[proxy]\n=competing.example.test\n";
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}

void CompeteWithServiceCandidate(PolicyRuntime& runtime) {
    const auto competing = runtime.Prepare(CompetingRuntimeSource());
    BOOST_REQUIRE(competing.Ok());
    BOOST_REQUIRE(runtime.Commit(competing));
}

void RequireSamePointers(const DurablePolicyPointerState& actual, const DurablePolicyPointerState& expected) {
    BOOST_TEST(actual.current_present == expected.current_present);
    BOOST_TEST(actual.current_bytes == expected.current_bytes);
    BOOST_TEST(actual.previous_present == expected.previous_present);
    BOOST_TEST(actual.previous_bytes == expected.previous_bytes);
}
}

BOOST_AUTO_TEST_SUITE(policy_update_service_tests)

BOOST_AUTO_TEST_CASE(close_during_durable_commit_restores_pointers_without_runtime_publication) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedCurrent(Bundle(identity, "domain:old.example.test\n"));
    store->SeedPrevious(Bundle(identity, "domain:previous.example.test\n"));
    const auto before = store->Pointers();
    store->BlockCommit();
    PolicyUpdateService service(runtime, source, store, fetcher);

    PolicyUpdateResult result;
    std::thread update([&] { result = service.RunOnce(); });
    const bool entered = store->WaitForCommit();
    if (!entered) {
        store->ReleaseCommit();
        update.join();
    }
    BOOST_REQUIRE(entered);
    service.Close();
    store->ReleaseCommit();
    update.join();

    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Closed));
    BOOST_TEST(!runtime.GetSnapshot());
    RequireSamePointers(store->Pointers(), before);
}

BOOST_AUTO_TEST_CASE(rejected_runtime_commit_restores_existing_current_and_previous) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedCurrent(Bundle(identity, "domain:old.example.test\n"));
    store->SeedPrevious(Bundle(identity, "domain:previous.example.test\n"));
    const auto before = store->Pointers();
    store->BlockCommit();
    PolicyUpdateService service(runtime, source, store, fetcher);

    PolicyUpdateResult result;
    std::thread update([&] { result = service.RunOnce(); });
    const bool entered = store->WaitForCommit();
    if (!entered) {
        store->ReleaseCommit();
        update.join();
    }
    BOOST_REQUIRE(entered);
    CompeteWithServiceCandidate(runtime);
    store->ReleaseCommit();
    update.join();

    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Failed));
    RequireSamePointers(store->Pointers(), before);
}

BOOST_AUTO_TEST_CASE(rejected_first_runtime_commit_clears_current_and_preserves_previous) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedPrevious(Bundle(identity, "domain:previous.example.test\n"));
    const auto before = store->Pointers();
    store->BlockCommit();
    PolicyUpdateService service(runtime, source, store, fetcher);

    PolicyUpdateResult result;
    std::thread update([&] { result = service.RunOnce(); });
    const bool entered = store->WaitForCommit();
    if (!entered) {
        store->ReleaseCommit();
        update.join();
    }
    BOOST_REQUIRE(entered);
    CompeteWithServiceCandidate(runtime);
    store->ReleaseCommit();
    update.join();

    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Failed));
    RequireSamePointers(store->Pointers(), before);
}

BOOST_AUTO_TEST_CASE(commit_failures_before_and_after_pointer_change_restore_original_state) {
    for (const auto failure : {FakeStore::CommitFailure::BeforePointerChange,
             FakeStore::CommitFailure::AfterPointerChange}) {
        auto source = Source();
        auto store = std::make_shared<FakeStore>();
        auto fetcher = std::make_shared<ScriptedFetcher>();
        PolicyRuntime runtime;
        const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
        store->SeedPrevious(Bundle(identity, "domain:previous.example.test\n"));
        const auto before = store->Pointers();
        store->FailCommit(failure);
        PolicyUpdateService service(runtime, source, store, fetcher);

        const auto result = service.RunOnce();
        BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Failed));
        RequireSamePointers(store->Pointers(), before);
        BOOST_TEST(!runtime.GetSnapshot());
    }
}

BOOST_AUTO_TEST_CASE(rollback_failure_is_reported_in_commit_failure_diagnostic) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedPrevious(Bundle(identity, "domain:previous.example.test\n"));
    store->FailCommit(FakeStore::CommitFailure::AfterPointerChange);
    store->FailNextPointerRestore();
    PolicyUpdateService service(runtime, source, store, fetcher);

    const auto result = service.RunOnce();
    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Failed));
    BOOST_TEST(result.diagnostic.find("rollback") != std::string::npos);
    BOOST_TEST(!runtime.GetSnapshot());
}

BOOST_AUTO_TEST_CASE(restoring_previous_marks_durable_current_present) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedPrevious(Bundle(identity, "domain:restored.example.test\n"));
    PolicyUpdateService service(runtime, source, store, fetcher);

    const auto result = service.RestoreAndPrepare();
    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    BOOST_TEST(service.Status().durable_current);
    BOOST_TEST(service.Status().durable_previous);
}

BOOST_AUTO_TEST_CASE(refresh_after_restore_uses_cached_remote_source_and_rereads_local_rules) {
    const auto directory = std::filesystem::temp_directory_path() / ("openppp-policy-refresh-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path directory;
        ~Cleanup() { std::error_code error; std::filesystem::remove_all(directory, error); }
    } cleanup{directory};
    std::filesystem::create_directory(directory);
    const auto rules_path = directory / "routing.rules";
    const std::string old_rules = "default proxy\ndns direct local\ndns proxy remote\n[proxy]\nset:remote\n[reject]\n=local.example.test\n";
    const std::string updated_rules = "default proxy\ndns direct local\ndns proxy remote\n[proxy]\nset:remote\n[direct]\n=local.example.test\n";
    {
        std::ofstream rules(rules_path, std::ios::binary);
        rules << old_rules;
        BOOST_REQUIRE(bool(rules));
    }

    auto source = Source();
    source.updates_enabled = false;
    source.rules_path = rules_path.string();
    source.rules_text.clear();
    auto store = std::make_shared<FakeStore>();
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedCurrent(Bundle(identity, "domain:cached.example.test\n", old_rules));
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, nullptr);

    const auto restored = service.RestoreAndPrepare();
    BOOST_REQUIRE(static_cast<int>(restored.code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    const auto initial = runtime.GetSnapshot();
    BOOST_REQUIRE(initial);
    BOOST_TEST(static_cast<int>(runtime.Evaluate("local.example.test").action) == static_cast<int>(PolicyAction::Reject));

    {
        std::ofstream rules(rules_path, std::ios::binary | std::ios::trunc);
        rules << updated_rules;
        BOOST_REQUIRE(bool(rules));
    }
    const auto refreshed = service.RunOnce();
    const auto active = runtime.GetSnapshot();
    BOOST_TEST(static_cast<int>(refreshed.code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    BOOST_REQUIRE(active);
    BOOST_TEST(active->Version() > initial->Version());
    BOOST_TEST(static_cast<int>(runtime.Evaluate("local.example.test").action) == static_cast<int>(PolicyAction::Direct));
    BOOST_TEST(static_cast<int>(runtime.Evaluate("cached.example.test").action) == static_cast<int>(PolicyAction::Proxy));
}

BOOST_AUTO_TEST_CASE(repeated_updates_reuse_the_unchanged_declared_url) {
    auto source = Source();
    const auto declared_url = source.rule_sets.at("remote").url;
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, fetcher);

    BOOST_TEST(static_cast<int>(service.RunOnce().code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    BOOST_TEST(static_cast<int>(service.RunOnce().code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    BOOST_REQUIRE_EQUAL(fetcher->urls.size(), 2u);
    BOOST_TEST(fetcher->urls[0] == declared_url);
    BOOST_TEST(fetcher->urls[1] == declared_url);
    BOOST_TEST(fetcher->etags[1] == "etag-1");
    BOOST_TEST(source.rule_sets.at("remote").url == declared_url);
    BOOST_TEST(source.rule_sets.at("remote").text.empty());
}

BOOST_AUTO_TEST_CASE(compiler_fetch_pin_and_uncached_304_fail_before_commit) {
    auto run_failure = [](PolicySource source, std::shared_ptr<ScriptedFetcher> fetcher,
        const char* case_name) {
        auto store = std::make_shared<FakeStore>();
        PolicyRuntime runtime;
        PolicyUpdateService service(runtime, source, store, fetcher);
        const auto result = service.RunOnce();
        BOOST_TEST_CONTEXT(case_name) {
            BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::Failed));
            BOOST_TEST(!store->Pointers().current_present);
            BOOST_TEST(!runtime.GetSnapshot());
        }
    };

    auto invalid_rules = Source();
    invalid_rules.rules_text = "default unsupported\n[proxy]\nset:remote\n";
    run_failure(invalid_rules, std::make_shared<ScriptedFetcher>(), "invalid compiler input");

    auto fetch_failure = std::make_shared<ScriptedFetcher>();
    fetch_failure->fail = true;
    run_failure(Source(), fetch_failure, "source fetch failure");

    auto pinned = Source();
    pinned.rule_sets.at("remote").sha256 = PolicySha256("different payload\n");
    run_failure(pinned, std::make_shared<ScriptedFetcher>(), "source pin mismatch");

    auto not_modified = std::make_shared<ScriptedFetcher>();
    not_modified->status = 304;
    run_failure(Source(), not_modified, "304 without cached source");
}

BOOST_AUTO_TEST_CASE(changed_immutable_declaration_requires_reconnect_without_fetching) {
    auto source = Source();
    auto changed = source;
    changed.rule_sets.at("remote").url = "https://rules.example/changed";
    auto fetcher = std::make_shared<ScriptedFetcher>();
    auto store = std::make_shared<FakeStore>();
    PolicyRuntime runtime;
    PolicyLoadResult declaration;
    declaration.source = changed;
    PolicyUpdateService service(runtime, source, store, fetcher, {}, [declaration] { return declaration; });

    const auto result = service.RunOnce();
    BOOST_TEST(static_cast<int>(result.code) == static_cast<int>(PolicyUpdateResultCode::RequiresReconnect));
    BOOST_TEST(fetcher->urls.empty());
    BOOST_TEST(!store->Pointers().current_present);
}

BOOST_AUTO_TEST_CASE(unchanged_update_keeps_the_active_runtime_version) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    fetcher->bodies = {"domain:same.example.test\n", "domain:same.example.test\n"};
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, fetcher);

    const auto first = service.RunOnce();
    const auto active = runtime.GetSnapshot();
    BOOST_REQUIRE(active);
    const auto second = service.RunOnce();
    BOOST_TEST(static_cast<int>(first.code) == static_cast<int>(PolicyUpdateResultCode::Updated));
    BOOST_TEST(static_cast<int>(second.code) == static_cast<int>(PolicyUpdateResultCode::Unchanged));
    BOOST_TEST(runtime.GetSnapshot()->Version() == active->Version());
}

BOOST_AUTO_TEST_CASE(snapshot_and_status_reads_complete_during_durable_commit) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScriptedFetcher>();
    PolicyRuntime runtime;
    const auto identity = PolicyUpdateService::ImmutableFingerprint(source);
    store->SeedCurrent(Bundle(identity, "domain:old.example.test\n"));
    const auto initial = runtime.Prepare(CompetingRuntimeSource());
    BOOST_REQUIRE(runtime.Commit(initial));
    store->BlockCommit();
    PolicyUpdateService service(runtime, source, store, fetcher);

    std::thread update([&] { (void)service.RunOnce(); });
    const bool entered = store->WaitForCommit();
    if (!entered) {
        store->ReleaseCommit();
        update.join();
    }
    BOOST_REQUIRE(entered);
    std::atomic_bool read_started{false};
    std::atomic_bool read_completed{false};
    std::thread reader([&] {
        read_started.store(true, std::memory_order_release);
        (void)runtime.GetSnapshot();
        (void)service.Status();
        read_completed.store(true, std::memory_order_release);
    });
    while (!read_started.load(std::memory_order_acquire)) std::this_thread::yield();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!read_completed.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    const bool completed_before_release = read_completed.load(std::memory_order_acquire);
    store->ReleaseCommit();
    reader.join();
    update.join();
    BOOST_TEST(completed_before_release);
}

BOOST_AUTO_TEST_CASE(scheduler_uses_exponential_backoff_caps_at_one_hour_and_resets_on_success) {
    auto source = Source();
    source.updates_enabled = true;
    source.updates_interval = "24h";
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScheduledFetcher>(std::vector<bool>{
        false, false, false, false, false, false, false, false, true, false});
    auto clock = std::make_shared<FakeClock>(std::chrono::system_clock::time_point(std::chrono::seconds(10'000)));
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, fetcher, clock);

    BOOST_REQUIRE(service.Start());
    service.Trigger();
    BOOST_REQUIRE(fetcher->WaitForCalls(1));
    const std::vector<std::chrono::seconds> delays = {
        std::chrono::seconds(60), std::chrono::seconds(120), std::chrono::seconds(240),
        std::chrono::seconds(480), std::chrono::seconds(960), std::chrono::seconds(1920),
        std::chrono::seconds(3600)};
    std::int64_t next_attempt = clock->NowMillis() + 60'000;
    BOOST_REQUIRE(WaitForScheduledAttempt(service, next_attempt));
    for (std::size_t i = 0; i < delays.size(); ++i) {
        clock->Advance(delays[i]);
        BOOST_REQUIRE(fetcher->WaitForCalls(i + 2));
        next_attempt = clock->NowMillis() + (i + 1 == delays.size() ? 3'600'000 : delays[i + 1].count() * 1000);
        BOOST_REQUIRE(WaitForScheduledAttempt(service, next_attempt));
    }

    service.Trigger();
    BOOST_REQUIRE(fetcher->WaitForCalls(9));
    const auto success_next = clock->NowMillis() + 24 * 60 * 60 * 1000LL;
    BOOST_REQUIRE(WaitForScheduledAttempt(service, success_next));
    service.Trigger();
    BOOST_REQUIRE(fetcher->WaitForCalls(10));
    BOOST_REQUIRE(WaitForScheduledAttempt(service, clock->NowMillis() + 60'000));
    service.Close();
}

BOOST_AUTO_TEST_CASE(start_is_idempotent_triggers_coalesce_and_close_stops_fetching) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScheduledFetcher>(std::vector<bool>{true, true}, true);
    auto clock = std::make_shared<FakeClock>(std::chrono::system_clock::time_point(std::chrono::seconds(1000)));
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, fetcher, clock);

    BOOST_REQUIRE(service.Start());
    BOOST_TEST(service.Start());
    service.Trigger();
    BOOST_REQUIRE(fetcher->WaitForCalls(1));
    for (int i = 0; i < 10; ++i) service.Trigger();
    fetcher->ReleaseFirst();
    BOOST_REQUIRE(fetcher->WaitForCalls(2));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    BOOST_TEST(fetcher->Calls() == 2u);

    service.Close();
    service.Trigger();
    clock->Advance(std::chrono::hours(48));
    BOOST_TEST(fetcher->Calls() == 2u);
    BOOST_TEST(!service.Start());
}

BOOST_AUTO_TEST_CASE(close_cancels_inflight_fetch_and_overflow_prevents_start) {
    auto source = Source();
    auto store = std::make_shared<FakeStore>();
    auto fetcher = std::make_shared<ScheduledFetcher>(std::vector<bool>{true}, true);
    auto clock = std::make_shared<FakeClock>(std::chrono::system_clock::time_point(std::chrono::seconds(1000)));
    PolicyRuntime runtime;
    PolicyUpdateService service(runtime, source, store, fetcher, clock);

    BOOST_REQUIRE(service.Start());
    service.Trigger();
    BOOST_REQUIRE(fetcher->WaitForCalls(1));
    service.Close();
    BOOST_TEST(fetcher->Calls() == 1u);

    auto overflow_source = Source();
    overflow_source.updates_enabled = true;
    overflow_source.updates_interval = "24h";
    auto overflow_clock = std::make_shared<FakeClock>(std::chrono::system_clock::time_point::max() -
        std::chrono::hours(1));
    PolicyRuntime overflow_runtime;
    PolicyUpdateService overflow_service(overflow_runtime, overflow_source, store,
        std::make_shared<ScheduledFetcher>(), overflow_clock);
    BOOST_TEST(!overflow_service.Start());
}

BOOST_AUTO_TEST_SUITE_END()
