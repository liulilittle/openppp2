#include <ppp/app/client/policy/DurablePolicyBundle.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
namespace fs = std::filesystem;
using namespace ppp::app::client::policy;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct TemporaryDirectory final {
    fs::path path = fs::temp_directory_path() /
        ("openppp2-policy-bundle-" + PolicySha256(std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count())).substr(0, 16));
    ~TemporaryDirectory() { std::error_code ec; fs::remove_all(path, ec); }
};

DurablePolicyBundle Bundle(const std::string& identity, std::string rules, std::string source_bytes,
    std::int64_t timestamp) {
    DurablePolicyBundle bundle;
    bundle.identity_fingerprint = identity;
    bundle.rules = std::move(rules);
    bundle.rules_validated_at_ms = timestamp;
    DurablePolicySource source;
    source.name = "remote-list";
    source.format = "text";
    source.tag = "stable";
    source.sha256 = PolicySha256(source_bytes);
    for (auto& ch : source.sha256) if (ch >= 'a' && ch <= 'f') ch = static_cast<char>(ch - 'a' + 'A');
    source.url_redacted = "https://rules.example/[redacted]";
    source.url_fingerprint = PolicySha256("https://rules.example/list");
    source.bytes = std::move(source_bytes);
    source.validated_at_ms = timestamp;
    bundle.rule_sets.emplace(source.name, std::move(source));
    return bundle;
}

void CommitLoadAndRecover() {
    TemporaryDirectory temporary;
    const auto identity = PolicySha256("identity");
    FileDurablePolicyBundleStore store(temporary.path.string());
    std::string error;

    auto first = Bundle(identity, "rules-v1", "source-v1", 10);
    Require(store.Commit(first, error), "first durable policy commit should succeed with uppercase pin");
    auto loaded = store.LoadCurrent(identity);
    Require(loaded.Ok() && loaded.bundle.rules == "rules-v1", "current bundle should load and verify");
    Require(loaded.bundle.rule_sets.at("remote-list").bytes == "source-v1", "source blob should load");

    auto second = Bundle(identity, "rules-v2", "source-v2", 20);
    Require(store.Commit(second, error), "second durable policy commit should succeed");
    loaded = store.LoadCurrent(identity);
    Require(loaded.Ok() && loaded.bundle.rules == "rules-v2", "second commit should become current");
    loaded = store.LoadPrevious(identity);
    Require(loaded.Ok() && loaded.bundle.rules == "rules-v1", "previous pointer should preserve old bundle");
    Require(store.RestorePreviousAsCurrent(identity, error), "previous bundle should be recoverable");
    loaded = store.LoadCurrent(identity);
    Require(loaded.Ok() && loaded.bundle.rules == "rules-v1", "recovery should restore previous bundle as current");
}

void RejectsInvalidIdentityAndPreservesCorruptContentAddressedFile() {
    TemporaryDirectory temporary;
    FileDurablePolicyBundleStore store(temporary.path.string());
    std::string error;
    auto invalid = Bundle(std::string(64, 'z'), "rules", "source", 1);
    Require(!store.Commit(invalid, error), "non-hex identity must be rejected");

    const auto identity = PolicySha256("tamper-identity");
    auto bundle = Bundle(identity, "rules-tamper", "source-tamper", 1);
    Require(store.Commit(bundle, error), "initial bundle should commit");
    const auto digest = PolicySha256(bundle.rules);
    const auto blob = temporary.path / identity / "blobs" / digest;
    {
        std::ofstream output(blob, std::ios::binary | std::ios::trunc);
        output << "corrupt";
    }
    error.clear();
    Require(!store.Commit(bundle, error), "corrupt digest-named blob must not be overwritten");
    std::ifstream input(blob, std::ios::binary);
    std::string preserved((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    Require(preserved == "corrupt", "existing content-addressed file must remain untouched");
    Require(!store.LoadCurrent(identity).Ok(), "tampered current bundle must fail integrity validation");
}

void PointerStageFailurePreservesBothPointersAndRestartRecovery() {
    const auto stages = {
        FileDurablePolicyBundleStore::Stage::Write,
        FileDurablePolicyBundleStore::Stage::Flush,
        FileDurablePolicyBundleStore::Stage::Rename,
        FileDurablePolicyBundleStore::Stage::DirectoryFlush
    };
    const auto pointer_writes = { 1, 2, 3, 4, 5 };
    for (const auto stage : stages) {
        const char* expected_diagnostic = stage == FileDurablePolicyBundleStore::Stage::Write
            ? "write durable temporary file"
            : stage == FileDurablePolicyBundleStore::Stage::Flush
                ? "flush durable temporary file"
                : stage == FileDurablePolicyBundleStore::Stage::Rename
                    ? "atomically replace durable pointer" : "fsync durable directory";
        for (const int fail_at : pointer_writes) {
            TemporaryDirectory temporary;
            const auto identity = PolicySha256("stage-failure-identity");
            FileDurablePolicyBundleStore store(temporary.path.string());
            std::string error;
            Require(store.Commit(Bundle(identity, "rules-v1", "source-v1", 10), error),
                "initial durable bundle should commit");
            Require(store.Commit(Bundle(identity, "rules-v2", "source-v2", 20), error),
                "second durable bundle should commit");
            DurablePolicyPointerState before;
            Require(store.CapturePointerState(identity, before, error), "pointer state should be captured");

            int stage_calls = 0;
            int injected_failures = 0;
            FileDurablePolicyBundleStore::Options options;
            options.allow_stage = [&](FileDurablePolicyBundleStore::Stage current) {
                if (current != stage) return true;
                if (++stage_calls == fail_at) {
                    ++injected_failures;
                    return false;
                }
                return true;
            };
            FileDurablePolicyBundleStore failing_store(temporary.path.string(), std::move(options));
            error.clear();
            Require(!failing_store.Commit(Bundle(identity, "rules-v3", "source-v3", 30), error),
                "injected durability failure must fail commit");
            Require(injected_failures == 1, "the injected failure should be one-shot");
            Require(error.find(expected_diagnostic) != std::string::npos,
                "durability failure should report its failed stage");

            DurablePolicyPointerState after;
            Require(store.CapturePointerState(identity, after, error), "post-failure pointer state should be captured");
            Require(after.current_present == before.current_present && after.current_bytes == before.current_bytes,
                "failed commit must preserve CURRENT bytes");
            Require(after.previous_present == before.previous_present && after.previous_bytes == before.previous_bytes,
                "failed commit must preserve PREVIOUS bytes");

            FileDurablePolicyBundleStore restarted_store(temporary.path.string());
            auto current = restarted_store.LoadCurrent(identity);
            auto previous = restarted_store.LoadPrevious(identity);
            Require(current.Ok() && current.bundle.rules == "rules-v2",
                "restart should recover the prior CURRENT bundle after failure");
            Require(previous.Ok() && previous.bundle.rules == "rules-v1",
                "restart should recover the prior PREVIOUS bundle after failure");
        }
    }
}
}

int main() {
    try {
        CommitLoadAndRecover();
        RejectsInvalidIdentityAndPreservesCorruptContentAddressedFile();
        PointerStageFailurePreservesBothPointersAndRestartRecovery();
        std::cout << "policy_durable_bundle_test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "policy_durable_bundle_test failed: " << error.what() << '\n';
        return 1;
    }
}
