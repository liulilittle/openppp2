#define BOOST_TEST_MODULE policy_status_file_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/policy/PolicyStatusFile.h>
#include <ppp/app/client/policy/PolicyUpdateService.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {
using namespace ppp::app::client::policy;
namespace fs = std::filesystem;

struct TempDirectory final {
    fs::path path;
    TempDirectory() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path = fs::temp_directory_path() / ("openppp-policy-status-" + std::to_string(stamp));
        fs::create_directories(path);
    }
    ~TempDirectory() { std::error_code ec; fs::remove_all(path, ec); }
    fs::path File() const { return path / "STATUS.json"; }
};

std::int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

PolicyStatusRecord Record(std::int64_t updatedAt) {
    PolicyStatusRecord record;
    record.identity = "test-identity";
    record.pid = 0x7fffffff;
    record.process_start = "unmatched-start-token";
    record.updated_at_ms = updatedAt;
    record.session_generation = 7;
    record.active_version = 12;
    record.prepared_version = 13;
    record.prepared_digest = "prepared-digest";
    record.durable_current = "current-digest";
    record.durable_previous = "previous-digest";
    record.last_attempt_ms = updatedAt - 10;
    record.last_success_ms = updatedAt - 20;
    record.next_attempt_ms = updatedAt + 1000;
    record.last_result = "unchanged";
    record.last_diagnostic = "redacted diagnostic";
    record.counters.dns_cache_hits = 101;
    record.counters.dns_timeout_attempts = 4;
    record.counters.dns_timeouts = 3;
    record.counters.fake_ip_mappings = 17;
    record.counters.policy_direct = 5;
    record.sources.push_back({"rules", "https://example.invalid/rules", "etag-1", "date-1", "sha256", 42, updatedAt});
    return record;
}

std::string ReadAll(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void WriteText(const fs::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    BOOST_REQUIRE(output.good());
}
}

BOOST_AUTO_TEST_SUITE(policy_status_file_tests)

BOOST_AUTO_TEST_CASE(writes_all_fields_and_classifies_current_process) {
    TempDirectory directory;
    PolicyStatusRecord record = Record(NowMs());
    BOOST_REQUIRE(GetCurrentProcessIdentity(record.pid, record.process_start, record.last_diagnostic));
    record.last_diagnostic.clear();
    std::string error;
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));

    const auto result = ReadStatus(directory.File().string(), record.identity, NowMs());
#if defined(__linux__) || defined(_WIN32)
    BOOST_TEST(static_cast<int>(result.state) == static_cast<int>(PolicyStatusState::Online));
#else
    BOOST_TEST(static_cast<int>(result.state) == static_cast<int>(PolicyStatusState::Unverified));
#endif
    BOOST_TEST(result.record.session_generation == 7u);
    BOOST_TEST(result.record.active_version == 12u);
    BOOST_TEST(result.record.prepared_version == 13u);
    BOOST_TEST(result.record.prepared_digest == "prepared-digest");
    BOOST_TEST(result.record.counters.dns_cache_hits == 101u);
    BOOST_TEST(result.record.counters.dns_timeout_attempts == 4u);
    BOOST_TEST(result.record.counters.dns_timeouts == 3u);
    BOOST_TEST(result.record.counters.fake_ip_mappings == 17u);
    BOOST_TEST(result.record.counters.policy_direct == 5u);
    BOOST_REQUIRE_EQUAL(result.record.sources.size(), 1u);
    BOOST_TEST(result.record.sources[0].url_redacted == "https://example.invalid/rules");
}

BOOST_AUTO_TEST_CASE(reports_pid_start_mismatch_as_offline) {
    TempDirectory directory;
    std::string error;
    auto record = Record(NowMs());
    BOOST_REQUIRE(GetCurrentProcessIdentity(record.pid, record.process_start, error));
    record.process_start += "-reused";
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    const auto result = ReadStatus(directory.File().string(), record.identity, NowMs());
    BOOST_TEST(static_cast<int>(result.state) == static_cast<int>(PolicyStatusState::Offline));
    BOOST_TEST(result.reason.find("start identity") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(identity_and_explicit_shutdown_are_offline) {
    TempDirectory directory;
    std::string error;
    auto record = Record(NowMs());
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    auto mismatch = ReadStatus(directory.File().string(), "other-identity", NowMs());
    BOOST_TEST(static_cast<int>(mismatch.state) == static_cast<int>(PolicyStatusState::Offline));
    BOOST_TEST(mismatch.reason.find("identity") != std::string::npos);
    record.offline = true;
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    const auto stopped = ReadStatus(directory.File().string(), record.identity, NowMs());
    BOOST_TEST(static_cast<int>(stopped.state) == static_cast<int>(PolicyStatusState::Offline));
    BOOST_TEST(stopped.reason.find("marks the process offline") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_duplicate_keys_unknown_keys_and_typed_invalid_fields) {
    TempDirectory directory;
    std::string error;
    const auto record = Record(NowMs());
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    const std::string valid = ReadAll(directory.File());

    std::string duplicate = valid;
    duplicate.replace(duplicate.find("\"schema\":1"), 10, "\"schema\":1,\"schema\":1");
    WriteText(directory.File(), duplicate);
    auto result = ReadStatus(directory.File().string(), record.identity, NowMs());
    BOOST_TEST(static_cast<int>(result.state) == static_cast<int>(PolicyStatusState::Offline));

    std::string invalidType = valid;
    const auto version = invalidType.find("\"active_version\":12");
    BOOST_REQUIRE(version != std::string::npos);
    invalidType.replace(version, 19, "\"active_version\":\"12\"");
    WriteText(directory.File(), invalidType);
    result = ReadStatus(directory.File().string(), record.identity, NowMs());
    BOOST_TEST(result.reason.find("field types") != std::string::npos);

    std::string unknown = valid;
    unknown.insert(unknown.rfind('}'), ",\"unexpected\":true");
    WriteText(directory.File(), unknown);
    result = ReadStatus(directory.File().string(), record.identity, NowMs());
    BOOST_TEST(result.reason.find("unknown key") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(rejects_oversized_file_before_reading_it_whole) {
    TempDirectory directory;
    WriteText(directory.File(), std::string(1024u * 1024u + 1u, ' '));
    const auto result = ReadStatus(directory.File().string(), "test-identity", NowMs());
    BOOST_TEST(result.reason.find("size limit") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(reports_expired_and_future_timestamps_as_stale) {
    TempDirectory directory;
    std::string error;
    auto record = Record(1000);
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    const auto expired = ReadStatus(directory.File().string(), record.identity, 1121, 120);
    BOOST_TEST(static_cast<int>(expired.state) == static_cast<int>(PolicyStatusState::Stale));
    record.updated_at_ms = 2000;
    BOOST_REQUIRE(WriteStatusAtomically(directory.File().string(), record.identity, record, error));
    const auto future = ReadStatus(directory.File().string(), record.identity, 1100);
    BOOST_TEST(static_cast<int>(future.state) == static_cast<int>(PolicyStatusState::Stale));
}

BOOST_AUTO_TEST_CASE(writer_refuses_identity_mismatch) {
    std::string error;
    BOOST_TEST(!WriteStatusAtomically("unused", "expected", Record(NowMs()), error));
    BOOST_TEST(error.find("identity") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(writer_lease_excludes_competing_cli_writers) {
    TempDirectory directory;
    std::string error;
    PolicyStatusWriterLease runtime;
    PolicyStatusWriterLease cli;
    BOOST_REQUIRE(runtime.TryAcquire(directory.File().string(), "test-identity", error));
    BOOST_TEST(runtime.OwnsLease());
    BOOST_TEST(!cli.TryAcquire(directory.File().string(), "test-identity", error));
    BOOST_TEST(error.find("already held") != std::string::npos);

    auto record = Record(NowMs());
    BOOST_REQUIRE(GetCurrentProcessIdentity(record.pid, record.process_start, error));
    BOOST_REQUIRE(runtime.Write(record, error));
    BOOST_TEST(!cli.Write(record, error));
    runtime.Release();

    BOOST_REQUIRE(cli.TryAcquire(directory.File().string(), "test-identity", error));
    record.offline = true;
    record.updated_at_ms = NowMs();
    BOOST_REQUIRE(cli.Write(record, error));
    BOOST_TEST(static_cast<int>(ReadStatus(directory.File().string(), record.identity, NowMs()).state) ==
        static_cast<int>(PolicyStatusState::Offline));
}

BOOST_AUTO_TEST_CASE(update_status_conversion_preserves_prepared_state_and_counters) {
    PolicyUpdateStatus update;
    update.identity_fingerprint = "test-identity";
    update.active_version = 8;
    update.prepared_pending_commit = true;
    update.prepared_version = 9;
    update.prepared_digest = "digest-9";
    update.durable_current = true;
    update.last_result = "prepared";
    update.sources.push_back({"rules", "https://example.invalid/rules", "etag", "date", "hash", 12, 100});
    PolicyStatusCounters counters;
    counters.dns_cache_hits = 4;
    counters.fake_ip_pending = 2;
    counters.policy_reject = 1;
    auto record = MakePolicyStatusRecord(update, counters, 10, "start-token", 3, 1000, true);
    BOOST_TEST(record.identity == "test-identity");
    BOOST_TEST(record.session_generation == 3u);
    BOOST_TEST(record.active_version == 8u);
    BOOST_TEST(record.prepared_version == 9u);
    BOOST_TEST(record.prepared_digest == "digest-9");
    BOOST_TEST(record.offline);
    BOOST_TEST(record.counters.dns_cache_hits == 4u);
    BOOST_TEST(record.counters.fake_ip_pending == 2u);
    BOOST_TEST(record.counters.policy_reject == 1u);
    BOOST_REQUIRE_EQUAL(record.sources.size(), 1u);
    BOOST_TEST(record.sources[0].url_redacted == "https://example.invalid/rules");
}

BOOST_AUTO_TEST_SUITE_END()
