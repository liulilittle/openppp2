#define BOOST_TEST_MODULE durable_fake_ip_store_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DurableFakeIpStore.h>
#include <ppp/app/client/dns/PolicyTelemetry.h>

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <mutex>
#include <string>
#include <thread>

namespace dns = ppp::app::client::dns;
namespace fs = std::filesystem;

namespace {
struct TempDirectory final {
    fs::path path;
    TempDirectory() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path = fs::temp_directory_path() / ("openppp2-fake-ip-" + std::to_string(stamp));
        fs::create_directories(path);
    }
    ~TempDirectory() { std::error_code ec; fs::remove_all(path, ec); }
};

std::string Read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void Write(const fs::path& path, const std::string& value) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
}

std::string HexBytes(const std::string& value) {
    static const char digits[] = "0123456789abcdef";
    std::string encoded;
    for (unsigned char ch : value) {
        encoded.push_back(digits[ch >> 4]);
        encoded.push_back(digits[ch & 15]);
    }
    return encoded;
}

uint64_t Checksum(const std::string& value) {
    uint64_t hash = 14695981039346656037ull;
    for (unsigned char ch : value) {
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string ChecksumHex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    std::string encoded(16, '0');
    for (int i = 15; i >= 0; --i) {
        encoded[static_cast<std::size_t>(i)] = digits[value & 15u];
        value >>= 4;
    }
    return encoded;
}

std::string JournalRecord(uint64_t sequence, uint32_t address, const std::string& hostname) {
    const std::string prefix = "A|" + std::to_string(sequence) + "|" + std::to_string(address) + "|" +
        HexBytes(hostname) + "|";
    return prefix + ChecksumHex(Checksum(prefix)) + "\n";
}
}

BOOST_AUTO_TEST_CASE(allocation_is_durable_and_reopens_with_the_same_identity) {
    TempDirectory temp;
    uint32_t first = 0;
    {
        dns::DurableFakeIpStore store;
        BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        BOOST_REQUIRE(store.Allocate("Api.Example.com.", first));
        BOOST_TEST(first == 0xc6120004u);
        BOOST_TEST(Read(temp.path / "fake-ip.journal").find("api.example.com") == std::string::npos);
    }
    dns::DurableFakeIpStore reopened;
    BOOST_REQUIRE(reopened.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t same = 0;
    BOOST_REQUIRE(reopened.Allocate("api.example.com", same));
    BOOST_TEST(same == first);
    std::string hostname;
    BOOST_REQUIRE(reopened.LookupHostname(first, hostname));
    BOOST_TEST(hostname == "api.example.com");
}

BOOST_AUTO_TEST_CASE(only_an_incomplete_final_journal_record_is_ignored) {
    TempDirectory temp;
    uint32_t first = 0;
    {
        dns::DurableFakeIpStore store;
        BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        BOOST_REQUIRE(store.Allocate("one.example", first));
    }
    const auto journal_path = temp.path / "fake-ip.journal";
    auto journal = Read(journal_path);
    journal += "A|2|3323068421|74776f2e6578616d706c65|deadbeef";
    Write(journal_path, journal);
    dns::DurableFakeIpStore reopened;
    BOOST_REQUIRE(reopened.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t second = 0;
    BOOST_REQUIRE(reopened.Allocate("two.example", second));
    BOOST_TEST(second != first);
    reopened.Close();
    dns::DurableFakeIpStore appended_after_repair;
    BOOST_REQUIRE(appended_after_repair.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t restored_first = 0, restored_second = 0;
    BOOST_REQUIRE(appended_after_repair.LookupAddress("one.example", restored_first));
    BOOST_REQUIRE(appended_after_repair.LookupAddress("two.example", restored_second));
    BOOST_TEST(restored_first == first);
    BOOST_TEST(restored_second == second);
    appended_after_repair.Close();

    journal = Read(journal_path);
    journal += "A|99|3323068422|6261642e6578616d706c65|0000000000000000\n";
    Write(journal_path, journal);
    dns::DurableFakeIpStore corrupt;
    BOOST_TEST(!corrupt.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
}

BOOST_AUTO_TEST_CASE(identity_and_pool_changes_are_rejected) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    store.Close();
    BOOST_TEST(!store.Open(temp.path.string(), "profile-b", "198.18.0.0/16"));
    BOOST_TEST(!store.Open(temp.path.string(), "profile-a", "198.19.0.0/16"));
}

BOOST_AUTO_TEST_CASE(pool_validation_keeps_fake_range_bounds_inside_the_cidr) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_TEST(!store.Open(temp.path.string(), "profile-small", "198.18.0.0/31"));
    BOOST_TEST(!store.Open(temp.path.string(), "profile-relay", "198.19.0.0/16"));
    BOOST_TEST(!store.Open(temp.path.string(), "profile-overlap", "198.18.0.0/15"));
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/29"));
    BOOST_TEST(store.Contains(0xc6120000u));
    BOOST_TEST(store.Contains(0xc6120007u));
    BOOST_TEST(!store.Contains(0xc6120008u));
    uint32_t address = 0;
    BOOST_REQUIRE(store.Allocate("first.example", address));
    BOOST_TEST(address == 0xc6120004u);
}

BOOST_AUTO_TEST_CASE(pool_exhaustion_rejects_the_next_hostname) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-small", "198.18.0.0/29"));
    uint32_t a = 0, b = 0, c = 0, overflow = 1;
    BOOST_REQUIRE(store.Allocate("a.example", a));
    BOOST_REQUIRE(store.Allocate("b.example", b));
    BOOST_REQUIRE(store.Allocate("c.example", c));
    BOOST_TEST(a == 0xc6120004u);
    BOOST_TEST(b == 0xc6120005u);
    BOOST_TEST(c == 0xc6120006u);
    BOOST_TEST(!store.Allocate("overflow.example", overflow));
    BOOST_TEST(overflow == 0u);
}

BOOST_AUTO_TEST_CASE(store_stats_report_mappings_exhaustion_and_durable_failures) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-small", "198.18.0.0/29"));
    uint32_t first = 0, second = 0, third = 0, overflow = 0;
    BOOST_REQUIRE(store.Allocate("a.example", first));
    BOOST_REQUIRE(store.Allocate("b.example", second));
    BOOST_REQUIRE(store.Allocate("c.example", third));
    BOOST_TEST(store.SnapshotStats().fake_ip_mappings == 3u);
    BOOST_TEST(!store.Allocate("overflow.example", overflow));
    const auto exhausted = store.SnapshotStats();
    BOOST_TEST(exhausted.fake_ip_mappings == 3u);
    BOOST_TEST(exhausted.fake_ip_exhaustions == 1u);
    BOOST_TEST(exhausted.fake_ip_persistence_errors == 0u);
    store.Close();
    BOOST_TEST(store.SnapshotStats().fake_ip_mappings == 3u);

    TempDirectory failed_temp;
    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
        return stage != dns::DurableFakeIpStore::Stage::JournalFlush;
    };
    dns::DurableFakeIpStore failing;
    BOOST_REQUIRE(failing.Open(failed_temp.path.string(), "profile-a", "198.18.0.0/16", options));
    uint32_t unpublished = 0;
    BOOST_TEST(!failing.Allocate("unpublished.example", unpublished));
    const auto failed = failing.SnapshotStats();
    BOOST_TEST(failed.fake_ip_mappings == 0u);
    BOOST_TEST(failed.fake_ip_exhaustions == 0u);
    BOOST_TEST(failed.fake_ip_persistence_errors == 1u);
    failing.Close();
    BOOST_TEST(failing.SnapshotStats().fake_ip_persistence_errors == 1u);
}

BOOST_AUTO_TEST_CASE(policy_telemetry_snapshots_are_session_scoped_and_conserve_gauges) {
    dns::PolicyTelemetry first;
    dns::PolicyTelemetry second;
    first.RecordDnsCacheHit();
    first.RecordDnsCacheMiss();
    first.RecordDnsCacheCoalesced();
    first.RecordDnsTimeout();
    first.RecordDnsUpstreamFailure();
    first.RecordDnsCancelled();
    first.RecordPolicyDirect();
    first.RecordPolicyProxy();
    first.RecordPolicyReject();
    first.AddFakeIpPending(2);
    first.AddFakeIpPending(-1);
    first.AddFakeIpPending(-4);

    dns::DurableFakeIpStore::Stats store;
    store.fake_ip_mappings = 7;
    store.fake_ip_exhaustions = 3;
    store.fake_ip_persistence_errors = 2;
    const auto snapshot = first.Snapshot(store);
    BOOST_TEST(snapshot.dns_cache_hits == 1u);
    BOOST_TEST(snapshot.dns_cache_misses == 1u);
    BOOST_TEST(snapshot.dns_cache_coalesced == 1u);
    BOOST_TEST(snapshot.dns_timeouts == 1u);
    BOOST_TEST(snapshot.dns_upstream_failures == 1u);
    BOOST_TEST(snapshot.dns_cancelled == 1u);
    BOOST_TEST(snapshot.fake_ip_mappings == 7u);
    BOOST_TEST(snapshot.fake_ip_exhaustions == 3u);
    BOOST_TEST(snapshot.fake_ip_persistence_errors == 2u);
    BOOST_TEST(snapshot.fake_ip_pending == 0u);
    BOOST_TEST(snapshot.policy_direct == 1u);
    BOOST_TEST(snapshot.policy_proxy == 1u);
    BOOST_TEST(snapshot.policy_reject == 1u);

    const auto isolated = second.Snapshot();
    BOOST_TEST(isolated.dns_cache_hits == 0u);
    BOOST_TEST(isolated.policy_direct == 0u);
    BOOST_TEST(isolated.fake_ip_mappings == 0u);
}

BOOST_AUTO_TEST_CASE(lock_is_exclusive_and_failed_durable_append_poison_store) {
    TempDirectory temp;
    dns::DurableFakeIpStore first;
    BOOST_REQUIRE(first.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    dns::DurableFakeIpStore second;
    BOOST_TEST(!second.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));

    first.Close();
    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
        return stage != dns::DurableFakeIpStore::Stage::JournalFlush;
    };
    dns::DurableFakeIpStore failing;
    BOOST_REQUIRE(failing.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
    uint32_t address = 123;
    BOOST_TEST(!failing.Allocate("blocked.example", address));
    BOOST_TEST(address == 0u);
    BOOST_TEST(!failing.IsOpen());
    BOOST_TEST(!failing.Allocate("other.example", address));
}

BOOST_AUTO_TEST_CASE(known_mapping_lookup_does_not_wait_for_append_flush) {
    TempDirectory temp;
    uint32_t first = 0;
    {
        dns::DurableFakeIpStore initial;
        BOOST_REQUIRE(initial.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        BOOST_REQUIRE(initial.Allocate("one.example", first));
    }

    std::mutex gate_mutex;
    std::condition_variable gate_condition;
    bool flush_entered = false;
    bool resume_flush = false;
    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [&](dns::DurableFakeIpStore::Stage stage) {
        if (stage != dns::DurableFakeIpStore::Stage::JournalFlush) return true;
        std::unique_lock<std::mutex> lock(gate_mutex);
        flush_entered = true;
        gate_condition.notify_all();
        gate_condition.wait(lock, [&] { return resume_flush; });
        return true;
    };

    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
    bool allocation_ok = false;
    std::thread allocation([&] {
        uint32_t second = 0;
        allocation_ok = store.Allocate("two.example", second);
    });
    bool reached_flush = false;
    {
        std::unique_lock<std::mutex> lock(gate_mutex);
        reached_flush = gate_condition.wait_for(lock, std::chrono::seconds(5), [&] { return flush_entered; });
    }
    auto lookup = std::async(std::launch::async, [&] {
        std::string hostname;
        return store.LookupHostname(first, hostname) && hostname == "one.example" && store.Contains(first);
    });
    const auto lookup_status = lookup.wait_for(std::chrono::seconds(1));
    const auto while_flushing = store.SnapshotStats();
    {
        std::lock_guard<std::mutex> lock(gate_mutex);
        resume_flush = true;
    }
    gate_condition.notify_all();
    allocation.join();
    BOOST_TEST(reached_flush);
    const bool lookup_completed_during_flush = lookup_status == std::future_status::ready;
    BOOST_TEST(lookup_completed_during_flush);
    BOOST_TEST(lookup.get());
    BOOST_TEST(allocation_ok);
    BOOST_TEST(while_flushing.fake_ip_mappings == 1u);
    BOOST_TEST(store.SnapshotStats().fake_ip_mappings == 2u);
}

BOOST_AUTO_TEST_CASE(compaction_preserves_mappings_and_replays_new_tail) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t first = 0, second = 0;
    BOOST_REQUIRE(store.Allocate("one.example", first));
    BOOST_REQUIRE(store.Compact());
    BOOST_TEST(Read(temp.path / "fake-ip.journal").empty());
    BOOST_REQUIRE(store.Allocate("two.example", second));
    BOOST_REQUIRE(store.Compact());
    uint32_t third = 0;
    BOOST_REQUIRE(store.Allocate("three.example", third));
    store.Close();

    dns::DurableFakeIpStore reopened;
    BOOST_REQUIRE(reopened.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t restored_first = 0, restored_second = 0, restored_third = 0;
    BOOST_REQUIRE(reopened.LookupAddress("one.example", restored_first));
    BOOST_REQUIRE(reopened.LookupAddress("two.example", restored_second));
    BOOST_REQUIRE(reopened.LookupAddress("three.example", restored_third));
    BOOST_TEST(restored_first == first);
    BOOST_TEST(restored_second == second);
    BOOST_TEST(restored_third == third);
}

BOOST_AUTO_TEST_CASE(compaction_crash_before_journal_truncate_recovers_from_snapshot) {
    TempDirectory temp;
    {
        dns::DurableFakeIpStore store;
        BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        uint32_t first = 0;
        BOOST_REQUIRE(store.Allocate("one.example", first));
        BOOST_REQUIRE(store.Compact());
        uint32_t second = 0;
        BOOST_REQUIRE(store.Allocate("two.example", second));
        dns::DurableFakeIpStore::Options options;
        options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
            return stage != dns::DurableFakeIpStore::Stage::JournalTruncate;
        };
        // Reopen under the fault seam so snapshot replacement succeeds but log truncation fails.
        store.Close();
        dns::DurableFakeIpStore failing;
        BOOST_REQUIRE(failing.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
        BOOST_TEST(!failing.Compact());
        BOOST_TEST(!failing.IsOpen());
    }
    dns::DurableFakeIpStore recovered;
    BOOST_REQUIRE(recovered.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t first = 0, second = 0, third = 0;
    BOOST_REQUIRE(recovered.LookupAddress("one.example", first));
    BOOST_REQUIRE(recovered.LookupAddress("two.example", second));
    BOOST_REQUIRE(recovered.Allocate("three.example", third));
    recovered.Close();
    dns::DurableFakeIpStore reopened;
    BOOST_REQUIRE(reopened.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t restored_first = 0, restored_second = 0, restored_third = 0;
    BOOST_REQUIRE(reopened.LookupAddress("one.example", restored_first));
    BOOST_REQUIRE(reopened.LookupAddress("two.example", restored_second));
    BOOST_REQUIRE(reopened.LookupAddress("three.example", restored_third));
    BOOST_TEST(restored_first == first);
    BOOST_TEST(restored_second == second);
    BOOST_TEST(restored_third == third);
}

BOOST_AUTO_TEST_CASE(compacted_journal_rejects_a_valid_checksum_with_a_sequence_gap) {
    TempDirectory temp;
    dns::DurableFakeIpStore store;
    BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    uint32_t first = 0, second = 0;
    BOOST_REQUIRE(store.Allocate("one.example", first));
    BOOST_REQUIRE(store.Allocate("two.example", second));
    BOOST_REQUIRE(store.Compact());
    store.Close();

    Write(temp.path / "fake-ip.journal",
        JournalRecord(1, first, "one.example") +
        JournalRecord(3, 0xc6120006u, "three.example"));
    dns::DurableFakeIpStore rejected;
    BOOST_TEST(!rejected.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
}

BOOST_AUTO_TEST_CASE(failed_torn_tail_repair_blocks_open_until_repair_succeeds) {
    const dns::DurableFakeIpStore::Stage failing_stages[] = {
        dns::DurableFakeIpStore::Stage::JournalRepair,
        dns::DurableFakeIpStore::Stage::JournalRepairFlush
    };
    for (std::size_t i = 0; i < sizeof(failing_stages) / sizeof(failing_stages[0]); ++i) {
        TempDirectory temp;
        {
            dns::DurableFakeIpStore store;
            BOOST_REQUIRE(store.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
            uint32_t first = 0;
            BOOST_REQUIRE(store.Allocate("one.example", first));
        }
        {
            std::ofstream journal(temp.path / "fake-ip.journal", std::ios::binary | std::ios::app);
            journal << "A|2|3323068421|74776f2e6578616d706c65|deadbeef";
        }
        dns::DurableFakeIpStore::Options options;
        const auto fail_at = failing_stages[i];
        options.allow_stage = [fail_at](dns::DurableFakeIpStore::Stage stage) { return stage != fail_at; };
        dns::DurableFakeIpStore failed_repair;
        BOOST_TEST(!failed_repair.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
        dns::DurableFakeIpStore recovered;
        BOOST_REQUIRE(recovered.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        uint32_t second = 0;
        BOOST_REQUIRE(recovered.Allocate("two.example", second));
        recovered.Close();
        dns::DurableFakeIpStore reopened;
        BOOST_REQUIRE(reopened.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
        uint32_t restored = 0;
        BOOST_REQUIRE(reopened.LookupAddress("two.example", restored));
        BOOST_TEST(restored == second);
    }
}

BOOST_AUTO_TEST_CASE(failed_initial_directory_flush_can_be_retried_without_losing_store) {
    TempDirectory temp;
    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
        return stage != dns::DurableFakeIpStore::Stage::DirectoryFlush;
    };
    dns::DurableFakeIpStore failing;
    BOOST_TEST(!failing.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
    dns::DurableFakeIpStore recovered;
    BOOST_REQUIRE(recovered.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
}

BOOST_AUTO_TEST_CASE(snapshot_write_flush_and_rename_failures_do_not_open_store) {
    const dns::DurableFakeIpStore::Stage failing_stages[] = {
        dns::DurableFakeIpStore::Stage::SnapshotWrite,
        dns::DurableFakeIpStore::Stage::SnapshotFlush,
        dns::DurableFakeIpStore::Stage::SnapshotRename
    };
    for (std::size_t i = 0; i < sizeof(failing_stages) / sizeof(failing_stages[0]); ++i) {
        TempDirectory temp;
        dns::DurableFakeIpStore::Options options;
        const auto fail_at = failing_stages[i];
        options.allow_stage = [fail_at](dns::DurableFakeIpStore::Stage stage) { return stage != fail_at; };
        dns::DurableFakeIpStore failing;
        BOOST_TEST(!failing.Open(temp.path.string(), "profile-a", "198.18.0.0/16", options));
        dns::DurableFakeIpStore recovered;
        BOOST_REQUIRE(recovered.Open(temp.path.string(), "profile-a", "198.18.0.0/16"));
    }
}

BOOST_AUTO_TEST_CASE(directory_create_failure_prevents_first_mapping_from_being_published) {
    TempDirectory temp;
    const auto storage = temp.path / "new" / "identity";
    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
        return stage != dns::DurableFakeIpStore::Stage::DirectoryCreate;
    };
    dns::DurableFakeIpStore failed;
    BOOST_TEST(!failed.Open(storage.string(), "profile-a", "198.18.0.0/16", options));
    uint32_t unpublished = 1;
    BOOST_TEST(!failed.Allocate("one.example", unpublished));
    BOOST_TEST(unpublished == 0u);

    dns::DurableFakeIpStore recovered;
    BOOST_REQUIRE(recovered.Open(storage.string(), "profile-a", "198.18.0.0/16"));
    uint32_t first = 0;
    BOOST_REQUIRE(recovered.Allocate("one.example", first));
    BOOST_TEST(first == 0xc6120004u);
    recovered.Close();
    dns::DurableFakeIpStore reopened;
    BOOST_REQUIRE(reopened.Open(storage.string(), "profile-a", "198.18.0.0/16"));
    uint32_t same = 0;
    BOOST_REQUIRE(reopened.Allocate("one.example", same));
    BOOST_TEST(same == first);
}

#if !defined(_WIN32)
BOOST_AUTO_TEST_CASE(parent_flush_failure_blocks_open_and_keeps_acknowledged_identity) {
    TempDirectory temp;
    const auto storage = temp.path / "identity";
    uint32_t first = 0;
    {
        dns::DurableFakeIpStore store;
        BOOST_REQUIRE(store.Open(storage.string(), "profile-a", "198.18.0.0/16"));
        BOOST_REQUIRE(store.Allocate("one.example", first));
    }

    dns::DurableFakeIpStore::Options options;
    options.allow_stage = [](dns::DurableFakeIpStore::Stage stage) {
        return stage != dns::DurableFakeIpStore::Stage::ParentFlush;
    };
    dns::DurableFakeIpStore failed;
    BOOST_TEST(!failed.Open(storage.string(), "profile-a", "198.18.0.0/16", options));
    uint32_t unpublished = 1;
    BOOST_TEST(!failed.Allocate("two.example", unpublished));
    BOOST_TEST(unpublished == 0u);

    dns::DurableFakeIpStore recovered;
    BOOST_REQUIRE(recovered.Open(storage.string(), "profile-a", "198.18.0.0/16"));
    uint32_t restored = 0, second = 0;
    BOOST_REQUIRE(recovered.Allocate("one.example", restored));
    BOOST_REQUIRE(recovered.Allocate("two.example", second));
    BOOST_TEST(restored == first);
    BOOST_TEST(second != first);
}
#endif
