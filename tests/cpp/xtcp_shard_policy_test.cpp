#include <ppp/app/client/xtcp/XtcpShardPolicy.h>
#include <cstdio>
#include <cstdlib>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort(); } } while (0)
using namespace ppp::app::client::xtcp;

int main() {
    XtcpCpuInputs cpus;
    cpus.online = 32; cpus.quota_cpus = 32; cpus.affinity_known = cpus.quota_known = true;
    cpus.allowed = {1, 3, 5, 7, 9, 11, 13, 15};
    CHECK(cpus.Effective() == 8);
    CHECK(SelectXtcpShards("", "", cpus, true).shards == 1);
    CHECK(SelectXtcpShards("auto", "", cpus, true).shards == 4);
    CHECK(SelectXtcpShards("auto", "", cpus, false).shards == 1);
    CHECK(SelectXtcpShards("auto", "0", cpus, true).shards == 1);
    for (unsigned i = 1; i <= 8; ++i) CHECK(SelectXtcpShards(std::to_string(i), "0", cpus, true).shards == i);
    for (auto text : {"0", "9", "2junk", " 2", "2 ", "+2", "-1", "AUTO", "18446744073709551616"}) {
        auto result = SelectXtcpShards(text, "", cpus, true);
        CHECK(result.shards == 1 && result.invalid);
    }
    CHECK(SelectXtcpShards("auto", "no", cpus, true).invalid);
    cpus.quota_cpus = 3;
    CHECK(SelectXtcpShards("auto", "", cpus, true).shards == 1);
    cpus.quota_cpus = 0; CHECK(cpus.Effective() == 1);
    cpus.quota_cpus = 32; cpus.quota_known = false;
    CHECK(SelectXtcpShards("auto", "", cpus, true).shards == 1);
    cpus.quota_known = true;
    std::vector<unsigned> list;
    for (auto text : {"", "1,", ",1", "1,,2", "1,1", "1, 3", "-1", "+1", "1-3", "4294967296"})
        CHECK(!ParseXtcpCpuList(text, list));
    CHECK(ParseXtcpCpuList("3,1", list) && list[0] == 3 && list[1] == 1);
    CHECK(SelectXtcpWorkerAffinity("workers", "3,1", "1", 2, cpus, true).enabled);
    CHECK(!SelectXtcpWorkerAffinity("workers", "3,2", "1", 2, cpus, true).valid);
    CHECK(!SelectXtcpWorkerAffinity("workers", "3", "1", 2, cpus, true).valid);
    {
        auto queues = SelectXtcpWorkerAffinity("queues", "3,1", "1", 2, cpus, true);
        CHECK(queues.valid && queues.enabled && queues.queues && queues.reason == "queues");
        CHECK(queues.cpus.size() == 2 && queues.cpus[0] == 3 && queues.cpus[1] == 1);
        CHECK(!queues.CanStart(false) && queues.CanStart(true)); // strict: every pin must succeed
        auto degraded = SelectXtcpWorkerAffinity("queues", "3,1", "0", 2, cpus, true);
        CHECK(degraded.CanStart(false));                        // non-strict: degraded start
        // Strict map rules: count mismatch, duplicates, outside envelope, format, platform.
        for (auto text : {"3", "3,1,5", "3,3", "3,2", "3,x", "", "3, 1"}) {
            auto bad = SelectXtcpWorkerAffinity("queues", text, "1", 2, cpus, true);
            CHECK(!bad.valid && !bad.enabled && bad.reason == "invalid-queue-map" && !bad.CanStart(true));
        }
        CHECK(!SelectXtcpWorkerAffinity("queues", "3,1", "1", 2, cpus, false).valid);
        auto quota = cpus; quota.quota_cpus = 1;
        CHECK(!SelectXtcpWorkerAffinity("queues", "3,1", "1", 2, quota, true).valid);
        auto single = SelectXtcpWorkerAffinity("queues", "3", "1", 0, cpus, true);
        CHECK(single.valid && !single.enabled && single.queues);
        CHECK(single.reason == "queues-unsupported-single-shard");
    }
    CHECK(!SelectXtcpWorkerAffinity("workers", "3,1", "1", 0, cpus, true).valid);
    CHECK(!SelectXtcpWorkerAffinity("workers", "3,1", "1", 2, cpus, false).valid);
    CHECK(!SelectXtcpWorkerAffinity("workers", "3,1", "true", 2, cpus, true).valid);
    CHECK(!SelectXtcpWorkerAffinity("off", "", "", 2, cpus, true).enabled);
    unsigned reads = 0;
    CHECK(!ApplyXtcpWorkerAffinity(3, [](unsigned) noexcept { return false; }, [&](unsigned) noexcept { ++reads; return true; }));
    CHECK(reads == 0);
    CHECK(!ApplyXtcpWorkerAffinity(3, [](unsigned) noexcept { return true; }, [](unsigned) noexcept { return false; }));
    CHECK(ApplyXtcpWorkerAffinity(3, [](unsigned id) noexcept { return id == 3; }, [](unsigned id) noexcept { return id == 3; }));
    auto strict_map = SelectXtcpWorkerAffinity("workers", "3,1", "1", 2, cpus, true);
    const bool mock_failure = ApplyXtcpWorkerAffinity(3, [](unsigned) noexcept { return false; }, [](unsigned) noexcept { return true; });
    CHECK(!strict_map.CanStart(mock_failure));
    CHECK(strict_map.CanStart(true));
    strict_map.strict = false;
    CHECK(strict_map.CanStart(mock_failure));
    std::puts("xtcp_shard_policy_test: parsing, quota, rollback, platform, and mock pin cases passed");
}
