// bm_rib_lpm —— RIB/FIB Longest-Prefix-Match lookup microbenchmark.
//
// Builds N routes with varying prefixes (/8, /16, /24, /32), fills a
// ForwardInformationTable snapshot, then hammers GetNextHop() with random
// destination IPs in the hot loop to measure LPM hash-lookup throughput.
//
// Linked with rib.cpp + bench_stubs.cpp + bench_alloc_stub.cpp.
// rib.cpp depends on IPEndPoint (NoneAddress/AnyAddress/PrefixToNetmask),
// ppp::io::File, ppp::diagnostics, Tokenize/ATrim helpers — declarations come
// from rib.h/stdafx headers; only AddRoute/Fill/GetNextHop are exercised here.
#include <benchmark/benchmark.h>

#include <ppp/net/native/rib.h>

#include <cstdint>
#include <vector>

using ppp::net::IPEndPoint;
using ppp::net::native::ForwardInformationTable;
using ppp::net::native::RouteInformationTable;

namespace {
// Deterministic xorshift32 PRNG (avoids <random> runtime cost), returns a
// 32-bit pseudo-random value and advances state in place.
inline uint32_t xorshift32(uint32_t& state) noexcept {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// Pre-generates n random destination IPs for hot-loop queries so the PRNG
// itself is not measured.
std::vector<uint32_t> make_query_ips(int n) {
    std::vector<uint32_t> ips;
    ips.reserve(static_cast<size_t>(n));
    uint32_t state = 0x12345678u;
    for (int i = 0; i < n; ++i) {
        ips.push_back(xorshift32(state));
    }
    return ips;
}
} // namespace

static void BM_RibLpm(benchmark::State& state) {
    const int route_count = static_cast<int>(state.range(0));

    // Build a RIB with route_count routes, then snapshot it into a FIB so
    // Fill() copies + sorts the buckets for longest-prefix lookup.
    RouteInformationTable rib;
    const uint32_t gw = htonl((10u << 24) | 1u); // 10.0.0.1, network order
    for (int i = 0; i < route_count; ++i) {
        int prefix;
        switch (i & 3) {
            case 0:  prefix = 8;  break;
            case 1:  prefix = 16; break;
            case 2:  prefix = 24; break;
            default: prefix = 32; break;
        }
        uint32_t b0 = static_cast<uint32_t>((i >> 16) & 0xFF);
        uint32_t b1 = static_cast<uint32_t>((i >> 8) & 0xFF);
        uint32_t b2 = static_cast<uint32_t>(i & 0xFF);
        uint32_t addr = htonl((172u << 24) | (b0 << 16) | (b1 << 8) | b2);
        uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
        addr &= mask; // ensure (ip & mask) == ip so AddRoute accepts it
        rib.AddRoute(addr, prefix, gw);
    }

    ForwardInformationTable fib;
    fib.Fill(rib);
    if (!fib.IsAvailable()) {
        state.SkipWithError("FIB fill produced no forwarding entries");
        return;
    }

    const int query_count = 1024;
    std::vector<uint32_t> query_ips = make_query_ips(query_count);

    for (auto _ : state) {
        for (int i = 0; i < query_count; ++i) {
            uint32_t nh = fib.GetNextHop(query_ips[static_cast<size_t>(i)]);
            benchmark::DoNotOptimize(nh);
        }
    }
    state.SetItemsProcessed(state.iterations() * query_count);
    state.counters["routes"] = route_count;
}

BENCHMARK(BM_RibLpm)
    ->Arg(100)->Arg(1000)->Arg(10000)
    ->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
