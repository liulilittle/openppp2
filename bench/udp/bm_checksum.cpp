// bm_checksum —— Internet checksum (ip_standard_chksum) 微基准。
// checksum.cpp 提供 SSE2 SIMD（由 __SIMD__ 守卫）与标量两个实现，
// 当 bench CMake 列表以 __SIMD__ 编译时，此处测量的是 SSE2 加速路径。
#include <benchmark/benchmark.h>

#include <ppp/net/native/checksum.h>

#include <cstdint>
#include <vector>

using ppp::net::native::ip_standard_chksum;

namespace {
// 填充确定性 pattern 数据，避免全零缓冲区让优化器过度折叠。
std::vector<uint8_t> make_buffer(int len) {
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    for (int i = 0; i < len; ++i) {
        buf[static_cast<size_t>(i)] = static_cast<uint8_t>((i * 131 + 7) & 0xFF);
    }
    return buf;
}
} // namespace

static void BM_Checksum(benchmark::State& state) {
    const int len = static_cast<int>(state.range(0));
    std::vector<uint8_t> buf = make_buffer(len);

    // 自检：校验和对相同输入应稳定返回同一值。
    const unsigned short probe = ip_standard_chksum(buf.data(), len);
    if (ip_standard_chksum(buf.data(), len) != probe) {
        state.SkipWithError("ip_standard_chksum is non-deterministic");
        return;
    }

    for (auto _ : state) {
        unsigned short cksum = ip_standard_chksum(buf.data(), len);
        benchmark::DoNotOptimize(cksum);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * len);
    state.counters["buf_B"] = len;
}

BENCHMARK(BM_Checksum)
    ->Arg(64)->Arg(512)->Arg(1400)
    ->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
