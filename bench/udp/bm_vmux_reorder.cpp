// bm_vmux_reorder —— VMux Flow Reorder Buffer 微基准（header-only）。
// MuxFlowReorderBuffer<T> 是模板类，按 sequence 排序存储，支持 TryInsert / Take。
// 测量不同乱序率下插入 1000 帧并依次 Take 出来的吞吐：
//   0%  乱序：顺序插入 seq=1,2,...,1000
//  10% 乱序：随机交换约 10% 的序列号
//  50% 乱序：随机打乱约 50% 的序列号
#include <benchmark/benchmark.h>

#include <ppp/app/mux/MuxFlowReorderBuffer.h>

#include <algorithm>
#include <cstdint>
#include <vector>

using ppp::app::mux::MuxFlowReorderBuffer;

namespace {
// 简单确定性 PRNG
inline uint32_t xorshift32(uint32_t& state) noexcept {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// 生成 1000 个序列号，disorder_pct 控制乱序比例。
// 基准序列 1..1000，然后随机交换 disorder_pct% 的位置。
std::vector<std::uint32_t> make_sequence_order(int count, int disorder_pct, uint32_t seed) {
    std::vector<std::uint32_t> seqs;
    seqs.reserve(static_cast<size_t>(count));
    for (int i = 1; i <= count; ++i) {
        seqs.push_back(static_cast<std::uint32_t>(i));
    }
    uint32_t state = seed;
    int swaps = count * disorder_pct / 100;
    for (int s = 0; s < swaps; ++s) {
        int i = static_cast<int>(xorshift32(state) % static_cast<uint32_t>(count));
        int j = static_cast<int>(xorshift32(state) % static_cast<uint32_t>(count));
        std::swap(seqs[static_cast<size_t>(i)], seqs[static_cast<size_t>(j)]);
    }
    return seqs;
}
} // namespace

// 用 int 作为模板参数 T，value=42，bytes=4。
static void BM_Reorder(benchmark::State& state, int disorder_pct) {
    const int count = 1000;
    std::vector<std::uint32_t> seqs =
        make_sequence_order(count, disorder_pct, 0xC0FFEE);

    const std::size_t byte_cap = static_cast<std::size_t>(count) * 16;
    const std::size_t entry_cap = static_cast<std::size_t>(count) + 10;

    for (auto _ : state) {
        MuxFlowReorderBuffer<int> buf;
        for (int i = 0; i < count; ++i) {
            buf.TryInsert(seqs[static_cast<size_t>(i)], 0, 42, 4, byte_cap, entry_cap);
        }

        // 顺序 Take：reference=0 → 取 seq=1,2,...,1000
        int val = 0;
        for (std::uint32_t s = 1; s <= static_cast<std::uint32_t>(count); ++s) {
            buf.Take(s, val);
        }
        benchmark::DoNotOptimize(val);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations() * count);
    state.counters["disorder_%"] = disorder_pct;
}

BENCHMARK_CAPTURE(BM_Reorder, pct0, 0)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_Reorder, pct10, 10)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_Reorder, pct50, 50)->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
