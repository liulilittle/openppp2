// bm_vmux_ack —— VMux ACK Tracker 微基准（header-only）。
// 测量三个操作：
//   - Add(): 按 N 个 range 的间隔插入序列号
//   - EncodeMuxAckFrame(): 将 ACK 块序列化为 wire format
//   - DecodeMuxAckFrame(): 解析 wire format 回来
// N = 1 / 8 / 32 个 range。
#include <benchmark/benchmark.h>

#include <ppp/app/mux/MuxAckTracker.h>

#include <cstdint>
#include <vector>

using ppp::app::mux::DecodeMuxAckFrame;
using ppp::app::mux::EncodeMuxAckFrame;
using ppp::app::mux::MuxAckBlock;
using ppp::app::mux::MuxAckRange;
using ppp::app::mux::MuxAckTracker;

namespace {
// 生成 N 个不连续的 range，每个 range 宽 5（包含 5 个连续 seq），中间间隔 3。
// 例如 N=2: [0..4], [8..12]
// 这样 Add 每个序列号后 tracker 最终有 N 个 range。
std::vector<std::uint32_t> make_sequences(int n_ranges) {
    std::vector<std::uint32_t> seqs;
    std::uint32_t base = 0;
    for (int r = 0; r < n_ranges; ++r) {
        for (int i = 0; i < 5; ++i) {
            seqs.push_back(base + static_cast<std::uint32_t>(i));
        }
        base += 8; // 5 consecutive + 3 gap
    }
    return seqs;
}
} // namespace

static void BM_AckAdd(benchmark::State& state) {
    const int n_ranges = static_cast<int>(state.range(0));
    std::vector<std::uint32_t> seqs = make_sequences(n_ranges);

    for (auto _ : state) {
        MuxAckTracker tracker;
        for (std::uint32_t s : seqs) {
            tracker.Add(s, 256);
        }
        benchmark::DoNotOptimize(tracker.largest());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["ranges"] = n_ranges;
}

static void BM_AckEncode(benchmark::State& state) {
    const int n_ranges = static_cast<int>(state.range(0));
    std::vector<std::uint32_t> seqs = make_sequences(n_ranges);

    // 预填充 tracker → 提取 block
    MuxAckTracker tracker;
    for (std::uint32_t s : seqs) {
        tracker.Add(s, 256);
    }
    MuxAckBlock block;
    block.connection_id = 0;
    block.largest = tracker.largest();
    block.ranges = tracker.ranges();

    const std::size_t cap = 1 + 9 + block.ranges.size() * 8 + 64;
    std::vector<std::uint8_t> out(cap);

    for (auto _ : state) {
        std::size_t len = EncodeMuxAckFrame(&block, 1, out.data(), cap, 256);
        benchmark::DoNotOptimize(len);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["ranges"] = n_ranges;
}

static void BM_AckDecode(benchmark::State& state) {
    const int n_ranges = static_cast<int>(state.range(0));
    std::vector<std::uint32_t> seqs = make_sequences(n_ranges);

    // 预填充 tracker → 编码为 wire bytes（热循环只测 decode）
    MuxAckTracker tracker;
    for (std::uint32_t s : seqs) {
        tracker.Add(s, 256);
    }
    MuxAckBlock block;
    block.connection_id = 0;
    block.largest = tracker.largest();
    block.ranges = tracker.ranges();

    const std::size_t cap = 1 + 9 + block.ranges.size() * 8 + 64;
    std::vector<std::uint8_t> out(cap);
    std::size_t wire_len = EncodeMuxAckFrame(&block, 1, out.data(), cap, 256);
    if (wire_len == 0) {
        state.SkipWithError("encode failed");
        return;
    }

    std::vector<MuxAckBlock> decoded;

    for (auto _ : state) {
        bool ok = DecodeMuxAckFrame(out.data(), wire_len, 64, 256, decoded);
        benchmark::DoNotOptimize(ok);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["ranges"] = n_ranges;
}

BENCHMARK(BM_AckAdd)->Arg(1)->Arg(8)->Arg(32)->Repetitions(10)->UseRealTime();
BENCHMARK(BM_AckEncode)->Arg(1)->Arg(8)->Arg(32)->Repetitions(10)->UseRealTime();
BENCHMARK(BM_AckDecode)->Arg(1)->Arg(8)->Arg(32)->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
