// bm_vmux_rtx —— VMux Retransmit Buffer 微基准（header-only）。
// 测量三个操作：
//   - Track(): 插入 N 帧（shared_ptr 缓冲区）
//   - Ack(): 对覆盖全部 N 帧的范围做 ACK 释放
//   - CollectExpired(): 扫描过期帧
// N = 100 / 500 / 2000。
#include <benchmark/benchmark.h>

#include <ppp/app/mux/MuxRetransmitBuffer.h>

#include <cstdint>
#include <memory>
#include <vector>

using ppp::app::mux::MuxAckRange;
using ppp::app::mux::MuxRetransmitBuffer;

namespace {
// 分配一个 small frame shared_ptr，内容填充确定性 pattern。
std::shared_ptr<std::uint8_t> make_frame_buffer(int length, int seed) {
    auto p = std::shared_ptr<std::uint8_t>(
        new std::uint8_t[static_cast<size_t>(length)],
        std::default_delete<std::uint8_t[]>());
    for (int i = 0; i < length; ++i) {
        p.get()[static_cast<size_t>(i)] =
            static_cast<std::uint8_t>((i * 131 + seed * 7) & 0xFF);
    }
    return p;
}
} // namespace

static void BM_RtxTrack(benchmark::State& state) {
    const int n = static_cast<int>(state.range(0));
    const int frame_size = 64;
    const std::size_t byte_cap = static_cast<std::size_t>(n) * static_cast<std::size_t>(frame_size) * 2;

    // 预分配帧缓冲，热循环只测 Track 本身
    std::vector<std::shared_ptr<std::uint8_t>> bufs;
    bufs.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        bufs.push_back(make_frame_buffer(frame_size, i));
    }

    for (auto _ : state) {
        MuxRetransmitBuffer rtx;
        for (int i = 0; i < n; ++i) {
            rtx.Track(0, static_cast<std::uint32_t>(i), bufs[static_cast<size_t>(i)],
                      frame_size, 0, byte_cap);
        }
        benchmark::DoNotOptimize(rtx.size());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["frames"] = n;
}

static void BM_RtxAck(benchmark::State& state) {
    const int n = static_cast<int>(state.range(0));
    const int frame_size = 64;
    const std::size_t byte_cap = static_cast<std::size_t>(n) * static_cast<std::size_t>(frame_size) * 2;

    std::vector<std::shared_ptr<std::uint8_t>> bufs;
    bufs.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        bufs.push_back(make_frame_buffer(frame_size, i));
    }

    // ACK 范围 [0, n-1] 覆盖全部帧
    MuxAckRange range;
    range.start = 0;
    range.end = static_cast<std::uint32_t>(n - 1);
    std::vector<MuxAckRange> ranges = { range };

    for (auto _ : state) {
        // 每轮重新 Track 全部帧（Ack 后 buffer 清空）
        MuxRetransmitBuffer rtx;
        for (int i = 0; i < n; ++i) {
            rtx.Track(0, static_cast<std::uint32_t>(i), bufs[static_cast<size_t>(i)],
                      frame_size, 0, byte_cap);
        }
        std::vector<std::uint64_t> fast_candidates;
        std::uint64_t rtt = rtx.Ack(0, static_cast<std::uint32_t>(n - 1), ranges,
                                    1000, 3, 0, fast_candidates);
        benchmark::DoNotOptimize(rtt);
        benchmark::DoNotOptimize(rtx.size());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["frames"] = n;
}

static void BM_RtxCollectExpired(benchmark::State& state) {
    const int n = static_cast<int>(state.range(0));
    const int frame_size = 64;
    const std::size_t byte_cap = static_cast<std::size_t>(n) * static_cast<std::size_t>(frame_size) * 2;

    std::vector<std::shared_ptr<std::uint8_t>> bufs;
    bufs.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        bufs.push_back(make_frame_buffer(frame_size, i));
    }

    // 预填充一次：所有帧在 tick=0 发送，now=10000，pto=5000 → 全部过期
    MuxRetransmitBuffer rtx;
    for (int i = 0; i < n; ++i) {
        rtx.Track(0, static_cast<std::uint32_t>(i), bufs[static_cast<size_t>(i)],
                  frame_size, 0, byte_cap);
    }

    std::vector<std::uint64_t> expired;

    for (auto _ : state) {
        expired.clear();
        rtx.CollectExpired(10000, 5000, 60000, static_cast<std::size_t>(n), expired);
        benchmark::DoNotOptimize(expired.size());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["frames"] = n;
}

BENCHMARK(BM_RtxTrack)->Arg(100)->Arg(500)->Arg(2000)->Repetitions(10)->UseRealTime();
BENCHMARK(BM_RtxAck)->Arg(100)->Arg(500)->Arg(2000)->Repetitions(10)->UseRealTime();
BENCHMARK(BM_RtxCollectExpired)->Arg(100)->Arg(500)->Arg(2000)->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
