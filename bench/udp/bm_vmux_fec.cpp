// bm_vmux_fec —— VMux FEC XOR codec 微基准（header-only）。
// 测量两个方向：
//   - MuxFecEncoder: Reset + Add K 帧 + Build parity 帧
//   - MuxFecRecover: K-1 数据帧 + 1 parity 帧恢复缺失帧
// 帧大小 512 / 1400 字节，K = 4 / 8 / 16。
#include <benchmark/benchmark.h>

#include <ppp/app/mux/MuxFecCodec.h>

#include <cstdint>
#include <cstring>
#include <vector>

using ppp::app::mux::MuxFecEncoder;
using ppp::app::mux::MuxFecFrameView;
using ppp::app::mux::MuxFecRecover;
using ppp::app::mux::ParseMuxFecFrame;

namespace {
// 生成确定性 pattern 的帧缓冲，避免全零让 XOR 退化为无操作。
std::vector<std::uint8_t> make_frame(int length, int seed) {
    std::vector<std::uint8_t> buf(static_cast<size_t>(length));
    for (int i = 0; i < length; ++i) {
        buf[static_cast<size_t>(i)] =
            static_cast<std::uint8_t>((i * 131 + seed * 7) & 0xFF);
    }
    return buf;
}
} // namespace

// ---- Encoder benchmark: Reset + Add K frames + Build ----
static void BM_FecEncode(benchmark::State& state, int K) {
    const int frame_size = static_cast<int>(state.range(0));
    std::vector<std::vector<std::uint8_t>> frames;
    frames.reserve(static_cast<size_t>(K));
    for (int i = 0; i < K; ++i) {
        frames.push_back(make_frame(frame_size, i));
    }

    // Build 输出缓冲：1 + K*8 + 2 + (frame_size+2)
    const int cap = 1 + K * 8 + 2 + frame_size + 2;
    std::vector<std::uint8_t> out(static_cast<size_t>(cap));

    for (auto _ : state) {
        MuxFecEncoder enc;
        enc.Reset(0);
        for (int i = 0; i < K; ++i) {
            enc.Add(static_cast<std::uint32_t>(i + 1), static_cast<std::uint32_t>(i),
                    frames[static_cast<size_t>(i)].data(), frame_size);
        }
        int len = enc.Build(out.data(), cap);
        benchmark::DoNotOptimize(len);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * frame_size * K);
    state.counters["K"] = K;
    state.counters["frame_B"] = frame_size;
}

// ---- Recover benchmark: parse parity + XOR-recover missing frame ----
static void BM_FecRecover(benchmark::State& state, int K) {
    const int frame_size = static_cast<int>(state.range(0));
    std::vector<std::vector<std::uint8_t>> frames;
    frames.reserve(static_cast<size_t>(K));
    for (int i = 0; i < K; ++i) {
        frames.push_back(make_frame(frame_size, i));
    }

    // Build parity once (outside the hot loop — we're measuring recover, not encode).
    MuxFecEncoder enc;
    enc.Reset(0);
    for (int i = 0; i < K; ++i) {
        enc.Add(static_cast<std::uint32_t>(i + 1), static_cast<std::uint32_t>(i),
                frames[static_cast<size_t>(i)].data(), frame_size);
    }
    const int cap = 1 + K * 8 + 2 + frame_size + 2;
    std::vector<std::uint8_t> parity_buf(static_cast<size_t>(cap));
    int parity_len = enc.Build(parity_buf.data(), cap);
    if (parity_len <= 0) {
        state.SkipWithError("FEC build failed");
        return;
    }

    MuxFecFrameView view;
    if (!ParseMuxFecFrame(parity_buf.data(), parity_len, 255, view)) {
        state.SkipWithError("FEC parse failed");
        return;
    }

    // present[] 指向 K-1 帧，missing_index = 0（恢复第一帧）。
    std::vector<const std::uint8_t*> present(static_cast<size_t>(K), nullptr);
    std::vector<int> present_lengths(static_cast<size_t>(K), 0);
    for (int i = 1; i < K; ++i) {
        present[static_cast<size_t>(i)] = frames[static_cast<size_t>(i)].data();
        present_lengths[static_cast<size_t>(i)] = frame_size;
    }

    std::vector<std::uint8_t> recovered(static_cast<size_t>(frame_size));

    for (auto _ : state) {
        int rlen = MuxFecRecover(view, present.data(), present_lengths.data(),
                                 0, recovered.data(), frame_size);
        benchmark::DoNotOptimize(rlen);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * frame_size * K);
    state.counters["K"] = K;
    state.counters["frame_B"] = frame_size;
}

// K=4 / 8 / 16，帧大小 512 / 1400
BENCHMARK_CAPTURE(BM_FecEncode, K4, 4)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_FecEncode, K8, 8)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_FecEncode, K16, 16)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();

BENCHMARK_CAPTURE(BM_FecRecover, K4, 4)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_FecRecover, K8, 8)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();
BENCHMARK_CAPTURE(BM_FecRecover, K16, 16)
    ->Arg(512)->Arg(1400)->Repetitions(10)->UseRealTime();

BENCHMARK_MAIN();
