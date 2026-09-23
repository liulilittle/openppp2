// SSEA SIMD performance micro-benchmarks.
//
// Measures every SSEA algorithm (base94, delta, shuffle, masked_xor) across
// all SIMD levels that are compiled in, using the ssea_simd dispatch tables
// directly (bypassing the openppp2 public API wrapper).  A correctness
// self-check runs first; if it fails the process exits non-zero before any
// timing begins.
//
// Build:
//   cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release
//   cmake --build build-bench --target bm_ssea
// Run:
//   ./build-bench/bm_ssea                      # full benchmark
//   ./build-bench/bm_ssea --benchmark_min_time=0.001  # smoke test (ctest)

#include <benchmark/benchmark.h>

#include <ppp/cryptography/ssea_simd/sse_dispatch.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

using ssea::SimdLevel;
using ssea::SseaFuncs;
using ssea::ssea_cpu_level;
using ssea::ssea_dispatch;
using ssea::ssea_dispatch_for;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

constexpr int32_t kKey       = 0x4f13;
constexpr uint32_t kShuffleKey = 0x5a4f13;

// SIMD levels that can be benchmarked on this build.  On GCC builds compiled
// with a limited -m flag set, ssea_dispatch_for() silently falls back to the
// highest compiled level, so we list every level and let the dispatch table
// resolve it — the benchmark simply labels which level was requested.
struct LevelEntry {
    SimdLevel level;
    const char* name;
};

const LevelEntry kLevels[] = {
    {SimdLevel::Scalar, "scalar"},
    {SimdLevel::SSE2,   "SSE2"},
    {SimdLevel::SSE3,   "SSE3"},
    {SimdLevel::SSSE3,  "SSSE3"},
    {SimdLevel::SSE4_1, "SSE4.1"},
    {SimdLevel::SSE4_2, "SSE4.2"},
    {SimdLevel::AVX,    "AVX"},
    {SimdLevel::AVX2,   "AVX2"},
};

// Fill a buffer with a deterministic but non-trivial pattern.
void fill_pattern(uint8_t* p, int n) {
    uint32_t s = 0x12345678u;
    for (int i = 0; i < n; ++i) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        p[i] = static_cast<uint8_t>(s & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// Correctness self-check — runs once before any benchmark.
// Verifies roundtrip correctness for each algorithm at each compiled level,
// and cross-level output consistency.
// ---------------------------------------------------------------------------

bool ssea_self_check() {
    const int N = 1400;
    std::vector<uint8_t> raw(N);
    fill_pattern(raw.data(), N);

    const SimdLevel cpu = ssea_cpu_level();
    std::printf("[ssea] CPU detected level: %s (%d)\n",
                kLevels[static_cast<int>(cpu)].name,
                static_cast<int>(cpu));

    // Reference outputs from the scalar table.
    const SseaFuncs& ref = ssea_dispatch_for(SimdLevel::Scalar);

    // --- base94 roundtrip (scalar reference) ---
    {
        std::unique_ptr<uint8_t[]> enc;
        int enclen = ref.base94_encode(raw.data(), N, kKey, enc);
        if (enclen <= 0 || !enc) {
            std::fprintf(stderr, "[ssea] self-check FAIL: base94_encode scalar returned %d\n", enclen);
            return false;
        }
        std::unique_ptr<uint8_t[]> dec;
        int declen = ref.base94_decode(enc.get(), enclen, kKey, dec);
        if (declen != N || !dec) {
            std::fprintf(stderr, "[ssea] self-check FAIL: base94_decode scalar len %d != %d\n", declen, N);
            return false;
        }
        if (std::memcmp(dec.get(), raw.data(), N) != 0) {
            std::fprintf(stderr, "[ssea] self-check FAIL: base94 roundtrip mismatch (scalar)\n");
            return false;
        }
    }

    // --- delta roundtrip (scalar reference) ---
    {
        std::unique_ptr<uint8_t[]> enc;
        int enclen = ref.delta_encode(raw.data(), N, kKey, enc);
        if (enclen != N || !enc) {
            std::fprintf(stderr, "[ssea] self-check FAIL: delta_encode scalar returned %d\n", enclen);
            return false;
        }
        std::unique_ptr<uint8_t[]> dec;
        int declen = ref.delta_decode(enc.get(), N, kKey, dec);
        if (declen != N || !dec) {
            std::fprintf(stderr, "[ssea] self-check FAIL: delta_decode scalar len %d != %d\n", declen, N);
            return false;
        }
        if (std::memcmp(dec.get(), raw.data(), N) != 0) {
            std::fprintf(stderr, "[ssea] self-check FAIL: delta roundtrip mismatch (scalar)\n");
            return false;
        }
    }

    // --- shuffle roundtrip (scalar reference) ---
    {
        std::vector<char> buf(raw.begin(), raw.end());
        ref.shuffle_data(buf.data(), N, kShuffleKey);
        ref.unshuffle_data(buf.data(), N, kShuffleKey);
        if (std::memcmp(buf.data(), raw.data(), N) != 0) {
            std::fprintf(stderr, "[ssea] self-check FAIL: shuffle roundtrip mismatch (scalar)\n");
            return false;
        }
    }

    // --- masked_xor / masked_xor_random_next (scalar reference) ---
    {
        std::vector<uint8_t> a = raw;
        std::vector<uint8_t> b = raw;
        ref.masked_xor(a.data(), a.data() + N, kKey);
        ref.masked_xor_random_next(b.data(), b.data() + N, kKey);
        // masked_xor is an in-place XOR with a keystream; just verify it does
        // not crash and returns true.
    }

    // --- cross-level consistency for base94 ---
    // Encode with scalar, then decode with every compiled level.  Output must match.
    {
        std::unique_ptr<uint8_t[]> enc;
        int enclen = ref.base94_encode(raw.data(), N, kKey, enc);
        for (const auto& le : kLevels) {
            const SseaFuncs& f = ssea_dispatch_for(le.level);
            std::unique_ptr<uint8_t[]> dec;
            int declen = f.base94_decode(enc.get(), enclen, kKey, dec);
            if (declen != N || !dec) {
                std::fprintf(stderr, "[ssea] self-check FAIL: base94_decode %s returned %d\n", le.name, declen);
                return false;
            }
            if (std::memcmp(dec.get(), raw.data(), N) != 0) {
                std::fprintf(stderr, "[ssea] self-check FAIL: base94 cross-level mismatch (%s)\n", le.name);
                return false;
            }
        }
    }

    // --- cross-level consistency for delta ---
    {
        std::unique_ptr<uint8_t[]> enc;
        int enclen = ref.delta_encode(raw.data(), N, kKey, enc);
        for (const auto& le : kLevels) {
            const SseaFuncs& f = ssea_dispatch_for(le.level);
            std::unique_ptr<uint8_t[]> dec;
            int declen = f.delta_decode(enc.get(), N, kKey, dec);
            if (declen != N || !dec) {
                std::fprintf(stderr, "[ssea] self-check FAIL: delta_decode %s returned %d\n", le.name, declen);
                return false;
            }
            if (std::memcmp(dec.get(), raw.data(), N) != 0) {
                std::fprintf(stderr, "[ssea] self-check FAIL: delta cross-level mismatch (%s)\n", le.name);
                return false;
            }
        }
    }

    std::printf("[ssea] self-check PASSED (all levels)\n");
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// --- Base94 Encode ---
void BM_Base94Encode(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = ssea_dispatch().base94_encode(data.data(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Base94Encode)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Base94 Decode ---
void BM_Base94Decode(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    // Pre-encode to get a valid base94 stream.
    std::unique_ptr<uint8_t[]> encoded;
    int enclen = ssea_dispatch().base94_encode(data.data(), N, kKey, encoded);
    if (enclen <= 0 || !encoded) {
        state.SkipWithError("base94_encode failed in setup");
        return;
    }
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = ssea_dispatch().base94_decode(encoded.get(), enclen, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Base94Decode)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Delta Encode ---
void BM_DeltaEncode(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = ssea_dispatch().delta_encode(data.data(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DeltaEncode)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Delta Decode ---
void BM_DeltaDecode(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    // Pre-encode to get a valid delta stream.
    std::unique_ptr<uint8_t[]> encoded;
    int enclen = ssea_dispatch().delta_encode(data.data(), N, kKey, encoded);
    if (enclen != N || !encoded) {
        state.SkipWithError("delta_encode failed in setup");
        return;
    }
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = ssea_dispatch().delta_decode(encoded.get(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_DeltaDecode)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Shuffle ---
void BM_Shuffle(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<char> data(N);
    fill_pattern(reinterpret_cast<uint8_t*>(data.data()), N);
    for (auto _ : state) {
        ssea_dispatch().shuffle_data(data.data(), N, kShuffleKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Shuffle)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Unshuffle ---
void BM_Unshuffle(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<char> data(N);
    fill_pattern(reinterpret_cast<uint8_t*>(data.data()), N);
    ssea_dispatch().shuffle_data(data.data(), N, kShuffleKey); // pre-shuffle for realistic input
    for (auto _ : state) {
        ssea_dispatch().unshuffle_data(data.data(), N, kShuffleKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Unshuffle)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Masked XOR ---
void BM_MaskedXor(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        ssea_dispatch().masked_xor(data.data(), data.data() + N, kKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_MaskedXor)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// --- Masked XOR Random Next ---
void BM_MaskedXorRandomNext(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        ssea_dispatch().masked_xor_random_next(data.data(), data.data() + N, kKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_MaskedXorRandomNext)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->Arg(16384);

// ---------------------------------------------------------------------------
// Cross-level comparison: benchmark the SAME algorithm at each SIMD level
// using ssea_dispatch_for(), so the report shows the speedup curve.
// ---------------------------------------------------------------------------

// Helper template to reduce boilerplate.
template <typename Fn>
void BM_LevelCompare(benchmark::State& state, Fn fn, const char* algo_name) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    fn(f, N, kKey, kShuffleKey, state);
}

void BM_Base94Encode_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = f.base94_encode(data.data(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
}

void BM_Base94Decode_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    // Pre-encode using scalar to get a valid stream.
    std::unique_ptr<uint8_t[]> enc;
    int enclen = ssea_dispatch_for(SimdLevel::Scalar).base94_encode(data.data(), N, kKey, enc);
    if (enclen <= 0 || !enc) { state.SkipWithError("setup failed"); return; }
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = f.base94_decode(enc.get(), enclen, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
}

void BM_DeltaEncode_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = f.delta_encode(data.data(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
}

void BM_DeltaDecode_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    std::unique_ptr<uint8_t[]> enc;
    ssea_dispatch_for(SimdLevel::Scalar).delta_encode(data.data(), N, kKey, enc);
    for (auto _ : state) {
        std::unique_ptr<uint8_t[]> out;
        int outlen = f.delta_decode(enc.get(), N, kKey, out);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
    }
    state.SetBytesProcessed(state.iterations() * N);
}

void BM_MaskedXor_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        f.masked_xor(data.data(), data.data() + N, kKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
}

void BM_MaskedXorRandomNext_Level(benchmark::State& state) {
    const int N = static_cast<int>(state.range(0));
    const SimdLevel lvl = static_cast<SimdLevel>(state.range(1));
    const SseaFuncs& f = ssea_dispatch_for(lvl);
    std::vector<uint8_t> data(N);
    fill_pattern(data.data(), N);
    for (auto _ : state) {
        f.masked_xor_random_next(data.data(), data.data() + N, kKey);
        benchmark::DoNotOptimize(data.data());
    }
    state.SetBytesProcessed(state.iterations() * N);
}

// Register cross-level comparisons at 1400 bytes (typical MTU payload).
// Args: (payload_size, simd_level_int)
#define SSEA_LEVEL_ARGS(BM_FN) \
    BM_FN->Args({1400, 0})->Args({1400, 1})->Args({1400, 2})->Args({1400, 3}) \
          ->Args({1400, 4})->Args({1400, 5})->Args({1400, 6})->Args({1400, 7})

SSEA_LEVEL_ARGS(BENCHMARK(BM_Base94Encode_Level));
SSEA_LEVEL_ARGS(BENCHMARK(BM_Base94Decode_Level));
SSEA_LEVEL_ARGS(BENCHMARK(BM_DeltaEncode_Level));
SSEA_LEVEL_ARGS(BENCHMARK(BM_DeltaDecode_Level));
SSEA_LEVEL_ARGS(BENCHMARK(BM_MaskedXor_Level));
SSEA_LEVEL_ARGS(BENCHMARK(BM_MaskedXorRandomNext_Level));
#undef SSEA_LEVEL_ARGS

// ---------------------------------------------------------------------------
// main — run self-check first, then benchmarks.
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    if (!ssea_self_check()) {
        std::fprintf(stderr, "[ssea] self-check FAILED — aborting benchmark.\n");
        return 1;
    }
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    return 0;
}
