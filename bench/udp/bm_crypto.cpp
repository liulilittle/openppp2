// BM1a —— 底层密码器微基准 / H4 验证台。
// 对比真实 OpenSSL EVP 路径 (aes-*-cfb) 与 AES-NI 路径 (simd-aes-*-cfb)。
#include <benchmark/benchmark.h>

#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/EVP.h>

#include <memory>
#include <vector>
#include <cstring>

using ppp::Byte;
using ppp::cryptography::Ciphertext;
using ppp::cryptography::EVP;

static std::vector<Byte> make_payload(int n) {
    std::vector<Byte> v((size_t)n);
    for (int i = 0; i < n; ++i) {
        v[(size_t)i] = (Byte)((i * 131 + 7) & 0xFF);
    }
    return v;
}

static std::shared_ptr<Ciphertext> make_benchmark_cipher(const char* method) {
    // method 本身决定后端。普通 aes-* 必须保持 OpenSSL，显式 simd-aes-* 走 AES-NI。
    EVP::SetSimdAuto(false);
    auto cipher = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("bench-pw"));
    EVP::SetSimdAuto(true);
    return cipher;
}

static bool roundtrip_ok(const char* method) {
    auto c = make_benchmark_cipher(method);
    std::vector<Byte> data = make_payload(256);

    int enclen = 0;
    std::shared_ptr<Byte> enc = c->Encrypt(nullptr, data.data(), (int)data.size(), enclen);
    if (!enc || enclen <= 0) {
        return false;
    }

    int declen = 0;
    std::shared_ptr<Byte> dec = c->Decrypt(nullptr, enc.get(), enclen, declen);
    if (!dec || declen != (int)data.size()) {
        return false;
    }
    return std::memcmp(dec.get(), data.data(), data.size()) == 0;
}

static void BM_Encrypt(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported (simd-* needs __SIMD__ + AES-NI)");
        return;
    }
    if (!roundtrip_ok(method)) {
        state.SkipWithError("self-check roundtrip failed");
        return;
    }

    auto c = make_benchmark_cipher(method);
    const int datalen = (int)state.range(0);
    std::vector<Byte> data = make_payload(datalen);

    for (auto _ : state) {
        int outlen = 0;
        std::shared_ptr<Byte> out = c->Encrypt(nullptr, data.data(), datalen, outlen);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed((int64_t)state.iterations() * datalen);
    state.counters["payload_B"] = datalen;
    state.counters["allocations"] = 1;
}

// 保留每次 repetition 原始样本，供 compare.py 做 bootstrap CI。
#define REGISTER(name, method)                                            \
    BENCHMARK_CAPTURE(BM_Encrypt, name, method)                           \
        ->Arg(64)->Arg(512)->Arg(1400)                                    \
        ->Repetitions(15)->UseRealTime()

REGISTER(aes128cfb_openssl, "aes-128-cfb");
REGISTER(aes128cfb_simd,    "simd-aes-128-cfb");
REGISTER(aes256cfb_openssl, "aes-256-cfb");
REGISTER(aes256cfb_simd,    "simd-aes-256-cfb");

#undef REGISTER

BENCHMARK_MAIN();
