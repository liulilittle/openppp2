// BM1a —— 底层密码器微基准 / H4 验证台。
// 对比真实 OpenSSL EVP 路径 (aes-*-cfb) 与 AES-NI 路径 (simd-aes-*-cfb)。
#include <benchmark/benchmark.h>

#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/EVP.h>

#include <memory>
#include <vector>
#include <cstring>
#include <wmmintrin.h>

using ppp::Byte;
using ppp::cryptography::Ciphertext;
using ppp::cryptography::EVP;

namespace aesni {
    void aes256_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;
    void aes256_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len,
        const uint8_t* iv, const __m128i* round_key) noexcept;
}

static inline __m128i aes256_encrypt_block_reference(__m128i block, const __m128i* round_key) {
    block = _mm_xor_si128(block, round_key[0]);
    for (int i = 1; i < 14; ++i) block = _mm_aesenc_si128(block, round_key[i]);
    return _mm_aesenclast_si128(block, round_key[14]);
}

// Kept in the benchmark as the pre-optimization one-block-at-a-time oracle.
static void aes256_cfb_decrypt_scalar_reference(uint8_t* plaintext,
    const uint8_t* ciphertext, size_t len, const uint8_t* iv,
    const __m128i* round_key) {
    __m128i feedback = _mm_loadu_si128(reinterpret_cast<const __m128i*>(iv));
    const size_t blocks = len / 16;
    const size_t remaining = len % 16;
    for (size_t i = 0; i < blocks; ++i) {
        const __m128i cipher_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(ciphertext + i * 16));
        const __m128i plain_block = _mm_xor_si128(
            cipher_block, aes256_encrypt_block_reference(feedback, round_key));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(plaintext + i * 16), plain_block);
        feedback = cipher_block;
    }
    if (remaining != 0) {
        const __m128i keystream = aes256_encrypt_block_reference(feedback, round_key);
        for (size_t i = 0; i < remaining; ++i) {
            plaintext[blocks * 16 + i] = ciphertext[blocks * 16 + i] ^
                reinterpret_cast<const uint8_t*>(&keystream)[i];
        }
    }
}

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

static bool simd_decrypt_matches_openssl() {
    auto reference = make_benchmark_cipher("aes-256-cfb");
    auto accelerated = make_benchmark_cipher("simd-aes-256-cfb");
    if (!reference || !accelerated) {
        return false;
    }
    const int lengths[] = {1, 15, 16, 17, 63, 64, 65, 1400, 4096};
    for (int length : lengths) {
        std::vector<Byte> data = make_payload(length);
        int cipher_len = 0;
        std::shared_ptr<Byte> encrypted = reference->Encrypt(nullptr, data.data(), length, cipher_len);
        if (!encrypted || cipher_len != length) {
            return false;
        }
        int plain_len = 0;
        std::shared_ptr<Byte> decrypted = accelerated->Decrypt(nullptr, encrypted.get(), cipher_len, plain_len);
        if (!decrypted || plain_len != length || std::memcmp(decrypted.get(), data.data(), (size_t)length) != 0) {
            return false;
        }
    }
    return true;
}

static bool simd_decrypt_matches_scalar() {
    const uint8_t key[32] = {
        0x31, 0x72, 0x05, 0xa6, 0x48, 0x19, 0xc2, 0x53,
        0x84, 0x25, 0xd6, 0x07, 0x98, 0x39, 0xea, 0x5b,
        0xac, 0x4d, 0xfe, 0x6f, 0x10, 0xb1, 0x62, 0x03,
        0x54, 0xf5, 0x86, 0x27, 0xc8, 0x69, 0x3a, 0xdb};
    const uint8_t iv[16] = {0x8d, 0x3e, 0xaf, 0x50, 0xc1, 0x72, 0x13, 0xa4,
        0x35, 0xd6, 0x47, 0xe8, 0x79, 0x1a, 0xbb, 0x5c};
    const size_t lengths[] = {1, 15, 16, 17, 63, 64, 65, 1400, 4096};
    __m128i round_key[15];
    aesni::aes256_cfb_key_expansion(key, round_key);
    for (size_t length : lengths) {
        std::vector<uint8_t> ciphertext(length);
        for (size_t i = 0; i < length; ++i) ciphertext[i] = static_cast<uint8_t>(i * 73 + 19);
        std::vector<uint8_t> expected(length);
        std::vector<uint8_t> actual(length);
        aes256_cfb_decrypt_scalar_reference(expected.data(), ciphertext.data(), length, iv, round_key);
        aesni::aes256_cfb_decrypt(actual.data(), ciphertext.data(), length, iv, round_key);
        if (actual != expected) return false;
    }
    return true;
}

static void BM_DecryptKernel(benchmark::State& state, bool use_simd) {
    if (!simd_decrypt_matches_scalar()) {
        state.SkipWithError("SIMD CFB decrypt differs from scalar reference");
        return;
    }
    const uint8_t key[32] = {
        0x31, 0x72, 0x05, 0xa6, 0x48, 0x19, 0xc2, 0x53,
        0x84, 0x25, 0xd6, 0x07, 0x98, 0x39, 0xea, 0x5b,
        0xac, 0x4d, 0xfe, 0x6f, 0x10, 0xb1, 0x62, 0x03,
        0x54, 0xf5, 0x86, 0x27, 0xc8, 0x69, 0x3a, 0xdb};
    const uint8_t iv[16] = {0x8d, 0x3e, 0xaf, 0x50, 0xc1, 0x72, 0x13, 0xa4,
        0x35, 0xd6, 0x47, 0xe8, 0x79, 0x1a, 0xbb, 0x5c};
    __m128i round_key[15];
    aesni::aes256_cfb_key_expansion(key, round_key);
    const size_t length = static_cast<size_t>(state.range(0));
    std::vector<uint8_t> ciphertext(length), plaintext(length);
    for (size_t i = 0; i < length; ++i) ciphertext[i] = static_cast<uint8_t>(i * 73 + 19);
    for (auto _ : state) {
        if (use_simd) {
            aesni::aes256_cfb_decrypt(plaintext.data(), ciphertext.data(), length, iv, round_key);
        } else {
            aes256_cfb_decrypt_scalar_reference(plaintext.data(), ciphertext.data(), length, iv, round_key);
        }
        benchmark::DoNotOptimize(plaintext.data());
        benchmark::ClobberMemory();
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(length));
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

static void BM_Decrypt(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported (simd-* needs __SIMD__ + AES-NI)");
        return;
    }
    if (!roundtrip_ok(method) || (std::strcmp(method, "simd-aes-256-cfb") == 0 &&
        (!simd_decrypt_matches_openssl() || !simd_decrypt_matches_scalar()))) {
        state.SkipWithError("decrypt compatibility self-check failed");
        return;
    }

    auto c = make_benchmark_cipher(method);
    auto reference = make_benchmark_cipher("aes-256-cfb");
    const int datalen = (int)state.range(0);
    std::vector<Byte> plain = make_payload(datalen);
    int cipher_len = 0;
    std::shared_ptr<Byte> encrypted = reference->Encrypt(nullptr, plain.data(), datalen, cipher_len);
    if (!encrypted || cipher_len != datalen) {
        state.SkipWithError("could not prepare AES-256-CFB ciphertext");
        return;
    }

    for (auto _ : state) {
        int outlen = 0;
        std::shared_ptr<Byte> out = c->Decrypt(nullptr, encrypted.get(), cipher_len, outlen);
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

#define REGISTER_DECRYPT(name, method)                                    \
    BENCHMARK_CAPTURE(BM_Decrypt, name, method)                            \
        ->Arg(64)->Arg(512)->Arg(1400)                                     \
        ->Repetitions(15)->UseRealTime()

REGISTER_DECRYPT(aes256cfb_openssl, "aes-256-cfb");
REGISTER_DECRYPT(aes256cfb_simd, "simd-aes-256-cfb");

BENCHMARK_CAPTURE(BM_DecryptKernel, scalar, false)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->UseRealTime();
BENCHMARK_CAPTURE(BM_DecryptKernel, simd4, true)->Arg(64)->Arg(512)->Arg(1400)->Arg(4096)->UseRealTime();

#undef REGISTER
#undef REGISTER_DECRYPT

BENCHMARK_MAIN();
