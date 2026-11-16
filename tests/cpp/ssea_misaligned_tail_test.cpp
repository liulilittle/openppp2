#define BOOST_TEST_MODULE ssea_misaligned_tail_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/ssea_simd/ssea_scalar_ref.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#endif

using XorFn = bool (*)(const void*, const void*, int32_t) noexcept;
using GoldenFn = void (*)(uint8_t*, int, int32_t) noexcept;

bool ssea_test_sse2_compiled() noexcept;
bool ssea_test_sse3_compiled() noexcept;
bool ssea_test_avx2_compiled() noexcept;
bool ssea_test_masked_xor_sse(const void*, const void*, int32_t) noexcept;
bool ssea_test_masked_xor_sse3(const void*, const void*, int32_t) noexcept;
bool ssea_test_masked_xor_avx2(const void*, const void*, int32_t) noexcept;
bool ssea_test_masked_xor_random_next_sse(const void*, const void*, int32_t) noexcept;
bool ssea_test_masked_xor_random_next_sse3(const void*, const void*, int32_t) noexcept;
bool ssea_test_masked_xor_random_next_avx2(const void*, const void*, int32_t) noexcept;

namespace {

constexpr int kPrefix = 16;
constexpr int kMaxOffset = 15;
constexpr int kMaxLength = 67;
constexpr std::size_t kBufferSize = kPrefix + kMaxOffset + kMaxLength + 16;
constexpr int32_t kFixedKey = 0x5A17C3D1;
constexpr int32_t kRandomKey = 0x13579BDF;

struct CpuSupport {
    bool sse2 = false;
    bool sse3 = false;
    bool avx2 = false;
};

CpuSupport DetectCpuSupport() noexcept {
    CpuSupport support;
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    int regs[4] = {};
    __cpuid(regs, 1);
    support.sse2 = 0 != (regs[3] & (1 << 26));
    support.sse3 = 0 != (regs[2] & 1);
    const bool osxsave = 0 != (regs[2] & (1 << 27));
    const bool avx = 0 != (regs[2] & (1 << 28));
    const bool ymm_enabled = osxsave && avx && ((_xgetbv(0) & 0x6) == 0x6);
    __cpuidex(regs, 7, 0);
    support.avx2 = ymm_enabled && 0 != (regs[1] & (1 << 5));
#elif (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__x86_64__) || defined(__i386__))
    __builtin_cpu_init();
    support.sse2 = 0 != __builtin_cpu_supports("sse2");
    support.sse3 = 0 != __builtin_cpu_supports("sse3");
    support.avx2 = 0 != __builtin_cpu_supports("avx2");
#endif
    return support;
}

struct Digest {
    uint64_t value = UINT64_C(14695981039346656037);

    void Add(uint8_t byte) noexcept {
        value ^= byte;
        value *= UINT64_C(1099511628211);
    }

    void AddCase(int offset, int length, const std::array<uint8_t, kBufferSize>& bytes) noexcept {
        Add(static_cast<uint8_t>(offset));
        Add(static_cast<uint8_t>(length));
        for (uint8_t byte : bytes) {
            Add(byte);
        }
    }
};

std::array<uint8_t, kBufferSize> MakeInput() noexcept {
    std::array<uint8_t, kBufferSize> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(i * 37 + 0x5B);
    }
    return bytes;
}

void GoldenFixed(uint8_t* data, int length, int32_t key) noexcept {
    int offset = 0;
    while (offset + 4 <= length) {
        int32_t word;
        std::memcpy(&word, data + offset, sizeof(word));
        word ^= key;
        std::memcpy(data + offset, &word, sizeof(word));
        offset += 4;
    }
    if (offset + 2 <= length) {
        int16_t half;
        std::memcpy(&half, data + offset, sizeof(half));
        half = static_cast<int16_t>(half ^ key);
        std::memcpy(data + offset, &half, sizeof(half));
        offset += 2;
    }
    if (offset < length) {
        data[offset] = static_cast<uint8_t>(data[offset] ^ key);
    }
}

void GoldenRandomNext(uint8_t* data, int length, int32_t key) noexcept {
    unsigned int seed = static_cast<unsigned int>(key);
    key = ssea::random_next_scalar(&seed);
    int offset = 0;
    while (offset + 4 <= length) {
        int32_t word;
        std::memcpy(&word, data + offset, sizeof(word));
        word ^= key;
        std::memcpy(data + offset, &word, sizeof(word));
        offset += 4;
        seed = static_cast<unsigned int>(key);
        key = ssea::random_next_scalar(&seed);
    }
    if (offset + 2 <= length) {
        int16_t half;
        std::memcpy(&half, data + offset, sizeof(half));
        half = static_cast<int16_t>(half ^ key);
        std::memcpy(data + offset, &half, sizeof(half));
        offset += 2;
    }
    if (offset < length) {
        data[offset] = static_cast<uint8_t>(data[offset] ^ key);
    }
}

template <typename ReferenceFn>
uint64_t CheckOperation(const char* name, int32_t key, GoldenFn golden_fn,
                        ReferenceFn reference_fn, const std::vector<XorFn>& variants,
                        uint64_t expected_digest) {
    Digest golden_digest;
    for (int offset = 0; offset <= kMaxOffset; ++offset) {
        for (int length = 0; length <= kMaxLength; ++length) {
            auto golden = MakeInput();
            auto reference = golden;
            const std::size_t start = static_cast<std::size_t>(kPrefix + offset);
            golden_fn(golden.data() + start, length, key);
            BOOST_REQUIRE_MESSAGE(
                reference_fn(reference.data() + start, reference.data() + start + length, key),
                name << " scalar reference rejected offset=" << offset << " length=" << length);
            BOOST_CHECK_MESSAGE(golden == reference,
                name << " scalar reference differs from pre-fix behavior at offset="
                     << offset << " length=" << length);
            golden_digest.AddCase(offset, length, golden);
        }
    }

    std::ostringstream digest_text;
    digest_text << std::hex << std::setw(16) << std::setfill('0') << golden_digest.value;
    BOOST_CHECK_MESSAGE(golden_digest.value == expected_digest,
        name << " pre-fix golden digest changed: " << digest_text.str());

    for (std::size_t variant_index = 0; variant_index < variants.size(); ++variant_index) {
        const XorFn variant = variants[variant_index];
        Digest variant_digest;
        for (int offset = 0; offset <= kMaxOffset; ++offset) {
            for (int length = 0; length <= kMaxLength; ++length) {
                auto expected = MakeInput();
                auto actual = expected;
                const std::size_t start = static_cast<std::size_t>(kPrefix + offset);
                golden_fn(expected.data() + start, length, key);
                BOOST_REQUIRE_MESSAGE(
                    variant(actual.data() + start, actual.data() + start + length, key),
                    name << " SIMD implementation rejected offset=" << offset
                         << " length=" << length);
                BOOST_CHECK_MESSAGE(actual == expected,
                    name << " SIMD implementation " << variant_index
                         << " differs from golden output at offset=" << offset
                         << " length=" << length);
                variant_digest.AddCase(offset, length, actual);
            }
        }
        BOOST_CHECK_MESSAGE(variant_digest.value == expected_digest,
            name << " SIMD implementation " << variant_index
                 << " differs from pre-fix golden digest");
    }
    return golden_digest.value;
}

}  // namespace

BOOST_AUTO_TEST_CASE(misaligned_scalar_tails_match_reference_and_golden_output) {
    const CpuSupport cpu = DetectCpuSupport();
    std::vector<XorFn> fixed_variants;
    std::vector<XorFn> random_variants;

    if (ssea_test_sse2_compiled() && cpu.sse2) {
        fixed_variants.push_back(ssea_test_masked_xor_sse);
        random_variants.push_back(ssea_test_masked_xor_random_next_sse);
    }
    if (ssea_test_sse3_compiled() && cpu.sse3) {
        fixed_variants.push_back(ssea_test_masked_xor_sse3);
        random_variants.push_back(ssea_test_masked_xor_random_next_sse3);
    }
    if (ssea_test_avx2_compiled() && cpu.avx2) {
        fixed_variants.push_back(ssea_test_masked_xor_avx2);
        random_variants.push_back(ssea_test_masked_xor_random_next_avx2);
    }

    CheckOperation("masked_xor", kFixedKey, GoldenFixed,
        ssea::masked_xor_scalar, fixed_variants, UINT64_C(0xabdee34998b16395));
    CheckOperation("masked_xor_random_next", kRandomKey, GoldenRandomNext,
        ssea::masked_xor_random_next_scalar, random_variants, UINT64_C(0x9afbc1cfcdf2f5a5));
}
