#include <ppp/cryptography/ssea_simd/ssea_simd.h>
#include <ppp/cryptography/ssea_simd/sse_impl_sse3.h>

bool ssea_test_sse2_compiled() noexcept {
#if defined(SSEA_X86)
    return true;
#else
    return false;
#endif
}

bool ssea_test_sse3_compiled() noexcept {
#if defined(SSEA_SSE3)
    return true;
#else
    return false;
#endif
}

bool ssea_test_masked_xor_sse(const void* first, const void* last, int32_t key) noexcept {
    return ssea::masked_xor_sse(first, last, key);
}

bool ssea_test_masked_xor_sse3(const void* first, const void* last, int32_t key) noexcept {
    return ssea::masked_xor_sse3(first, last, key);
}

bool ssea_test_masked_xor_random_next_sse(const void* first, const void* last,
                                           int32_t key) noexcept {
    return ssea::masked_xor_random_next_sse(first, last, key);
}

bool ssea_test_masked_xor_random_next_sse3(const void* first, const void* last,
                                            int32_t key) noexcept {
    return ssea::masked_xor_random_next_sse3(first, last, key);
}
