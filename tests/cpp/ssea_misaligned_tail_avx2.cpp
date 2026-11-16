#include <ppp/cryptography/ssea_simd/sse_impl_avx2.h>

bool ssea_test_avx2_compiled() noexcept {
#if defined(SSEA_AVX2)
    return true;
#else
    return false;
#endif
}

bool ssea_test_masked_xor_avx2(const void* first, const void* last, int32_t key) noexcept {
    return ssea::masked_xor_avx2(first, last, key);
}

bool ssea_test_masked_xor_random_next_avx2(const void* first, const void* last,
                                            int32_t key) noexcept {
    return ssea::masked_xor_random_next_avx2(first, last, key);
}
