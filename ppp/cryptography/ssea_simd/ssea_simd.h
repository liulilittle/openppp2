#pragma once

#include "ssea_scalar_ref.h"

#include <cstdint>
#include <cstring>

#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) || \
    (defined(__x86_64__) || defined(__i386__))
#define SSEA_X86 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>
#endif
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // SSE2 implementations of the remaining ssea module primitives:
    //   * delta_encode  - out[i] = in[i] - in[i-1]          (psubb + byte shift)
    //   * delta_decode  - out[i] = out[i-1] + in[i]         (parallel prefix sum)
    //   * masked_xor    - fixed 32-bit key xor              (pxor 16 bytes)
    //   * masked_xor_random_next - per-word LCG keystream   (serial NON-LINEAR
    //                     fold chain: kf = random_next(&kf) overwrites the seed
    //                     with the returned value, so jump-ahead does NOT apply;
    //                     keystream stays scalar, the XOR is batched via SSE2)
    //   * shuffle       - scalar micro-optimization only    (SIMD not applicable:
    //                     data-dependent random permutation)
    //
    // Correctness: every path here is verified byte-for-byte identical to the
    // scalar reference for EVERY input length 1..65535, plus multiple kf/key
    // values, canary (out-of-bounds) guards and unaligned offsets - see
    // tests/test_ssea.cpp. Per-method feasibility proofs: docs/algorithms.md
    // (EN) and docs/algorithms_CN.md (CN).
    // All outputs are verified byte-for-byte identical to the scalar reference.
    // -----------------------------------------------------------------------------

    /**
     * @brief Delta-encodes a byte sequence: out[0] = in[0] - kf; out[i] = in[i] - in[i-1]
     *        (mod 256). SSE2: 16 bytes per iteration.
     * @param data      Input bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment for the first byte.
     * @param output    [out] Encoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_encode_sse(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_X86)
        const uint8_t* in = static_cast<const uint8_t*>(data);
        if (nullptr == in || data_size < 1)
        {
            return 0;
        }

        output = std::make_unique<uint8_t[]>(data_size + 16);
        uint8_t* out = output.get();

        int i = 0;
        __m128i prev_last = _mm_cvtsi32_si128(kf);            // in[-1] == kf (low byte) for the first block
        prev_last = _mm_and_si128(prev_last, _mm_set_epi32(0, 0, 0, 0xFF));  // keep only byte 0
        for (; i + 16 <= data_size; i += 16)
        {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + i));
            // prev[j] = in[i+j-1] = [in[i-1], in[i], ..., in[i+14]]
            __m128i prev = _mm_or_si128(_mm_slli_si128(a, 1), prev_last);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + i), _mm_sub_epi8(a, prev));
            prev_last = _mm_srli_si128(a, 15);       // in[i+15], needed as in[i-1] next block
        }

        uint8_t prev_byte = (i > 0) ? in[i - 1] : static_cast<uint8_t>(kf);
        for (; i < data_size; i++)
        {
            out[i] = static_cast<uint8_t>(in[i] - prev_byte);
            prev_byte = in[i];
        }

        return data_size;
#else
        (void)data;
        (void)data_size;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Delta-decodes: out[0] = in[0] + kf; out[i] = out[i-1] + in[i] (mod 256).
     *        SSE2: Hillis-Steele parallel prefix sum (16 lanes) + cross-block carry.
     * @param data      Delta-encoded bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment used at encode time.
     * @param output    [out] Decoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_decode_sse(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_X86)
        const uint8_t* in = static_cast<const uint8_t*>(data);
        if (nullptr == in || data_size < 1)
        {
            return 0;
        }

        output = std::make_unique<uint8_t[]>(data_size + 16);
        uint8_t* out = output.get();

        int i = 0;
        uint8_t acc = static_cast<uint8_t>(kf);      // out[-1] == kf
        for (; i + 16 <= data_size; i += 16)
        {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + i));
            // Parallel prefix sum over 16 lanes (mod 256).
            // slli_si128 shifts bytes toward the HIGH addresses: result[j] = in[j-k],
            // which is exactly the "previous byte" direction a prefix sum needs.
            __m128i p = a;
            p = _mm_add_epi8(p, _mm_slli_si128(p, 1));
            p = _mm_add_epi8(p, _mm_slli_si128(p, 2));
            p = _mm_add_epi8(p, _mm_slli_si128(p, 4));
            p = _mm_add_epi8(p, _mm_slli_si128(p, 8));

            __m128i o = _mm_add_epi8(p, _mm_set1_epi8(static_cast<char>(acc)));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + i), o);
            acc = static_cast<uint8_t>(_mm_cvtsi128_si32(_mm_srli_si128(o, 15)));
        }

        for (; i < data_size; i++)
        {
            acc = static_cast<uint8_t>(acc + in[i]);
            out[i] = acc;
        }

        return data_size;
#else
        (void)data;
        (void)data_size;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief XOR-masks a memory range with a fixed 32-bit key. SSE2: 16 bytes/op.
     *        Tail (4/2/1 bytes) matches the scalar word/half/byte logic.
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Fixed 32-bit XOR key.
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_sse(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_X86)
        uint8_t* p = static_cast<uint8_t*>(const_cast<void*>(min));
        const int length = static_cast<int>(static_cast<const uint8_t*>(max) - static_cast<const uint8_t*>(min));
        if (0 == length)
        {
            return true;
        }
        if (length < 0)
        {
            return false;
        }

        const __m128i k = _mm_set1_epi32(kf);
        int i = 0;
        for (; i + 16 <= length; i += 16)
        {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(p + i), _mm_xor_si128(v, k));
        }

        // Scalar tail: exact copy of the reference word/half/byte logic.
        int rem = length - i;
        int32_t* p32 = reinterpret_cast<int32_t*>(p + i);
        while (rem >= 4)
        {
            *p32 = *p32 ^ kf;
            p32++;
            rem -= 4;
        }
        int16_t* p16 = reinterpret_cast<int16_t*>(p32);
        if (rem >= 2)
        {
            *p16 = static_cast<int16_t>(*p16 ^ kf);
            p16++;
        }
        int8_t* p8 = reinterpret_cast<int8_t*>(p16);
        if (rem & 1)
        {
            *p8 = static_cast<int8_t>(*p8 ^ kf);
        }

        return true;
#else
        (void)min;
        (void)max;
        (void)kf;
        return false;
#endif
    }

    // -----------------------------------------------------------------------------
    // masked_xor_random_next keystream analysis (Note).
    //
    // The scalar code does: kf = random_next(&kf) per 32-bit word. random_next
    // writes the advanced seed into *seed and RETURNS the folded value, which is
    // then stored back into kf - overwriting the seed. Hence the keystream is a
    // NON-LINEAR chain: k_{n+1} = fold(k_n) (fold contains shifts/XORs), NOT the
    // textbook LCG chain seed_{n+1} = L3(seed_n). LCG jump-ahead does NOT apply.
    //
    // Consequence: the keystream cannot be parallelized. The SSE2 version keeps
    // the scalar keystream generation and batches the XOR over 16 bytes.
    // -----------------------------------------------------------------------------

    /**
     * @brief XOR-masks a memory range with a per-32-bit-word LCG keystream.
     *        Byte-for-byte identical keystream to the scalar reference; the XOR
     *        is batched via SSE2 (16 bytes per round, 4 keystream words).
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Initial key factor (LCG seed).
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_random_next_sse(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_X86)
        uint8_t* p = static_cast<uint8_t*>(const_cast<void*>(min));
        const int length = static_cast<int>(static_cast<const uint8_t*>(max) - static_cast<const uint8_t*>(min));
        if (0 == length)
        {
            return true;
        }
        if (length < 0)
        {
            return false;
        }

        // Scalar semantics: the first word uses random_next(seed) - update once
        // before the loop; every word afterwards advances the chain once.
        kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));

        int i = 0;
        for (; i + 16 <= length; i += 16)
        {
            int32_t ks[4];
            ks[0] = kf;                                          // word 4m+0: key from the pre-loop update
            for (int w = 1; w < 4; w++)
            {
                kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
                ks[w] = kf;
            }
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));  // key for word 4m+4

            __m128i kv = _mm_set_epi32(ks[3], ks[2], ks[1], ks[0]);
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(p + i), _mm_xor_si128(v, kv));
        }

        // Remaining full words (0..3): scalar, kf already holds the next key.
        int32_t* p32 = reinterpret_cast<int32_t*>(p + i);
        while (reinterpret_cast<const uint8_t*>(p32 + 1) <= static_cast<const uint8_t*>(max))
        {
            *p32 = *p32 ^ kf;
            p32++;
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
        }

        // Tail 2/1 bytes: use the current key WITHOUT advancing (scalar semantics).
        int16_t* p16 = reinterpret_cast<int16_t*>(p32);
        if (reinterpret_cast<const uint8_t*>(p16 + 1) <= static_cast<const uint8_t*>(max))
        {
            *p16 = static_cast<int16_t>(*p16 ^ kf);
            p16++;
        }
        int8_t* p8 = reinterpret_cast<int8_t*>(p16);
        if (p8 < reinterpret_cast<int8_t*>(const_cast<uint8_t*>(static_cast<const uint8_t*>(max))))
        {
            *p8 = static_cast<int8_t>(*p8 ^ kf);
        }

        return true;
#else
        (void)min;
        (void)max;
        (void)kf;
        return false;
#endif
    }

    /**
     * @brief Shuffles bytes in place using the (i ^ key) % size permutation.
     *        SIMD is NOT applicable (data-dependent random access permutation);
     *        this is a scalar micro-optimization: power-of-two sizes use AND
     *        instead of the 32-bit division.
     * @param encoded_data Mutable target buffer.
     * @param data_size    Number of bytes.
     * @param key          Permutation key.
     */
    inline void shuffle_data_opt(char* encoded_data, int data_size, uint32_t key) noexcept
    {
        if (nullptr == encoded_data || data_size <= 0)
        {
            return;
        }

        if (0 == (data_size & (data_size - 1)))   // power of two
        {
            const uint32_t mask = static_cast<uint32_t>(data_size - 1);
            for (int i = 0; i < data_size; i++)
            {
                const uint32_t j = (static_cast<uint32_t>(i) ^ key) & mask;
                std::swap(encoded_data[i], encoded_data[j]);
            }
        }
        else
        {
            for (int i = 0; i < data_size; i++)
            {
                const uint32_t j = (static_cast<uint32_t>(i) ^ key) % static_cast<uint32_t>(data_size);
                std::swap(encoded_data[i], encoded_data[j]);
            }
        }
    }

    /**
     * @brief Unshuffles bytes in place by running the shuffle backwards.
     * @param encoded_data Mutable target buffer.
     * @param data_size    Number of bytes.
     * @param key          Permutation key used originally.
     */
    inline void unshuffle_data_opt(char* encoded_data, int data_size, uint32_t key) noexcept
    {
        if (nullptr == encoded_data || data_size <= 0)
        {
            return;
        }

        if (0 == (data_size & (data_size - 1)))
        {
            const uint32_t mask = static_cast<uint32_t>(data_size - 1);
            for (int i = data_size - 1; i > -1; i--)
            {
                const uint32_t j = (static_cast<uint32_t>(i) ^ key) & mask;
                std::swap(encoded_data[i], encoded_data[j]);
            }
        }
        else
        {
            for (int i = data_size - 1; i > -1; i--)
            {
                const uint32_t j = (static_cast<uint32_t>(i) ^ key) % static_cast<uint32_t>(data_size);
                std::swap(encoded_data[i], encoded_data[j]);
            }
        }
    }
}
