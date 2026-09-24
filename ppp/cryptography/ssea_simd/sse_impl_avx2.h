#pragma once

#include "ssea_scalar_ref.h"
#include "base94_simd.h"
#include "sse_impl_sse2.h"

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

#if defined(SSEA_X86) && (defined(_MSC_VER) || defined(__AVX2__))
#define SSEA_AVX2 1
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // AVX2 256-bit kernels.
    //
    // AVX2 adds 256-bit INTEGER instructions (vpsubb, vpcmpgtb, vpand, vpshufb,
    // vpslldq, vpxor, ...). Note: 256-bit byte shuffles operate PER 128-bit
    // LANE, which matches the two-8-byte-group structure of the base94 kernels:
    //   lane 0 = input bytes [0..7],  lane 1 = input bytes [8..15].
    // The table-driven pshufb gather therefore runs BOTH groups in ONE 256-bit
    // instruction (each lane uses its own 16-byte index vector, combined with
    // vinserti128).
    //
    // Dispatch safety: these functions are only reached through the dispatch
    // table AFTER the CPUID probe confirmed AVX2 (and OS XMM/YMM state), see
    // sse_dispatch.h. Outputs are byte-for-byte identical to the scalar
    // references over every input length (tests/test_base94.cpp).
    // -----------------------------------------------------------------------------

    /**
     * @brief Encodes binary bytes with the Base94 mapping (AVX2 level).
     *        256-bit compute core + dual-lane pshufb gather; 16 input bytes/round.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_avx2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX2)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }

        static constexpr int BLOCK = 16;   // two 8-byte groups per round
        int outlen = 0;
        for (int i = 0; i < datalen; i++)
        {
            outlen += (static_cast<uint8_t>(bytes[i] - kf) >= BASE93_RADIX) ? 2 : 1;
        }

        output = std::make_unique<uint8_t[]>(outlen + 16);
        uint8_t* out = output.get();
        int op = 0;

        const __m256i kf8  = _mm256_set1_epi8(static_cast<char>(kf));
        const __m256i c80  = _mm256_set1_epi8(static_cast<char>(0x80));
        const __m256i c93  = _mm256_set1_epi8(static_cast<char>(93));
        const __m256i c20  = _mm256_set1_epi8(static_cast<char>(0x20));
        const __m256i cDC  = _mm256_set1_epi8(static_cast<char>(92 ^ 0x80));  // signed: -36
        const __m256i c39  = _mm256_set1_epi8(static_cast<char>(185 ^ 0x80)); // signed: 57
        const __m256i one  = _mm256_set1_epi8(1);
        const __m256i c7D  = _mm256_set1_epi8(static_cast<char>(0x7D));       // '}'
        const auto& tbl = encode_table();

        int i = 0;
        for (; i + BLOCK <= datalen; i += BLOCK)
        {
            // ---- 256-bit compute core: the 128-bit load holds bytes 0..15;
            //      group A = bytes 0..7, group B = bytes 8..15 (BOTH live in
            //      the low 128-bit lane; the high lane is garbage, unused) ----
            const __m128i a128 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + i));
            __m256i b8 = _mm256_castsi128_si256(a128);            // zero-extend semantics: high lane is garbage
            b8 = _mm256_sub_epi8(b8, kf8);                        // b = byte - kf

            __m256i biased = _mm256_xor_si256(b8, c80);
            __m256i L1 = _mm256_cmpgt_epi8(biased, cDC);          // b >= 93
            __m256i L2 = _mm256_cmpgt_epi8(biased, c39);          // b >= 186

            __m256i lo = _mm256_sub_epi8(b8, _mm256_and_si256(L1, c93));
            lo = _mm256_sub_epi8(lo, _mm256_and_si256(L2, c93));  // b % 93
            lo = _mm256_add_epi8(lo, c20);                        // + 0x20

            __m256i hi = _mm256_add_epi8(c7D, _mm256_and_si256(L2, one)); // '}' or '~'

            // Masks: sign bits of the LOW 128-bit lane hold BOTH groups;
            // the high lane is garbage and must not be read.
            const int all = _mm256_movemask_epi8(L1);
            const int maskA = all & 0xFF;                          // bytes 0..7
            const int maskB = (all >> 8) & 0xFF;                   // bytes 8..15

            // Per-group 128-bit expansion: unpacklo -> group A [hi,lo] pairs,
            // unpackhi -> group B [hi,lo] pairs.
            __m128i hi128 = _mm256_castsi256_si128(hi);
            __m128i lo128 = _mm256_castsi256_si128(lo);
            __m128i exA = _mm_unpacklo_epi8(hi128, lo128);
            __m128i exB = _mm_unpackhi_epi8(hi128, lo128);

            // Table gather per group (16-byte pshufb, one per group).
            __m128i idxA = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[maskA].data()));
            __m128i idxB = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[maskB].data()));
            __m128i outA = _mm_shuffle_epi8(exA, idxA);
            __m128i outB = _mm_shuffle_epi8(exB, idxB);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), outA);
            op += 8 + popcount8(maskA);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), outB);
            op += 8 + popcount8(maskB);
        }

        // Scalar tail: identical semantics, byte-for-byte.
        for (; i < datalen; i++)
        {
            const uint8_t b = static_cast<uint8_t>(bytes[i] - kf);
            if (b >= BASE93_RADIX)
            {
                out[op++] = static_cast<uint8_t>(0x20 + b / BASE93_RADIX + 92);
                out[op++] = static_cast<uint8_t>(0x20 + b % BASE93_RADIX);
            }
            else
            {
                out[op++] = static_cast<uint8_t>(0x20 + b);
            }
        }

        return outlen;
#else
        (void)data;
        (void)datalen;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Decodes bytes produced by base94_encode (AVX2 level).
     *        256-bit compute + validation; dual-lane table gather; 16 chars/round
     *        with a 17-char window (group B's first char IS group A's next).
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     */
    inline int base94_decode_avx2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX2)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }
        if (datalen < 16)
        {
            return base94_decode_scalar(data, datalen, kf, output);
        }

        int outlen = datalen;
        for (int i = 0; i < datalen; i++)
        {
            if (bytes[i] >= 0x7D)
            {
                outlen--;
                i++;
            }
        }

        output = std::make_unique<uint8_t[]>(outlen + 16);
        uint8_t* out = output.get();
        int op = 0;
        int carry = 0;

        const __m256i kf8 = _mm256_set1_epi8(static_cast<char>(kf));
        const __m256i c80 = _mm256_set1_epi8(static_cast<char>(0x80));
        const __m256i c93 = _mm256_set1_epi8(static_cast<char>(93));
        const __m256i c20 = _mm256_set1_epi8(static_cast<char>(0x20));
        const __m256i cA0 = _mm256_set1_epi8(static_cast<char>(0x20 ^ 0x80)); // signed: -96
        const __m256i cFE = _mm256_set1_epi8(static_cast<char>(0x7E ^ 0x80)); // signed: -2
        const __m256i cFC = _mm256_set1_epi8(static_cast<char>(0x7C ^ 0x80)); // signed: -4
        const __m256i cFD = _mm256_set1_epi8(static_cast<char>(0x7D ^ 0x80)); // signed: -3
        const __m256i cE5 = _mm256_set1_epi8(static_cast<char>(0x65 ^ 0x80)); // signed: -27
        const auto& tbl = decode_table();

        static constexpr int BLOCK = 16;
        int i = 0;
        for (; i + BLOCK + 1 <= datalen; i += BLOCK)
        {
            // Window [i, i+16]: lane0 = [c0..c7, c8, 0..0] (group A + its next),
            //                   lane1 = [c8..c15, c16, 0..0] (group B + its next).
            const __m128i n16 = _mm_cvtsi32_si128(bytes[i + BLOCK]);
            __m128i loA = _mm_or_si128(_mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i)),
                                       _mm_slli_si128(_mm_cvtsi32_si128(bytes[i + 8]), 8));
            __m128i loB = _mm_or_si128(_mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i + 8)),
                                       _mm_slli_si128(n16, 8));
            __m256i c16 = _mm256_inserti128_si256(_mm256_castsi128_si256(loA), loB, 1);

            __m256i cb = _mm256_xor_si256(c16, c80);
            __m256i esc   = _mm256_cmpgt_epi8(cb, cFC);   // ch >= 0x7D (per lane)
            __m256i tilde = _mm256_cmpgt_epi8(cb, cFD);   // ch >= 0x7E (per lane)

            __m256i nxt = _mm256_srli_si256(c16, 1);      // per-lane next char
            __m256i nb  = _mm256_xor_si256(nxt, c80);
            __m256i nxt_off = _mm256_sub_epi8(nxt, c20);

            // Validation (both group masks); any violation -> scalar reference.
            __m256i bad = _mm256_or_si256(_mm256_cmpgt_epi8(cA0, cb), _mm256_cmpgt_epi8(cb, cFE));
            __m256i bad_n = _mm256_or_si256(_mm256_cmpgt_epi8(cA0, nb), _mm256_cmpgt_epi8(nb, cFE));
            __m256i next_esc = _mm256_cmpgt_epi8(nb, cFD);
            __m256i next_hi  = _mm256_cmpgt_epi8(nb, cE5);
            __m256i ovf = _mm256_or_si256(_mm256_and_si256(esc, next_esc), _mm256_and_si256(tilde, next_hi));
            const int vbad = _mm256_movemask_epi8(_mm256_or_si256(_mm256_or_si256(bad, bad_n), ovf));
            if (0 != (vbad & 0xFF) || 0 != ((vbad >> 16) & 0xFF))
            {
                return base94_decode_scalar(data, datalen, kf, output);
            }

            // v = (ch>=0x7D) ? (93 + 93*(ch>=0x7E) + next - 0x20) : (ch - 0x20)
            __m256i v_esc = _mm256_add_epi8(_mm256_and_si256(tilde, c93), c93);
            v_esc = _mm256_add_epi8(v_esc, nxt_off);
            __m256i v_norm = _mm256_sub_epi8(c16, c20);
            __m256i v = _mm256_blendv_epi8(v_norm, v_esc, esc);   // per-lane select

            // delete masks: del = esc<<1 | carry; carry crosses the lane and
            // the block (group A's bit 7 deletes group B's char 0).
            const int esc_all = _mm256_movemask_epi8(esc);
            const int escA = esc_all & 0xFF;
            const int escB = (esc_all >> 16) & 0xFF;
            const int delA = ((escA << 1) & 0xFF) | carry;
            const int carryA = (escA >> 7) & 1;
            const int delB = ((escB << 1) & 0xFF) | carryA;
            carry = (escB >> 7) & 1;

            // Dual-lane compress: unpacklo duplicates each lane's low 8 bytes.
            __m256i v16 = _mm256_unpacklo_epi8(v, v);
            __m128i idxA = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[delA].data()));
            __m128i idxB = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[delB].data()));
            __m256i idx = _mm256_inserti128_si256(_mm256_castsi128_si256(idxA), idxB, 1);
            __m256i out32 = _mm256_shuffle_epi8(v16, idx);
            out32 = _mm256_add_epi8(out32, kf8);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), _mm256_castsi256_si128(out32));
            op += 8 - popcount8(delA);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), _mm256_extracti128_si256(out32, 1));
            op += 8 - popcount8(delB);
        }

        // Scalar validation of the tail (exact scalar semantics).
        for (int j = i + carry; j < datalen; j++)
        {
            const uint8_t c = bytes[j];
            if (c < 0x20 || c > 0x7E)
            {
                return base94_decode_scalar(data, datalen, kf, output);
            }
            if (c >= 0x7D)
            {
                if (++j >= datalen)
                {
                    return base94_decode_scalar(data, datalen, kf, output);
                }
                const uint8_t n = bytes[j];
                if (n < 0x20 || n > 0x7E)
                {
                    return base94_decode_scalar(data, datalen, kf, output);
                }
                const int off = n - 0x20;
                if (off > BASE93_RADIX || (c == 0x7E && off > 69))
                {
                    return base94_decode_scalar(data, datalen, kf, output);
                }
            }
        }

        i += carry;
        for (; i < datalen; i++)
        {
            const uint8_t b = bytes[i] - '\x20';
            if (b >= BASE93_RADIX)
            {
                const int v = (((b - BASE93_RADIX) + 1) * BASE93_RADIX) + (bytes[++i] - '\x20');
                if (v > 0xff)
                {
                    return 0;
                }
                out[op++] = static_cast<uint8_t>(v + kf);
            }
            else
            {
                out[op++] = static_cast<uint8_t>(b + kf);
            }
        }

        return outlen;
#else
        (void)data;
        (void)datalen;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Delta-encodes a byte sequence (AVX2 level), 32 bytes/round.
     *        Per-lane vpslldq with cross-lane previous-byte injection.
     * @param data      Input bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment for the first byte.
     * @param output    [out] Encoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_encode_avx2(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX2)
        const uint8_t* in = static_cast<const uint8_t*>(data);
        if (nullptr == in || data_size < 1)
        {
            return 0;
        }

        output = std::make_unique<uint8_t[]>(data_size + 16);
        uint8_t* out = output.get();

        int i = 0;
        __m128i prev_last = _mm_cvtsi32_si128(kf);   // in[-1] == kf (low byte)
        prev_last = _mm_and_si128(prev_last, _mm_set_epi32(0, 0, 0, 0xFF));
        for (; i + 32 <= data_size; i += 32)
        {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + i));
            __m128i x0 = _mm256_castsi256_si128(a);
            __m128i x1 = _mm256_extracti128_si256(a, 1);

            // prev for lane 0: [in[i-1], in[i]..in[i+14]]
            __m128i prev0 = _mm_or_si128(_mm_slli_si128(x0, 1), prev_last);
            // prev for lane 1: [in[i+15], in[i+16]..in[i+30]]
            __m128i a15 = _mm_srli_si128(x0, 15);                  // in[i+15]
            __m128i prev1 = _mm_or_si128(_mm_slli_si128(x1, 1), a15);

            __m256i prev = _mm256_inserti128_si256(_mm256_castsi128_si256(prev0), prev1, 1);
            __m256i o = _mm256_sub_epi8(a, prev);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + i), o);

            prev_last = _mm_srli_si128(x1, 15);                    // in[i+31]
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
     * @brief Delta-decodes a byte sequence (AVX2 level), 32 bytes/round.
     *        Per-lane parallel prefix sum + cross-lane carry propagation.
     * @param data      Delta-encoded bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment used at encode time.
     * @param output    [out] Decoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_decode_avx2(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX2)
        const uint8_t* in = static_cast<const uint8_t*>(data);
        if (nullptr == in || data_size < 1)
        {
            return 0;
        }

        output = std::make_unique<uint8_t[]>(data_size + 16);
        uint8_t* out = output.get();

        int i = 0;
        uint8_t acc = static_cast<uint8_t>(kf);
        for (; i + 32 <= data_size; i += 32)
        {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + i));

            // Per-lane prefix sums (vpslldq shifts INSIDE each 128-bit lane).
            __m256i p = a;
            p = _mm256_add_epi8(p, _mm256_slli_si256(p, 1));
            p = _mm256_add_epi8(p, _mm256_slli_si256(p, 2));
            p = _mm256_add_epi8(p, _mm256_slli_si256(p, 4));
            p = _mm256_add_epi8(p, _mm256_slli_si256(p, 8));

            // Lane 0 output: p0 + acc (previous block carry).
            __m128i p0 = _mm256_castsi256_si128(p);
            __m128i o0 = _mm_add_epi8(p0, _mm_set1_epi8(static_cast<char>(acc)));
            const uint8_t s0 = static_cast<uint8_t>(_mm_cvtsi128_si32(_mm_srli_si128(o0, 15)));

            // Lane 1 output: p1 + s0 (lane 0 total) - the true prefix sum.
            __m128i p1 = _mm256_extracti128_si256(p, 1);
            __m128i o1 = _mm_add_epi8(p1, _mm_set1_epi8(static_cast<char>(s0)));
            acc = static_cast<uint8_t>(_mm_cvtsi128_si32(_mm_srli_si128(o1, 15)));

            __m256i o = _mm256_inserti128_si256(_mm256_castsi128_si256(o0), o1, 1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + i), o);
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
     * @brief XOR-masks a memory range with a fixed 32-bit key (AVX2 level).
     *        32 bytes per vpxor; tail matches the scalar word/half/byte logic.
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Fixed 32-bit XOR key.
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_avx2(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_AVX2)
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

        const __m256i k = _mm256_set1_epi32(kf);
        int i = 0;
        for (; i + 32 <= length; i += 32)
        {
            __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p + i), _mm256_xor_si256(v, k));
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

    /**
     * @brief XOR-masks a memory range with a per-word LCG keystream (AVX2 level).
     *        Keystream stays scalar (non-linear fold chain, see ssea_simd.h);
     *        8 keystream words are batched per 32-byte vpxor.
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Initial key factor (LCG seed).
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_random_next_avx2(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_AVX2)
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
        for (; i + 32 <= length; i += 32)
        {
            int32_t ks[8];
            ks[0] = kf;
            for (int w = 1; w < 8; w++)
            {
                kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
                ks[w] = kf;
            }
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));  // key for word i+32

            __m256i kv = _mm256_set_epi32(ks[7], ks[6], ks[5], ks[4], ks[3], ks[2], ks[1], ks[0]);
            __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(p + i), _mm256_xor_si256(v, kv));
        }

        // Remaining full words (0..7): scalar, kf already holds the next key.
        int32_t* p32 = reinterpret_cast<int32_t*>(p + i);
        while (reinterpret_cast<const uint8_t*>(p32 + 1) <= static_cast<const uint8_t*>(max))
        {
            *p32 = *p32 ^ kf;
            p32++;
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
        }

        // Tail 2/1 bytes: use the current key WITHOUT advancing.
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
}
