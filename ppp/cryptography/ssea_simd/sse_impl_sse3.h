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

#if defined(SSEA_X86) && (defined(_MSC_VER) || defined(__SSE3__))
#define SSEA_SSE3 1
#endif

#if defined(SSEA_X86) && (defined(_MSC_VER) || defined(__SSE4_2__))
#define SSEA_SSE4_2 1
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // SSE3 and SSE4.2 kernels.
    //
    // SSE3 level: the only integer-relevant SSE3 instruction is LDDQU
    // (unaligned 128-bit load). The delta/masked kernels are the SSE2 versions
    // with LDDQU loads; the base94 kernels reuse the SSE2 hybrid (their loads
    // are 64-bit, LDDQU does not apply). Whether LDDQU actually helps is
    // measured in bench_dispatch.cpp - on modern CPUs it is equivalent to
    // MOVDQU, which the benchmark confirms.
    //
    // SSE4.2 level: adds the POPCNT instruction (CPUID.1:ECX bit 23), used for
    // the base94 output-position popcount (one instruction instead of a 256-
    // entry table lookup). The dispatch level requires both SSE4.2 (bit 20)
    // and POPCNT (bit 23) so _mm_popcnt_u32 is always safe here.
    // -----------------------------------------------------------------------------

    /**
     * @brief Encodes binary bytes with the Base94 mapping (SSE3 level).
     *        Same kernels as the SSE2 hybrid (64-bit loads, no LDDQU); kept as
     *        a distinct dispatch level for the per-level benchmark.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_sse3(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
        return base94_encode_sse2(data, datalen, kf, output);
    }

    /**
     * @brief Decodes bytes produced by base94_encode (SSE3 level).
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     */
    inline int base94_decode_sse3(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
        return base94_decode_sse2(data, datalen, kf, output);
    }

    /**
     * @brief Delta-encodes a byte sequence (SSE3 level): SSE2 kernel with
     *        LDDQU unaligned loads.
     * @param data      Input bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment for the first byte.
     * @param output    [out] Encoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_encode_sse3(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE3)
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
        for (; i + 16 <= data_size; i += 16)
        {
            __m128i a = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(in + i));  // SSE3 LDDQU
            __m128i prev = _mm_or_si128(_mm_slli_si128(a, 1), prev_last);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + i), _mm_sub_epi8(a, prev));
            prev_last = _mm_srli_si128(a, 15);
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
     * @brief Delta-decodes a byte sequence (SSE3 level): SSE2 prefix-sum kernel
     *        with LDDQU unaligned loads.
     * @param data      Delta-encoded bytes (data_size >= 1).
     * @param data_size Number of input bytes.
     * @param kf        Initial adjustment used at encode time.
     * @param output    [out] Decoded buffer (allocated with +16 slack).
     * @return data_size on success, 0 on failure.
     */
    inline int delta_decode_sse3(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE3)
        const uint8_t* in = static_cast<const uint8_t*>(data);
        if (nullptr == in || data_size < 1)
        {
            return 0;
        }

        output = std::make_unique<uint8_t[]>(data_size + 16);
        uint8_t* out = output.get();

        int i = 0;
        uint8_t acc = static_cast<uint8_t>(kf);
        for (; i + 16 <= data_size; i += 16)
        {
            __m128i a = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(in + i));  // SSE3 LDDQU
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
     * @brief XOR-masks a memory range with a fixed 32-bit key (SSE3 level):
     *        LDDQU load variant.
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Fixed 32-bit XOR key.
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_sse3(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_SSE3)
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
            __m128i v = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(p + i));  // SSE3 LDDQU
            _mm_storeu_si128(reinterpret_cast<__m128i*>(p + i), _mm_xor_si128(v, k));
        }

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
     * @brief XOR-masks a memory range with a per-word LCG keystream (SSE3 level):
     *        scalar keystream (non-linear fold chain) + LDDQU batched XOR.
     * @param min Inclusive start address.
     * @param max Exclusive end address.
     * @param kf  Initial key factor (LCG seed).
     * @return true on success, false when the range is invalid.
     */
    inline bool masked_xor_random_next_sse3(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_SSE3)
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

        kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));

        int i = 0;
        for (; i + 16 <= length; i += 16)
        {
            int32_t ks[4];
            ks[0] = kf;
            for (int w = 1; w < 4; w++)
            {
                kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
                ks[w] = kf;
            }
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));

            __m128i kv = _mm_set_epi32(ks[3], ks[2], ks[1], ks[0]);
            __m128i v = _mm_lddqu_si128(reinterpret_cast<const __m128i*>(p + i));  // SSE3 LDDQU
            _mm_storeu_si128(reinterpret_cast<__m128i*>(p + i), _mm_xor_si128(v, kv));
        }

        int32_t* p32 = reinterpret_cast<int32_t*>(p + i);
        while (reinterpret_cast<const uint8_t*>(p32 + 1) <= static_cast<const uint8_t*>(max))
        {
            *p32 = *p32 ^ kf;
            p32++;
            kf = random_next_scalar(reinterpret_cast<unsigned int*>(&kf));
        }

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
     * @brief Encodes binary bytes with the Base94 mapping (SSE4.2 level).
     *        Same kernels as the SSE4.1 path; the output popcount uses the
     *        POPCNT instruction instead of the table lookup.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_sse4_2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE4_2)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }

        static constexpr int BLOCK = 8;
        int outlen = 0;
        for (int i = 0; i < datalen; i++)
        {
            outlen += (static_cast<uint8_t>(bytes[i] - kf) >= BASE93_RADIX) ? 2 : 1;
        }

        output = std::make_unique<uint8_t[]>(outlen + 16);
        uint8_t* out = output.get();
        int op = 0;

        const __m128i kf8  = _mm_set1_epi8(static_cast<char>(kf));
        const __m128i c80  = _mm_set1_epi8(static_cast<char>(0x80));
        const __m128i c93  = _mm_set1_epi8(static_cast<char>(93));
        const __m128i c20  = _mm_set1_epi8(static_cast<char>(0x20));
        const __m128i cDC  = _mm_set1_epi8(static_cast<char>(92 ^ 0x80));  // signed: -36
        const __m128i c39  = _mm_set1_epi8(static_cast<char>(185 ^ 0x80)); // signed: 57
        const __m128i one  = _mm_set1_epi8(1);
        const __m128i c7D  = _mm_set1_epi8(static_cast<char>(0x7D));       // '}'
        const auto& tbl = encode_table();

        int i = 0;
        for (; i + BLOCK <= datalen; i += BLOCK)
        {
            __m128i b8 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i));
            b8 = _mm_sub_epi8(b8, kf8);

            __m128i biased = _mm_xor_si128(b8, c80);
            __m128i L1 = _mm_cmpgt_epi8(biased, cDC);         // b >= 93
            __m128i L2 = _mm_cmpgt_epi8(biased, c39);         // b >= 186

            __m128i lo = _mm_sub_epi8(b8, _mm_and_si128(L1, c93));
            lo = _mm_sub_epi8(lo, _mm_and_si128(L2, c93));
            lo = _mm_add_epi8(lo, c20);

            __m128i hi = _mm_add_epi8(c7D, _mm_and_si128(L2, one));

            __m128i ex = _mm_unpacklo_epi8(hi, lo);

            const int mask = _mm_movemask_epi8(L1) & 0xFF;
            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[mask].data()));
            __m128i out16 = _mm_shuffle_epi8(ex, idx);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += 8 + static_cast<int>(_mm_popcnt_u32(static_cast<uint32_t>(mask)));  // POPCNT (SSE4.2)
        }

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
     * @brief Decodes bytes produced by base94_encode (SSE4.2 level).
     *        Same kernels as the SSE4.1 path; the popcount uses POPCNT.
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     */
    inline int base94_decode_sse4_2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE4_2)
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

        const __m128i kf8 = _mm_set1_epi8(static_cast<char>(kf));
        const __m128i c80 = _mm_set1_epi8(static_cast<char>(0x80));
        const __m128i c93 = _mm_set1_epi8(static_cast<char>(93));
        const __m128i c20 = _mm_set1_epi8(static_cast<char>(0x20));
        const __m128i cA0 = _mm_set1_epi8(static_cast<char>(0x20 ^ 0x80));
        const __m128i cFE = _mm_set1_epi8(static_cast<char>(0x7E ^ 0x80));
        const __m128i cFC = _mm_set1_epi8(static_cast<char>(0x7C ^ 0x80));
        const __m128i cFD = _mm_set1_epi8(static_cast<char>(0x7D ^ 0x80));
        const __m128i cE5 = _mm_set1_epi8(static_cast<char>(0x65 ^ 0x80));
        const auto& tbl = decode_table();

        static constexpr int BLOCK = 8;
        int i = 0;
        for (; i + BLOCK + 1 <= datalen; i += BLOCK)
        {
            __m128i c16 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i));
            __m128i next1 = _mm_cvtsi32_si128(bytes[i + BLOCK]);
            c16 = _mm_or_si128(c16, _mm_slli_si128(next1, 8));

            __m128i cb = _mm_xor_si128(c16, c80);
            __m128i esc   = _mm_cmpgt_epi8(cb, cFC);
            __m128i tilde = _mm_cmpgt_epi8(cb, cFD);

            __m128i nxt = _mm_srli_si128(c16, 1);
            __m128i nb  = _mm_xor_si128(nxt, c80);
            __m128i nxt_off = _mm_sub_epi8(nxt, c20);

            __m128i bad = _mm_or_si128(_mm_cmpgt_epi8(cA0, cb), _mm_cmpgt_epi8(cb, cFE));
            __m128i bad_n = _mm_or_si128(_mm_cmpgt_epi8(cA0, nb), _mm_cmpgt_epi8(nb, cFE));
            __m128i next_esc = _mm_cmpgt_epi8(nb, cFD);
            __m128i next_hi  = _mm_cmpgt_epi8(nb, cE5);
            __m128i ovf = _mm_or_si128(_mm_and_si128(esc, next_esc), _mm_and_si128(tilde, next_hi));
            const int vbad = _mm_movemask_epi8(_mm_or_si128(_mm_or_si128(bad, bad_n), ovf)) & 0xFF;
            if (0 != vbad)
            {
                return base94_decode_scalar(data, datalen, kf, output);
            }

            __m128i v_esc = _mm_add_epi8(_mm_and_si128(tilde, c93), c93);
            v_esc = _mm_add_epi8(v_esc, nxt_off);
            __m128i v_norm = _mm_sub_epi8(c16, c20);
            __m128i v = _mm_blendv_epi8(v_norm, v_esc, esc);

            int esc_bits = _mm_movemask_epi8(esc) & 0xFF;
            const int del = ((esc_bits << 1) & 0xFF) | carry;
            carry = (esc_bits >> 7) & 1;

            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[del].data()));
            __m128i v16 = _mm_unpacklo_epi8(v, v);
            __m128i out16 = _mm_shuffle_epi8(v16, idx);
            out16 = _mm_add_epi8(out16, kf8);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += BLOCK - static_cast<int>(_mm_popcnt_u32(static_cast<uint32_t>(del)));  // POPCNT
        }

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
}
