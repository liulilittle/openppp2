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

#if defined(SSEA_X86) && (defined(_MSC_VER) || defined(__SSE4_1__))
#define SSEA_SSE4_1 1
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // base94 encode/decode for the SSE2 and SSE4.1 levels.
    //
    // SSE2 level (no pshufb): the compute core (subtract kf, unsigned compares,
    // mod-93 via compare+subtract, value blend) is fully vectorized; the
    // variable-length gather is done with a small scalar write loop driven by
    // the vector-computed mask. Division-free, branch-light - see the hybrid
    // route A argument in docs/algorithms.md.
    //
    // SSE4.1 level: same 128-bit kernels as the SSSE3 path (pshufb table
    // gather) plus _mm_blendv_epi8 for the value selection.
    //
    // Both are byte-for-byte identical to base94_encode_scalar /
    // base94_decode_scalar over every input length (tests/test_base94.cpp).
    // -----------------------------------------------------------------------------

    /**
     * @brief Encodes binary bytes with the Base94 mapping (SSE2 hybrid level).
     *        SSE2 compute core + scalar gather; matches base94_encode_scalar.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_sse2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_X86)
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

        int i = 0;
        for (; i + BLOCK <= datalen; i += BLOCK)
        {
            // ---- SSE2 compute core (identical to the SSSE3 kernel) ----
            __m128i b8 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i));
            b8 = _mm_sub_epi8(b8, kf8);                       // b = byte - kf (mod 256)

            __m128i biased = _mm_xor_si128(b8, c80);          // bias for unsigned compare
            __m128i L1 = _mm_cmpgt_epi8(biased, cDC);         // b >= 93
            __m128i L2 = _mm_cmpgt_epi8(biased, c39);         // b >= 186

            __m128i lo = _mm_sub_epi8(b8, _mm_and_si128(L1, c93));
            lo = _mm_sub_epi8(lo, _mm_and_si128(L2, c93));    // lo = b % 93
            lo = _mm_add_epi8(lo, c20);                       // lo = 0x20 + b % 93

            __m128i hi = _mm_add_epi8(c7D, _mm_and_si128(L2, one)); // '}' or '~'

            // ---- scalar gather driven by the mask (pure SSE2 has no pshufb) ----
            const int mask = _mm_movemask_epi8(L1) & 0xFF;    // bit k = 2-char pair k
            uint8_t lo8[16], hi8[16];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(lo8), lo);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(hi8), hi);

            int n = 0;
            for (int k = 0; k < BLOCK; k++)
            {
                if (0 != (mask & (1 << k)))
                {
                    out[op + n++] = hi8[k];                   // escape char first
                }
                out[op + n++] = lo8[k];                       // remainder last
            }
            op += n;
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
     * @brief Decodes bytes produced by base94_encode (SSE2 hybrid level).
     *        SSE2 compute core + scalar gather; matches base94_decode_scalar
     *        including every error path (violations fall back to the scalar
     *        reference).
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     */
    inline int base94_decode_sse2(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_X86)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }
        if (datalen < 16)
        {
            return base94_decode_scalar(data, datalen, kf, output);
        }

        // Compute the decoded length: each escape pair consumes 2 chars -> 1 byte.
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

        const __m128i c80 = _mm_set1_epi8(static_cast<char>(0x80));
        const __m128i c93 = _mm_set1_epi8(static_cast<char>(93));
        const __m128i c20 = _mm_set1_epi8(static_cast<char>(0x20));
        const __m128i cA0 = _mm_set1_epi8(static_cast<char>(0x20 ^ 0x80)); // signed: -96
        const __m128i cFE = _mm_set1_epi8(static_cast<char>(0x7E ^ 0x80)); // signed: -2
        const __m128i cFC = _mm_set1_epi8(static_cast<char>(0x7C ^ 0x80)); // signed: -4
        const __m128i cFD = _mm_set1_epi8(static_cast<char>(0x7D ^ 0x80)); // signed: -3
        const __m128i cE5 = _mm_set1_epi8(static_cast<char>(0x65 ^ 0x80)); // signed: -27

        static constexpr int BLOCK = 8;
        int i = 0;
        for (; i + BLOCK + 1 <= datalen; i += BLOCK)
        {
            __m128i c16 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i));
            __m128i next1 = _mm_cvtsi32_si128(bytes[i + BLOCK]);       // byte at i+8
            c16 = _mm_or_si128(c16, _mm_slli_si128(next1, 8));         // [c0..c7, c8, 0..0]

            __m128i cb = _mm_xor_si128(c16, c80);
            __m128i esc   = _mm_cmpgt_epi8(cb, cFC);   // ch >= 0x7D
            __m128i tilde = _mm_cmpgt_epi8(cb, cFD);   // ch >= 0x7E

            __m128i nxt = _mm_srli_si128(c16, 1);
            __m128i nb  = _mm_xor_si128(nxt, c80);
            __m128i nxt_off = _mm_sub_epi8(nxt, c20);

            // Validation (low 8 chars + their continuations); any violation
            // falls back to the scalar reference for exact error semantics.
            __m128i bad = _mm_or_si128(_mm_cmpgt_epi8(cA0, cb), _mm_cmpgt_epi8(cb, cFE));
            __m128i bad_n = _mm_or_si128(_mm_cmpgt_epi8(cA0, nb), _mm_cmpgt_epi8(nb, cFE));
            __m128i next_esc = _mm_cmpgt_epi8(nb, cFD);  // next >= 0x7E
            __m128i next_hi  = _mm_cmpgt_epi8(nb, cE5);  // next > 0x65
            __m128i ovf = _mm_or_si128(_mm_and_si128(esc, next_esc), _mm_and_si128(tilde, next_hi));
            const int vbad = _mm_movemask_epi8(_mm_or_si128(_mm_or_si128(bad, bad_n), ovf)) & 0xFF;
            if (0 != vbad)
            {
                return base94_decode_scalar(data, datalen, kf, output);
            }

            // v = (ch>=0x7D) ? (93 + 93*(ch>=0x7E) + next - 0x20) : (ch - 0x20)
            __m128i v_esc = _mm_add_epi8(_mm_and_si128(tilde, c93), c93);
            v_esc = _mm_add_epi8(v_esc, nxt_off);
            __m128i v_norm = _mm_sub_epi8(c16, c20);
            __m128i v = _mm_or_si128(_mm_and_si128(esc, v_esc), _mm_andnot_si128(esc, v_norm));

            // delete mask: only the continuation char of each pair is deleted
            int esc_bits = _mm_movemask_epi8(esc) & 0xFF;
            const int del = ((esc_bits << 1) & 0xFF) | carry;
            carry = (esc_bits >> 7) & 1;

            // scalar gather: skip deleted positions
            uint8_t v8[16];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(v8), v);
            for (int k = 0; k < BLOCK; k++)
            {
                if (0 == (del & (1 << k)))
                {
                    out[op++] = static_cast<uint8_t>(v8[k] + kf);
                }
            }
        }

        // Scalar validation of the tail with full scalar semantics.
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

        // Scalar tail reconstruction.
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
     * @brief Encodes binary bytes with the Base94 mapping (SSE4.1 level).
     *        Same pshufb table gather as the SSSE3 path; the value selection
     *        uses _mm_blendv_epi8 (SSE4.1). Matches base94_encode_scalar.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_sse4_1(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE4_1)
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
            b8 = _mm_sub_epi8(b8, kf8);                       // b = byte - kf

            __m128i biased = _mm_xor_si128(b8, c80);
            __m128i L1 = _mm_cmpgt_epi8(biased, cDC);         // b >= 93
            __m128i L2 = _mm_cmpgt_epi8(biased, c39);         // b >= 186

            __m128i lo = _mm_sub_epi8(b8, _mm_and_si128(L1, c93));
            lo = _mm_sub_epi8(lo, _mm_and_si128(L2, c93));    // b % 93
            lo = _mm_add_epi8(lo, c20);                       // + 0x20

            __m128i hi = _mm_add_epi8(c7D, _mm_and_si128(L2, one)); // '}' or '~'

            __m128i ex = _mm_unpacklo_epi8(hi, lo);           // [hi0,lo0,hi1,lo1,...]

            const int mask = _mm_movemask_epi8(L1) & 0xFF;
            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[mask].data()));
            __m128i out16 = _mm_shuffle_epi8(ex, idx);        // SSSE3 gather

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += 8 + popcount8(mask);
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
     * @brief Decodes bytes produced by base94_encode (SSE4.1 level).
     *        Same as base94_decode_sse with _mm_blendv_epi8 value selection.
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     */
    inline int base94_decode_sse4_1(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_SSE4_1)
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
        const __m128i cA0 = _mm_set1_epi8(static_cast<char>(0x20 ^ 0x80)); // signed: -96
        const __m128i cFE = _mm_set1_epi8(static_cast<char>(0x7E ^ 0x80)); // signed: -2
        const __m128i cFC = _mm_set1_epi8(static_cast<char>(0x7C ^ 0x80)); // signed: -4
        const __m128i cFD = _mm_set1_epi8(static_cast<char>(0x7D ^ 0x80)); // signed: -3
        const __m128i cE5 = _mm_set1_epi8(static_cast<char>(0x65 ^ 0x80)); // signed: -27
        const auto& tbl = decode_table();

        static constexpr int BLOCK = 8;
        int i = 0;
        for (; i + BLOCK + 1 <= datalen; i += BLOCK)
        {
            __m128i c16 = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(bytes + i));
            __m128i next1 = _mm_cvtsi32_si128(bytes[i + BLOCK]);
            c16 = _mm_or_si128(c16, _mm_slli_si128(next1, 8));

            __m128i cb = _mm_xor_si128(c16, c80);
            __m128i esc   = _mm_cmpgt_epi8(cb, cFC);   // ch >= 0x7D
            __m128i tilde = _mm_cmpgt_epi8(cb, cFD);   // ch >= 0x7E

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
            __m128i v = _mm_blendv_epi8(v_norm, v_esc, esc);   // SSE4.1 select

            int esc_bits = _mm_movemask_epi8(esc) & 0xFF;
            const int del = ((esc_bits << 1) & 0xFF) | carry;
            carry = (esc_bits >> 7) & 1;

            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[del].data()));
            __m128i v16 = _mm_unpacklo_epi8(v, v);       // duplicate low 8 bytes
            __m128i out16 = _mm_shuffle_epi8(v16, idx);  // SSSE3 compress
            out16 = _mm_add_epi8(out16, kf8);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += BLOCK - popcount8(del);
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
