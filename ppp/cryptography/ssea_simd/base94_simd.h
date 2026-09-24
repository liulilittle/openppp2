#pragma once

#include "ssea_scalar_ref.h"

#include <array>
#include <cstdint>

#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) || \
    (defined(__x86_64__) || defined(__i386__))
#define BASE94_X86 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>
#endif
#endif

#if defined(BASE94_X86) && (defined(_MSC_VER) || defined(__SSSE3__))
#define BASE94_SSSE3 1
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // Table-driven SIMD design (SSSE3 pshufb), see docs/plan.md (EN) and
    // docs/algorithms_CN.md (CN) for the full feasibility argument.
    //
    // Notes:
    //   * encode: escape first char is always '}' (0x7D) or '~' (0x7E), because
    //     b/93 in {1,2} for b in [93,255]; hi = 0x7D + (b >= 186),
    //     lo = b - 93*(b>=93) - 93*(b>=186). No division needed.
    //   * decode: escape start iff ch >= 0x7D; pair value = 93 + 93*(ch>=0x7E)
    //     + next - 0x20. Output position per char = i - popcount(escapes before i).
    //   * The variable-length expand (encode) / compress (decode) is a byte gather.
    //     Pure SSE2 has NO byte-level arbitrary permutation (pshufb is SSSE3);
    //     therefore the gather is one pshufb indexed by a precomputed 256-entry
    //     table keyed by the 8-bit mask of which bytes expand / are deleted.
    //
    // Correctness: every path here is verified byte-for-byte identical to the
    // scalar reference (ssea_scalar_ref.h) for EVERY input length 1..65535,
    // plus boundary combos (1679616 encode / 1024 decode / 10077696 roundtrip),
    // all scalar error paths, canary (out-of-bounds) guards, unaligned offsets
    // and multiple kf values - see tests/test_base94.cpp.
    // -----------------------------------------------------------------------------

    /**
     * @brief Returns the 8-bit popcount of a byte using a small LUT.
     * @param x Input byte.
     * @return Number of set bits (0..8).
     */
    inline int popcount8(uint32_t x) noexcept
    {
        static const std::array<uint8_t, 256> pc = [] {
            std::array<uint8_t, 256> t{};
            for (int i = 0; i < 256; i++)
            {
                int c = 0;
                for (int b = 0; b < 8; b++)
                {
                    c += (i >> b) & 1;
                }
                t[i] = static_cast<uint8_t>(c);
            }
            return t;
        }();
        return pc[x & 0xFF];
    }

    /**
     * @brief 256-entry x 16-byte pshufb index table for encode expansion.
     *        ENCODE_EXPAND_TABLE[mask][j] = source byte inside the unpacked
     *        [hi0,lo0,hi1,lo1,...] pair vector; mask bit i set => 2-char pair i.
     *        Scalar order per byte is [hi, lo] (escape char first, remainder last).
     */
    inline const std::array<std::array<uint8_t, 16>, 256>& encode_table() noexcept
    {
        static const std::array<std::array<uint8_t, 16>, 256> t = [] {
            std::array<std::array<uint8_t, 16>, 256> t{};
            for (int m = 0; m < 256; m++)
            {
                int j = 0;
                for (int i = 0; i < 8; i++)
                {
                    if ((m >> i) & 1)
                    {
                        t[m][j++] = static_cast<uint8_t>(2 * i);      // hi char first (2-char)
                    }
                    t[m][j++] = static_cast<uint8_t>(2 * i + 1);      // lo char always last
                }
                for (; j < 16; j++)
                {
                    t[m][j] = 0;                                       // garbage, truncated by length
                }
            }
            return t;
        }();
        return t;
    }

    /**
     * @brief 256-entry x 16-byte pshufb index table for decode compression.
     *        DECODE_COMPRESS_TABLE[mask][j] = source byte inside the duplicated
     *        value vector v16 = unpacklo_epi8(v, v) = [v0,v0,v1,v1,...]; even
     *        indices 2*i select v[i]. mask bit i set => char i is deleted
     *        (escape continuation).
     */
    inline const std::array<std::array<uint8_t, 16>, 256>& decode_table() noexcept
    {
        static const std::array<std::array<uint8_t, 16>, 256> t = [] {
            std::array<std::array<uint8_t, 16>, 256> t{};
            for (int m = 0; m < 256; m++)
            {
                int j = 0;
                for (int i = 0; i < 8; i++)
                {
                    if (0 == ((m >> i) & 1))
                    {
                        t[m][j++] = static_cast<uint8_t>(2 * i);
                    }
                }
                for (; j < 16; j++)
                {
                    t[m][j] = 0;
                }
            }
            return t;
        }();
        return t;
    }

    /**
     * @brief Encodes binary bytes with the Base94 mapping, scalar LUT variant
     *        (division-free, branch-light). Output matches base94_encode_scalar.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     */
    inline int base94_encode_lut(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }

        static const std::array<uint8_t, 256> len_tbl = [] {
            std::array<uint8_t, 256> t{};
            for (int i = 0; i < 256; i++)
            {
                t[i] = static_cast<uint8_t>((i >= BASE93_RADIX) ? 2 : 1);
            }
            return t;
        }();

        int outlen = 0;
        for (int i = 0; i < datalen; i++)
        {
            outlen += len_tbl[static_cast<uint8_t>(bytes[i] - kf)];
        }

        output = std::make_unique<uint8_t[]>(outlen + 16);
        uint8_t* p = output.get();
        for (int i = 0; i < datalen; i++)
        {
            const uint8_t b = static_cast<uint8_t>(bytes[i] - kf);
            if (b >= BASE93_RADIX)
            {
                *p++ = static_cast<uint8_t>(0x20 + b / BASE93_RADIX + 92);
                *p++ = static_cast<uint8_t>(0x20 + b % BASE93_RADIX);
            }
            else
            {
                *p++ = static_cast<uint8_t>(0x20 + b);
            }
        }

        return outlen;
    }

    /**
     * @brief Encodes binary bytes with the Base94 mapping using SSSE3 pshufb + tables.
     *        Output matches base94_encode_scalar byte-for-byte.
     * @param data    Input bytes (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted before mapping.
     * @param output  [out] Encoded buffer (allocated with +16 slack).
     * @return Encoded byte count, or 0 on failure.
     * @note  Requires SSSE3 (all x86-64 CPUs since 2006); falls back to 0 elsewhere.
     */
    inline int base94_encode_sse(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(BASE94_SSSE3)
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
                b8 = _mm_sub_epi8(b8, kf8);                       // b = byte - kf (mod 256)

                __m128i biased = _mm_xor_si128(b8, c80);          // bias for unsigned compare
                __m128i L1 = _mm_cmpgt_epi8(biased, cDC);         // b >= 93
                __m128i L2 = _mm_cmpgt_epi8(biased, c39);         // b >= 186

                __m128i lo = _mm_sub_epi8(b8, _mm_and_si128(L1, c93));
                lo = _mm_sub_epi8(lo, _mm_and_si128(L2, c93));    // lo = b % 93
                lo = _mm_add_epi8(lo, c20);                       // lo = 0x20 + b % 93

                __m128i hi = _mm_add_epi8(c7D, _mm_and_si128(L2, one)); // '}' or '~'

                __m128i ex = _mm_unpacklo_epi8(hi, lo);           // [hi0,lo0,hi1,lo1,...]

            const int mask = _mm_movemask_epi8(L1) & 0xFF;    // bit i = 2-char pair i (b >= 93)
            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[mask].data()));
            __m128i out16 = _mm_shuffle_epi8(ex, idx);        // SSSE3 gather

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += 8 + popcount8(mask);
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
     * @brief Decodes bytes produced by base94_encode using SSSE3 pshufb + tables.
     *        Output matches base94_decode_scalar byte-for-byte, including the error
     *        paths (returns 0 for any invalid input the scalar rejects).
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Decoded buffer (allocated with +16 slack).
     * @return Decoded byte count, or 0 on invalid input.
     * @note  Requires SSSE3; falls back to 0 elsewhere.
     */
    inline int base94_decode_sse(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(BASE94_SSSE3)
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        if (nullptr == bytes || datalen < 1)
        {
            return 0;
        }

        // Small inputs: use the scalar reference directly (SIMD overhead exceeds
        // benefit below 16 bytes; error semantics stay trivially exact).
        if (datalen < 16)
        {
            return base94_decode_scalar(data, datalen, kf, output);
        }

        // Compute the decoded length: each escape pair consumes 2 chars, emits 1 byte.
        int outlen = datalen;
        for (int i = 0; i < datalen; i++)
        {
            if (bytes[i] >= 0x7D)
            {
                outlen--;   // pair: 2 input chars -> 1 output byte
                i++;        // skip the continuation char
            }
        }

        output = std::make_unique<uint8_t[]>(outlen + 16);
        uint8_t* out = output.get();
        int op = 0;
        int carry = 0;   // previous block's escape at position 7 deletes next block's char 0

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
        for (; i + BLOCK + 1 <= datalen; i += BLOCK)   // +1: cross-block pair needs next char
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

            // Inline validation of the 8 chars AND their escape continuations:
            //   bad:      ch < 0x20 or ch > 0x7E
            //   bad_next: next < 0x20 or next > 0x7E
            //   ovf:      esc && (next >= 0x7E) || (tilde && next > 0x65)
            // Any violation falls back to the scalar reference (exact error code path).
            __m128i bad = _mm_or_si128(_mm_cmpgt_epi8(cA0, cb), _mm_cmpgt_epi8(cb, cFE));
            __m128i bad_n = _mm_or_si128(_mm_cmpgt_epi8(cA0, nb), _mm_cmpgt_epi8(nb, cFE));
            __m128i next_esc = _mm_cmpgt_epi8(nb, cFD);  // next >= 0x7E
            __m128i next_hi  = _mm_cmpgt_epi8(nb, cE5);  // next > 0x65 (next_off > 69)
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

            // delete mask: each escape pair deletes ONLY its continuation char,
            // i.e. del = esc << 1 | carry (previous block's bit 7 deletes this
            // block's char 0). The escape-start char itself keeps its value.
            int esc_bits = _mm_movemask_epi8(esc) & 0xFF;
            int del = ((esc_bits << 1) & 0xFF) | carry;
            carry = (esc_bits >> 7) & 1;

            __m128i idx = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tbl[del].data()));
            __m128i v16 = _mm_unpacklo_epi8(v, v);       // duplicate low 8 bytes
            __m128i out16 = _mm_shuffle_epi8(v16, idx);  // SSSE3 compress
            out16 = _mm_add_epi8(out16, kf8);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out + op), out16);
            op += BLOCK - popcount8(del);
        }

        // Scalar validation of the tail (< BLOCK+1 chars) with full scalar
        // semantics: range checks, escape continuation bounds, truncated escape.
        // The first char is skipped when the previous block's escape at position
        // 7 consumed it (carry).
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
                if (off > BASE93_RADIX)   // second char offset > 93
                {
                    return base94_decode_scalar(data, datalen, kf, output);
                }
                if (c == 0x7E && off > 69)  // '~' + next_off > 69 -> v > 255
                {
                    return base94_decode_scalar(data, datalen, kf, output);
                }
            }
        }

        // Scalar tail: exact scalar semantics for the remaining chars.
        i += carry;   // skip the char consumed by the previous block's escape at 7
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
