#pragma once

#include "ssea_scalar_ref.h"
#include "base94_simd.h"
#include "sse_impl_sse2.h"
#include "sse_impl_sse3.h"

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

#if defined(SSEA_X86) && (defined(_MSC_VER) || defined(__AVX__))
#define SSEA_AVX 1
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // AVX (first-generation) layer.
    //
    // WHY THE KERNELS ARE THE SAME AS SSE4.2:
    // First-generation AVX (Sandy Bridge) has NO 256-bit INTEGER instructions.
    // The 256-bit integer instructions used by the AVX2 layer (vpsubb, vpcmpgtb,
    // vpand, vpshufb, vpslldq, vpxor, ...) only arrived with AVX2 (Haswell).
    // AVX extends the floating-point and load/store domain to 256 bits (vaddps,
    // vmovups, ...) but keeps every integer SIMD operation at 128 bits. There is
    // therefore no 256-bit integer kernel to implement here: the AVX layer runs
    // the SAME 128-bit kernels as the SSE4.2 layer.
    //
    // THE ONLY DIFFERENCE IS INSTRUCTION ENCODING:
    // When the compiler is told /arch:AVX (MSVC) or -mavx (GCC/Clang) it emits
    // the VEX-prefixed form of the very same 128-bit instructions (vpxor, vpand,
    // vpshufb, ...). VEX encoding is non-destructive (three-operand form), which
    // lets the register allocator drop the register-to-register movs that the
    // legacy two-operand SSE encoding requires. The instruction stream differs;
    // the computed results do not.
    //
    // WHY THIS LAYER EXISTS (CPU-DETECTION COVERAGE):
    // The dispatch probe in sse_dispatch.h classifies each machine into one of
    // Scalar / SSE2 / SSSE3 / SSE4_1 / AVX / AVX2. A large population of older
    // CPUs (Sandy Bridge, Ivy Bridge, some VIA/Zhaoxin parts) reports AVX but
    // NOT AVX2. Those machines must not run 256-bit kernels, and the AVX layer
    // gives them a distinct, correctly-named dispatch slot whose kernels are the
    // proven 128-bit ones.
    //
    // ROUTING (per algorithm family):
    //   base94 encode/decode   -> SSE4.2 level (the highest 128-bit base94
    //                             kernel; adds the POPCNT output popcount).
    //   delta encode/decode    -> SSE3 level (LDDQU unaligned 128-bit loads;
    //                             SSE3 instructions are a strict subset of AVX,
    //                             so they are always available here).
    //   masked_xor(+random)    -> SSE3 level (same LDDQU load variant).
    //
    // CORRECTNESS:
    // Every forwarding target is itself verified byte-for-byte against the
    // scalar reference over every input length and kf value, see
    // tests/test_dispatch.cpp (verify_table compares encode/decode/delta/masked
    // output to the *_scalar implementations). The AVX wrappers add no logic of
    // their own and therefore preserve that guarantee exactly.
    // -----------------------------------------------------------------------------

    /**
     * @brief Encodes binary bytes with the Base94 mapping (AVX level).
     *        AVX adds no 256-bit integer instructions, so this layer reuses the
     *        128-bit SSE4.2 kernel unchanged; only the VEX instruction encoding
     *        differs, and the encoding choice is made by the compiler /arch flag
     *        (/arch:AVX on MSVC, -mavx on GCC/Clang), never by this wrapper.
     *        The result is byte-for-byte identical to base94_encode_scalar and
     *        to every other level (tests/test_dispatch.cpp).
     * @param data    Input bytes to encode (datalen >= 1).
     * @param datalen Number of input bytes.
     * @param kf      Per-byte offset subtracted from every byte before the
     *                Base94 mapping.
     * @param output  [out] Unique pointer to the encoded buffer; it is assigned
     *                a freshly allocated array with +16 slack bytes (see the
     *                +16 slack convention in sse_impl_sse2.h).
     * @return Encoded byte count on success (always >= datalen), or 0 when the
     *         input pointer is null or datalen is below 1.
     */
    inline int base94_encode_avx(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX)
        return base94_encode_sse4_2(data, datalen, kf, output);
#else
        (void)data;
        (void)datalen;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Decodes bytes produced by base94_encode (AVX level).
     *        Forwards to the 128-bit SSE4.2 kernel; same reasoning as
     *        base94_encode_avx (AVX has no 256-bit integer instructions, so the
     *        128-bit kernel is the correct one, only the VEX encoding differs).
     *        Every validation and error path is inherited unchanged, so the
     *        wrapper rejects invalid input exactly as the scalar reference does.
     * @param data    Encoded Base94 byte sequence (datalen >= 1).
     * @param datalen Number of encoded input bytes.
     * @param kf      Per-byte offset added back after decoding.
     * @param output  [out] Unique pointer to the decoded buffer; it is assigned
     *                a freshly allocated array with +16 slack bytes.
     * @return Decoded byte count on success, or 0 on invalid input (also when
     *         the input pointer is null or datalen is below 1).
     */
    inline int base94_decode_avx(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX)
        return base94_decode_sse4_2(data, datalen, kf, output);
#else
        (void)data;
        (void)datalen;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Delta-encodes a byte sequence (AVX level).
     *        Forwards to delta_encode_sse3, which uses the SSE3 LDDQU unaligned
     *        128-bit load instruction for the block loop. LDDQU is a strict
     *        subset of the AVX ISA (AVX includes every SSE3 instruction), so
     *        using the SSE3 delta kernel at the AVX dispatch level is always
     *        valid and keeps a single 128-bit kernel per algorithm.
     * @param data      Input bytes to delta-encode (data_size >= 1).
     * @param data_size Number of input bytes; also the returned encoded size
     *                  (delta coding is fixed length).
     * @param kf        Initial adjustment used for the first byte (in[-1]).
     * @param output    [out] Unique pointer to the encoded buffer; it is assigned
     *                  a freshly allocated array with +16 slack bytes.
     * @return data_size on success, or 0 on failure (null pointer or data_size
     *         below 1).
     */
    inline int delta_encode_avx(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX)
        return delta_encode_sse3(data, data_size, kf, output);
#else
        (void)data;
        (void)data_size;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief Delta-decodes a byte sequence (AVX level).
     *        Forwards to delta_decode_sse3, the SSE3 LDDQU prefix-sum kernel.
     *        AVX includes every SSE3 instruction, so the SSE3 kernel is the
     *        correct 128-bit choice at this dispatch level (see the layer
     *        comment at the top of this file).
     * @param data      Delta-encoded bytes (data_size >= 1).
     * @param data_size Number of input bytes; also the returned decoded size.
     * @param kf        Initial adjustment that was used at encode time.
     * @param output    [out] Unique pointer to the decoded buffer; it is assigned
     *                  a freshly allocated array with +16 slack bytes.
     * @return data_size on success, or 0 on failure (null pointer or data_size
     *         below 1).
     */
    inline int delta_decode_avx(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept
    {
#if defined(SSEA_AVX)
        return delta_decode_sse3(data, data_size, kf, output);
#else
        (void)data;
        (void)data_size;
        (void)kf;
        (void)output;
        return 0;
#endif
    }

    /**
     * @brief XOR-masks a memory range with a fixed 32-bit key (AVX level).
     *        Forwards to masked_xor_sse3, whose block loop uses the SSE3 LDDQU
     *        unaligned 128-bit load/store variant. The XOR masking is byte-for-
     *        byte identical to masked_xor_scalar (tests/test_dispatch.cpp).
     * @param min Inclusive start address of the range to mask (may be unaligned).
     * @param max Exclusive end address of the range.
     * @param kf  Fixed 32-bit XOR key applied to every 32-bit word.
     * @return true on success (including the zero-length range), false when the
     *         range is invalid (max < min).
     */
    inline bool masked_xor_avx(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_AVX)
        return masked_xor_sse3(min, max, kf);
#else
        (void)min;
        (void)max;
        (void)kf;
        return false;
#endif
    }

    /**
     * @brief XOR-masks a memory range with a per-word LCG keystream (AVX level).
     *        Forwards to masked_xor_random_next_sse3, which keeps the non-linear
     *        fold keystream scalar and batches the XOR with the SSE3 LDDQU load
     *        variant. The in-place result is byte-for-byte identical to
     *        masked_xor_random_next_scalar (tests/test_dispatch.cpp).
     * @param min Inclusive start address of the range to mask (may be unaligned).
     * @param max Exclusive end address of the range.
     * @param kf  Initial key factor used to seed the LCG keystream.
     * @return true on success (including the zero-length range), false when the
     *         range is invalid (max < min).
     */
    inline bool masked_xor_random_next_avx(const void* min, const void* max, int32_t kf) noexcept
    {
#if defined(SSEA_AVX)
        return masked_xor_random_next_sse3(min, max, kf);
#else
        (void)min;
        (void)max;
        (void)kf;
        return false;
#endif
    }
}
