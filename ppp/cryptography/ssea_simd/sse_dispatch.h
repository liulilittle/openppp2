#pragma once

#include "ssea_scalar_ref.h"
#include "base94_simd.h"
#include "ssea_simd.h"
#include "sse_impl_sse2.h"
#include "sse_impl_sse3.h"
#include "sse_impl_avx.h"
#include "sse_impl_avx2.h"

#include <cstdint>
#include <memory>

#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) || \
    (defined(__x86_64__) || defined(__i386__))
#define SSEA_X86 1
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#include <immintrin.h>
#endif
#endif

namespace ssea
{
    // -----------------------------------------------------------------------------
    // CPU instruction-set auto-detection and static dispatch.
    //
    // Design (matches the project's aesni precedent: compile-time gate + runtime
    // CPUID dispatch):
    //
    //   1. `ssea_cpu_level()` probes CPUID exactly ONCE (function-local static,
    //      thread-safe magic static) and caches the highest supported level:
    //      Scalar -> SSE2 -> SSSE3 -> SSE4_1 -> AVX2.
    //   2. `ssea_dispatch()` returns a function-pointer table for the DETECTED
    //      level. The table is also a function-local static: after the first
    //      call, every algorithm call goes directly through the pointers with
    //      no per-call detection overhead.
    //   3. `ssea_dispatch_for(level)` exposes every level's table (used by the
    //      benchmark to compare implementations side by side).
    //
    // Level rationale:
    //   * SSE2  - baseline for all x86-64 CPUs. base94 uses the hybrid route:
    //             SSE2 compute core + scalar gather (pshufb is SSSE3).
    //   * SSSE3 - adds pshufb: table-driven gather for base94 (the chosen
    //             production path).
    //   * SSE4_1- same 128-bit kernels + SSE4.1 conveniences (blendv, extract,
    //             min/max epu8); AVX (no 256-bit integer ops) maps to this table.
    //   * AVX2  - 256-bit kernels: vpshufb dual-block base94, dual-block delta,
    //             vpxor masked_xor, 8-word XOR batching for the LCG keystream.
    //   * scalar- everything else (shuffle/decimal/random_next) is level-
    //             independent and always scalar (arguments in docs/algorithms.md).
    // -----------------------------------------------------------------------------

    /**
     * @brief Highest supported SIMD level of the current CPU (cached).
     */
    enum class SimdLevel : int
    {
        Scalar = 0,   ///< No SIMD used (portable fallback)
        SSE2   = 1,   ///< SSE2 (x86-64 baseline)
        SSE3   = 2,   ///< SSE3 (LDDQU unaligned loads)
        SSSE3  = 3,   ///< SSSE3 (pshufb)
        SSE4_1 = 4,   ///< SSE4.1 (blendv, extract, min/max)
        SSE4_2 = 5,   ///< SSE4.2 (POPCNT)
        AVX    = 6,   ///< AVX (128-bit kernels, VEX encoding)
        AVX2   = 7,   ///< AVX2 (256-bit integer kernels)
    };

    /**
     * @brief Function-pointer table of the ssea algorithm suite for one level.
     */
    struct SseaFuncs
    {
        /// Base94 stream codec (variable-length printable-ASCII mapping).
        int (*base94_encode)(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept;
        int (*base94_decode)(const void* data, int datalen, int kf, std::unique_ptr<uint8_t[]>& output) noexcept;

        /// Delta coding (lossless, fixed length).
        int (*delta_encode)(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept;
        int (*delta_decode)(const void* data, int data_size, int kf, std::unique_ptr<uint8_t[]>& output) noexcept;

        /// XOR masking (in place).
        bool (*masked_xor)(const void* min, const void* max, int32_t kf) noexcept;
        bool (*masked_xor_random_next)(const void* min, const void* max, int32_t kf) noexcept;

        /// Byte permutation (in place).
        void (*shuffle_data)(char* encoded_data, int data_size, uint32_t key) noexcept;
        void (*unshuffle_data)(char* encoded_data, int data_size, uint32_t key) noexcept;
    };

    /**
     * @brief Raw CPUID probe (leaf, subleaf -> regs[4]).
     * @param leaf    CPUID leaf.
     * @param subleaf CPUID sub-leaf.
     * @param regs    [out] eax, ebx, ecx, edx.
     */
    inline void cpuid_probe(int leaf, int subleaf, int regs[4]) noexcept
    {
#if defined(SSEA_X86)
#if defined(_MSC_VER)
        int info[4];
        __cpuidex(info, leaf, subleaf);
        regs[0] = info[0];
        regs[1] = info[1];
        regs[2] = info[2];
        regs[3] = info[3];
#else
        __cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
#endif
#else
        (void)leaf;
        (void)subleaf;
        regs[0] = 0;
        regs[1] = 0;
        regs[2] = 0;
        regs[3] = 0;
#endif
    }

    /**
     * @brief Reads XCR0 (extended control register) via XGETBV.
     * @param index XCR index (0 = XFEATURE_ENABLED_MASK).
     * @return The 64-bit XCR value, or 0 when XGETBV is unavailable.
     */
    inline uint64_t xgetbv_probe(uint32_t index) noexcept
    {
#if defined(SSEA_X86)
#if defined(_MSC_VER)
        return _xgetbv(index);
#else
        uint32_t eax, edx;
        __asm__ __volatile__("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
        return (static_cast<uint64_t>(edx) << 32) | eax;
#endif
#else
        (void)index;
        return 0;
#endif
    }

    /**
     * @brief Detects the highest supported SIMD level (cached after first call).
     * @return The detected level.
     * @note  Thread-safe (C++11 magic static); the result never changes at
     *        runtime, so the cache is valid for the process lifetime.
     */
    inline SimdLevel ssea_cpu_level() noexcept
    {
        static const SimdLevel level = []() noexcept {
#if defined(SSEA_X86)
            int regs[4] = { 0, 0, 0, 0 };
            // Maximum basic leaf.
            cpuid_probe(0, 0, regs);
            const int max_basic = regs[0];
            if (max_basic < 1)
            {
                return SimdLevel::Scalar;
            }

            // Leaf 1: feature bits.
            cpuid_probe(1, 0, regs);
            const uint32_t ecx1 = static_cast<uint32_t>(regs[2]);
            const uint32_t edx1 = static_cast<uint32_t>(regs[3]);

            // SSE2: EDX bit 26.
            if (0 == (edx1 & (1u << 26)))
            {
                return SimdLevel::Scalar;   // x86-64 always has SSE2; 32-bit may not
            }

            // OS AVX state must be enabled before any AVX/AVX2 instruction:
            // OSXSAVE (ECX bit 27) + XGETBV XCR0 bits 1 (XMM) and 2 (YMM).
            const bool osxsave = (ecx1 & (1u << 27)) != 0;
            bool avx_usable = false;
            if (osxsave && (ecx1 & (1u << 28)))   // AVX bit
            {
                const uint64_t xcr0 = xgetbv_probe(0);
                avx_usable = (0 != (xcr0 & 0x6)); // bits 1 and 2
            }

            // SSE3: ECX bit 0.
            const bool sse3 = 0 != (ecx1 & (1u << 0));
            // SSSE3: ECX bit 9.
            const bool ssse3 = 0 != (ecx1 & (1u << 9));
            // SSE4.1: ECX bit 19.
            const bool sse4_1 = 0 != (ecx1 & (1u << 19));
            // SSE4.2: ECX bit 20.
            const bool sse4_2 = 0 != (ecx1 & (1u << 20));
            // POPCNT: ECX bit 23 (required by the SSE4.2 kernels).
            const bool popcnt = 0 != (ecx1 & (1u << 23));

            // AVX2: leaf 7, EBX bit 5 (requires AVX usable).
            bool avx2 = false;
            if (avx_usable && max_basic >= 7)
            {
                cpuid_probe(7, 0, regs);
                avx2 = 0 != (static_cast<uint32_t>(regs[1]) & (1u << 5));
            }

            if (avx2)
            {
                return SimdLevel::AVX2;
            }
            if (avx_usable)
            {
                return SimdLevel::AVX;
            }
            if (sse4_2 && popcnt)
            {
                return SimdLevel::SSE4_2;
            }
            if (sse4_1)
            {
                return SimdLevel::SSE4_1;
            }
            if (ssse3)
            {
                return SimdLevel::SSSE3;
            }
            if (sse3)
            {
                return SimdLevel::SSE3;
            }
            return SimdLevel::SSE2;
#else
            return SimdLevel::Scalar;
#endif
        }();
        return level;
    }

    /**
     * @brief Function table for an explicit level (benchmark/comparison use).
     * @param level Requested level.
     * @return The table for that level.
     * @note  AVX has no 256-bit integer instructions, so its table uses the
     *        same 128-bit kernels as SSE4.2 (VEX encoding is a compiler
     *        /arch:AVX concern). On GCC builds, a level whose instructions
     *        were NOT enabled at compile time falls back to the next lower
     *        level that WAS compiled (e.g. -msse2 only -> every SIMD level
     *        above SSE2 falls back to SSE2). On MSVC all intrinsics compile,
     *        so the runtime CPUID probe alone picks the level.
     */
    inline const SseaFuncs& ssea_dispatch_for(SimdLevel level) noexcept
    {
        // NOTE: shuffle/decimal/random_next are level-independent (scalar),
        // see docs/algorithms.md for the arguments.
        static const SseaFuncs k_scalar = {
            base94_encode_scalar,
            base94_decode_scalar,
            delta_encode_scalar,
            delta_decode_scalar,
            masked_xor_scalar,
            masked_xor_random_next_scalar,
            shuffle_data_scalar,
            unshuffle_data_scalar,
        };

        [[maybe_unused]] static const SseaFuncs k_sse2 = {
            base94_encode_sse2,        // hybrid: SSE2 compute core + scalar gather
            base94_decode_sse2,
            delta_encode_sse,
            delta_decode_sse,
            masked_xor_sse,
            masked_xor_random_next_sse,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_sse3 = {
            base94_encode_sse3,        // SSE2 hybrid kernels (64-bit loads)
            base94_decode_sse3,
            delta_encode_sse3,         // LDDQU loads
            delta_decode_sse3,
            masked_xor_sse3,
            masked_xor_random_next_sse3,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_ssse3 = {
            base94_encode_sse,         // SSSE3 pshufb table gather
            base94_decode_sse,
            delta_encode_sse3,
            delta_decode_sse3,
            masked_xor_sse3,
            masked_xor_random_next_sse3,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_sse4_1 = {
            base94_encode_sse4_1,      // 128-bit kernels + SSE4.1 conveniences
            base94_decode_sse4_1,
            delta_encode_sse3,
            delta_decode_sse3,
            masked_xor_sse3,
            masked_xor_random_next_sse3,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_sse4_2 = {
            base94_encode_sse4_2,      // + POPCNT
            base94_decode_sse4_2,
            delta_encode_sse3,
            delta_decode_sse3,
            masked_xor_sse3,
            masked_xor_random_next_sse3,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_avx = {
            base94_encode_avx,         // 128-bit kernels (VEX encoding)
            base94_decode_avx,
            delta_encode_avx,
            delta_decode_avx,
            masked_xor_avx,
            masked_xor_random_next_avx,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        [[maybe_unused]] static const SseaFuncs k_avx2 = {
            base94_encode_avx2,        // 256-bit dual-block kernels
            base94_decode_avx2,
            delta_encode_avx2,
            delta_decode_avx2,
            masked_xor_avx2,
            masked_xor_random_next_avx2,
            shuffle_data_opt,
            unshuffle_data_opt,
        };

        switch (level)
        {
        case SimdLevel::AVX2:
#if defined(SSEA_AVX2)
            return k_avx2;
#else
            return ssea_dispatch_for(SimdLevel::AVX);
#endif
        case SimdLevel::AVX:
#if defined(SSEA_AVX)
            return k_avx;
#else
            return ssea_dispatch_for(SimdLevel::SSE4_2);
#endif
        case SimdLevel::SSE4_2:
#if defined(SSEA_SSE4_2)
            return k_sse4_2;
#else
            return ssea_dispatch_for(SimdLevel::SSE4_1);
#endif
        case SimdLevel::SSE4_1:
#if defined(SSEA_SSE4_1)
            return k_sse4_1;
#else
            return ssea_dispatch_for(SimdLevel::SSSE3);
#endif
        case SimdLevel::SSSE3:
#if defined(BASE94_SSSE3)
            return k_ssse3;
#else
            return ssea_dispatch_for(SimdLevel::SSE3);
#endif
        case SimdLevel::SSE3:
#if defined(SSEA_SSE3)
            return k_sse3;
#else
            return ssea_dispatch_for(SimdLevel::SSE2);
#endif
        case SimdLevel::SSE2:
#if defined(SSEA_X86)
            return k_sse2;
#else
            return ssea_dispatch_for(SimdLevel::Scalar);
#endif
        case SimdLevel::Scalar:
            return k_scalar;
        }
        return k_scalar;
    }

    // -----------------------------------------------------------------------------
    // Per-algorithm BEST-LEVEL combination.
    //
    // Instead of dispatching the WHOLE library at one level, each algorithm
    // picks its OWN fastest instruction set (measured, see docs/performance.md),
    // falling back to the next preference when the CPU does not support it:
    //
    //   base94_encode          AVX2 -> SSE4.1 -> SSE4.2 -> SSSE3 -> AVX -> SSE2 -> SSE3 -> Scalar
    //                          (measured: 2203 > 2043 > 2033 > 2019 > 2014 > 701 > 639 > 364 MB/s)
    //   base94_decode          SSSE3 -> SSE4.1 -> AVX -> SSE4.2 -> SSE2 -> SSE3 -> Scalar
    //                          (AVX2 is MEASURED SLOWER (644 vs 714 MB/s) and is
    //                           therefore never selected; 714 > 704 > 701 > 686 > 379 > 359 > 361)
    //   delta_encode           AVX2 -> SSE2 -> SSE3 -> SSE4.2 -> AVX -> SSE4.1 -> SSSE3 -> Scalar
    //                          (30048 > 27328 > 25832 > 24724 > 24493 > 23584 > 23354 > 2335)
    //   delta_decode           AVX2 -> SSE2 -> AVX -> SSE4.2 -> SSSE3 -> SSE4.1 -> SSE3 -> Scalar
    //                          (6025 > 5560 > 5596 > 5587 > 5564 > 5558 > 5516 > 691)
    //   masked_xor             AVX2 -> Scalar -> SSE2 -> AVX -> SSE3 -> SSSE3 -> SSE4_1 -> SSE4_2
    //                          (154967 > 78542 [auto-vectorized] > 67069 > 40821 > 40104 > ...)
    //   masked_xor_random_next any level (keystream-bound, ~1.4 GB/s everywhere) -> highest detected
    //   shuffle / unshuffle    Scalar (+power-of-two AND) - SIMD not applicable (argued)
    //
    // The compile-time fallback chain inside ssea_dispatch_for() covers GCC
    // builds compiled with a limited -m flag set: a preferred level that was
    // NOT compiled in degrades to the highest compiled level.
    // -----------------------------------------------------------------------------

    /// base94_encode preference, fastest first (docs/performance.md section 2).
    static constexpr SimdLevel k_base94_encode_pref[] = {
        SimdLevel::AVX2, SimdLevel::SSE4_1, SimdLevel::SSE4_2, SimdLevel::SSSE3,
        SimdLevel::AVX, SimdLevel::SSE2, SimdLevel::SSE3, SimdLevel::Scalar,
    };

    /// base94_decode preference, fastest first. AVX2 is intentionally absent
    /// (measured slower than SSSE3; a CPU with AVX2 always has SSSE3 too).
    static constexpr SimdLevel k_base94_decode_pref[] = {
        SimdLevel::SSSE3, SimdLevel::SSE4_1, SimdLevel::AVX, SimdLevel::SSE4_2,
        SimdLevel::SSE2, SimdLevel::SSE3, SimdLevel::Scalar,
    };

    /// delta_encode preference, fastest first.
    static constexpr SimdLevel k_delta_encode_pref[] = {
        SimdLevel::AVX2, SimdLevel::SSE2, SimdLevel::SSE3, SimdLevel::SSE4_2,
        SimdLevel::AVX, SimdLevel::SSE4_1, SimdLevel::SSSE3, SimdLevel::Scalar,
    };

    /// delta_decode preference, fastest first.
    static constexpr SimdLevel k_delta_decode_pref[] = {
        SimdLevel::AVX2, SimdLevel::SSE2, SimdLevel::AVX, SimdLevel::SSE4_2,
        SimdLevel::SSSE3, SimdLevel::SSE4_1, SimdLevel::SSE3, SimdLevel::Scalar,
    };

    /// masked_xor preference, fastest first. Scalar ranks SECOND because MSVC
    /// auto-vectorizes it (78542 MB/s) above every 128-bit SIMD level (~40 GB/s).
    static constexpr SimdLevel k_masked_xor_pref[] = {
        SimdLevel::AVX2, SimdLevel::Scalar, SimdLevel::SSE2, SimdLevel::AVX,
        SimdLevel::SSE3, SimdLevel::SSSE3, SimdLevel::SSE4_1, SimdLevel::SSE4_2,
    };

    /// masked_xor_random_next preference: keystream-bound (~1.4 GB/s at every
    /// level), so any level works; prefer the highest detected one.
    static constexpr SimdLevel k_masked_xor_random_next_pref[] = {
        SimdLevel::AVX2, SimdLevel::AVX, SimdLevel::SSE4_2, SimdLevel::SSE4_1,
        SimdLevel::SSSE3, SimdLevel::SSE3, SimdLevel::SSE2, SimdLevel::Scalar,
    };

    /**
     * @brief Selects the implementation for one algorithm: the first preference
     *        level the CPU supports (compile-time fallback chain included).
     * @tparam Getter  Extracts the function pointer from a level table.
     * @param cpu      Detected CPU level.
     * @param pref     Preference list, fastest first (level order).
     * @param n        Number of preference entries.
     * @param get      Table -> pointer extractor.
     * @return The pointer of the best supported level for this algorithm.
     */
    template <typename Getter>
    static auto pick_best_impl(SimdLevel cpu, const SimdLevel* pref, int n, Getter get) noexcept
    {
        for (int i = 0; i < n; i++)
        {
            if (static_cast<int>(pref[i]) <= static_cast<int>(cpu))
            {
                return get(ssea_dispatch_for(pref[i]));
            }
        }
        return get(ssea_dispatch_for(SimdLevel::Scalar));
    }

    /**
     * @brief The per-algorithm BEST-LEVEL function table for this CPU (cached).
     *
     * Every algorithm independently selects its measured-fastest instruction
     * set; when the CPU does not support a preference, it falls back to the
     * next one (and, on GCC builds, to the highest level compiled in).
     *
     * @return Table whose pointers are already selected; no per-call
     *         detection cost afterwards.
     */
    inline const SseaFuncs& ssea_dispatch() noexcept
    {
        static const SseaFuncs best = []() noexcept {
            const SimdLevel cpu = ssea_cpu_level();
            SseaFuncs f;
            f.base94_encode = pick_best_impl(cpu, k_base94_encode_pref,
                static_cast<int>(sizeof(k_base94_encode_pref) / sizeof(k_base94_encode_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.base94_encode; });
            f.base94_decode = pick_best_impl(cpu, k_base94_decode_pref,
                static_cast<int>(sizeof(k_base94_decode_pref) / sizeof(k_base94_decode_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.base94_decode; });
            f.delta_encode = pick_best_impl(cpu, k_delta_encode_pref,
                static_cast<int>(sizeof(k_delta_encode_pref) / sizeof(k_delta_encode_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.delta_encode; });
            f.delta_decode = pick_best_impl(cpu, k_delta_decode_pref,
                static_cast<int>(sizeof(k_delta_decode_pref) / sizeof(k_delta_decode_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.delta_decode; });
            f.masked_xor = pick_best_impl(cpu, k_masked_xor_pref,
                static_cast<int>(sizeof(k_masked_xor_pref) / sizeof(k_masked_xor_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.masked_xor; });
            f.masked_xor_random_next = pick_best_impl(cpu, k_masked_xor_random_next_pref,
                static_cast<int>(sizeof(k_masked_xor_random_next_pref) / sizeof(k_masked_xor_random_next_pref[0])),
                [](const SseaFuncs& t) noexcept { return t.masked_xor_random_next; });
            f.shuffle_data = shuffle_data_opt;
            f.unshuffle_data = unshuffle_data_opt;
            return f;
        }();
        return best;
    }
}
