#pragma once

#include <ppp/stdafx.h>

/**
 * @file Random.h
 * @brief Declares a deterministic pseudo-random number generator utility.
 */

namespace ppp {
    /**
     * @brief Lightweight pseudo-random number generator with configurable seed.
     */
    class Random {
    private:
        /** @brief Internal state table used by the generator algorithm. */
        int                                 SeedArray[56];
        /** @brief Current seed/state value. */
        int                                 Seed   = 0;
        /** @brief First rolling index into the seed table. */
        int                                 inext  = 0;
        /** @brief Second rolling index into the seed table. */
        int                                 inextp = 0;

        /** @brief Rebuilds the state table from the current seed value. */
        void                                InitializeSeedTable() noexcept;

    public:
        /** @brief Constructs generator seeded with current tick count. */
        Random() noexcept;
        /** @brief Constructs generator with an explicit seed value. */
        Random(int seed) noexcept;
        /** @brief Destroys the generator instance. */
        virtual ~Random() noexcept = default;

    public:
        /** @brief Gets mutable reference to the current seed value. */
        int&                                GetSeed() noexcept;
        /** @brief Sets the current seed value used by the generator. */
        void                                SetSeed(int seed) noexcept;
        /** @brief Gets a monotonic tick value for default seeding. */
        static uint64_t                     GetTickCount() noexcept;
        
    public:     
        /** @brief Generates the next non-negative pseudo-random integer. */
        int                                 Next() noexcept;
        /** @brief Generates the next pseudo-random floating-point value. */
        double                              NextDouble() noexcept;
        /** @brief Generates a pseudo-random integer within a range. */
        int                                 Next(int minValue, int maxValue) noexcept;
    };
}
