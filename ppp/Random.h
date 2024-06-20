#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    struct Random {
    private:
        int                                 SeedArray[56];
        int                                 Seed   = 0;
        int                                 inext  = 0;
        int                                 inextp = 0;

    public:
        Random() noexcept;
        Random(int seed) noexcept;

    public:
        int&                                GetSeed() noexcept;
        void                                SetSeed(int seed) noexcept;
        static uint64_t                     GetTickCount() noexcept;
        
    public:     
        int                                 Next() noexcept;
        double                              NextDouble() noexcept;
        int                                 Next(int minValue, int maxValue) noexcept;
    };
}