#include <ppp/stdafx.h>
#include <ppp/Random.h>
#include <ppp/threading/Executors.h>

/**
 * @file Random.cpp
 * @brief Implements deterministic pseudo-random number generation routines.
 */

namespace ppp {
    namespace {
        int SubtractInt32Unchecked(int left, int right) noexcept {
            const uint32_t wrapped = static_cast<uint32_t>(left) -
                static_cast<uint32_t>(right);
            return wrapped <= static_cast<uint32_t>(INT_MAX)
                ? static_cast<int>(wrapped)
                : static_cast<int>(static_cast<int64_t>(wrapped) - (INT64_C(1) << 32));
        }
    }

    /**
     * @brief Constructs a random generator using tick count as seed.
     */
    Random::Random() noexcept
        : Random(GetTickCount()) {

    }
    
    /**
     * @brief Constructs a random generator with an explicit seed.
     * @param seed Initial seed value.
     */
    Random::Random(int seed) noexcept
        : Seed(seed)
        , inext(0)
        , inextp(0) {
        memset(SeedArray, 0, sizeof(SeedArray));
        InitializeSeedTable();
    }

    /**
     * @brief Gets mutable access to the current seed value.
     * @return Reference to internal seed state.
     */
    int& Random::GetSeed() noexcept {
        return Seed;
    }

    /**
     * @brief Replaces the current seed value.
     * @param seed New seed state.
     */
    void Random::SetSeed(int seed) noexcept {
        Seed = seed;
        InitializeSeedTable();
    }

    /**
     * @brief Retrieves a tick count used for default random seeding.
     * @return Current tick count value.
     */
    uint64_t Random::GetTickCount() noexcept {
        return ppp::threading::Executors::GetTickCount();
    }

    /**
     * @brief Rebuilds the state table from the current seed using the
     *        seed-diffusion procedure of the underlying subtractive generator.
     */
    void Random::InitializeSeedTable() noexcept {
        int num = (Seed == INT_MIN) ? INT_MAX : abs(Seed);
        int num2 = 161803398 - num;
        SeedArray[55] = num2;

        int num3 = 1;
        for (int i = 1; i < 55; i++) {
            int num4 = 21 * i % 55;
            SeedArray[num4] = num3;

            num3 = SubtractInt32Unchecked(num2, num3);
            if (num3 < 0) {
                num3 += INT_MAX;
            }

            num2 = SeedArray[num4];
        }

        for (int j = 1; j < 5; j++) {
            for (int k = 1; k < 56; k++) {
                SeedArray[k] = SubtractInt32Unchecked(
                    SeedArray[k], SeedArray[1 + (k + 30) % 55]);
                if (SeedArray[k] < 0) {
                    SeedArray[k] += INT_MAX;
                }
            }
        }

        inext = 0;
        inextp = 21;
    }

    /**
     * @brief Generates the next pseudo-random integer and advances internal state.
     * @return Next generated pseudo-random integer.
     */
    int Random::Next() noexcept {
        do {
            /**
             * @brief Produces one value from the rolling subtractive generator state.
             */
            int num = inext;
            int num2 = inextp;
            if (++num >= 56) {
                num = 1;
            }

            if (++num2 >= 56) {
                num2 = 1;
            }

            int num3 = SeedArray[num] - SeedArray[num2];
            if (num3 == INT_MAX) {
                num3--;
            }

            if (num3 < 0) {
                num3 += INT_MAX;
            }

            SeedArray[num] = num3;
            inext = num;
            inextp = num2;
            Seed = num3;
        } while (false);
        return Seed;
    }

    /**
     * @brief Generates a pseudo-random double using two integer samples.
     * @return Pseudo-random floating-point value in an algorithm-defined interval.
     */
    double Random::NextDouble() noexcept {
        int num = Next();
        if ((Next() % 2 == 0) ? true : false) {
            num = -num;
        }

        double num2 = num;
        num2 += 2147483646.0;
        return num2 / 4294967293.0;
    }

    /**
     * @brief Generates a pseudo-random integer in the range [minValue, maxValue).
     * @param minValue Inclusive lower bound.
     * @param maxValue Exclusive upper bound.
     * @return Generated pseudo-random integer clamped to input semantics.
     */
    int Random::Next(int minValue, int maxValue) noexcept { /* MSDN: https://learn.microsoft.com/en-us/dotnet/api/system.random.next?view=net-7.0 */
        if (minValue == maxValue) { /* The Next(Int32) overload returns random integers that range from 0 to maxValue - 1.  However, if maxValue is 0, the method returns 0. */
            return minValue;
        }

        if (minValue > maxValue) {
            maxValue = minValue;
        }

        long long num = (long long)maxValue - (long long)minValue;
        if (num <= INT_MAX) {
            return (int)(((double)Next() * 4.6566128752457969E-10) * (double)num) + minValue;
        }

        return (int)((long long)(NextDouble() * (double)num) + minValue);
    }
}
