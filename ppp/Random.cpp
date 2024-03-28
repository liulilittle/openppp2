#include <ppp/stdafx.h>
#include <ppp/Random.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    Random::Random() noexcept
        : Random(GetTickCount()) {

    }
    
    Random::Random(int seed) noexcept
        : Seed(seed)
        , inext(0)
        , inextp(0) {
        memset(SeedArray, 0, sizeof(SeedArray));
    }

    int& Random::GetSeed() noexcept {
        return Seed;
    }

    void Random::SetSeed(int seed) noexcept {
        Seed = seed;
    }

    uint64_t Random::GetTickCount() noexcept {
        return ppp::threading::Executors::GetTickCount();
    }

    int Random::Next() noexcept {
        do {
            int num = (Seed == INT_MIN) ? INT_MAX : abs(Seed);
            int num2 = 161803398 - num;
            SeedArray[55] = num2;

            int num3 = 1;
            for (int i = 1; i < 55; i++) {
                int num4 = 21 * i % 55;
                SeedArray[num4] = num3;

                num3 = num2 - num3;
                if (num3 < 0) {
                    num3 += INT_MAX;
                }

                num2 = SeedArray[num4];
            }

            for (int j = 1; j < 5; j++) {
                for (int k = 1; k < 56; k++) {
                    SeedArray[k] -= SeedArray[1 + (k + 30) % 55];
                    if (SeedArray[k] < 0) {
                        SeedArray[k] += INT_MAX;
                    }
                }
            }

            inext = 0;
            inextp = 21;
            Seed = 1;
        } while (false);

        do {
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

    double Random::NextDouble() noexcept {
        int num = Next();
        if ((Next() % 2 == 0) ? true : false) {
            num = -num;
        }

        double num2 = num;
        num2 += 2147483646.0;
        return num2 / 4294967293.0;
    }

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