#define BOOST_TEST_MODULE random_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/Random.h>

#include <limits>

// Aim: the subtractive generator is deterministic per seed and every value
// stays inside the half-open range [0, INT_MAX).
BOOST_AUTO_TEST_CASE(random_deterministic_sequence) {
    ppp::Random left(42), right(42);
    for (int i = 0; i < 10000; ++i) {
        const int x = left.Next();
        const int y = right.Next();
        BOOST_TEST(x == y);
        BOOST_TEST(x >= 0);
        BOOST_TEST(x < std::numeric_limits<int>::max());
    }
}

// Aim: SetSeed() rebuilds the state table, so re-seeding reproduces the same
// stream position (contract behind ppp::Random::InitializeSeedTable).
BOOST_AUTO_TEST_CASE(random_set_seed_rebuilds_stream) {
    ppp::Random generator(1);
    generator.SetSeed(20260831);
    const int first = generator.Next();
    const int second = generator.Next();
    generator.SetSeed(20260831);
    BOOST_TEST(generator.Next() == first);
    BOOST_TEST(generator.Next() == second);
}

// Aim: distinct seeds must not produce identical leading values.
BOOST_AUTO_TEST_CASE(random_distinct_seeds_diverge) {
    ppp::Random one(1), two(2);
    BOOST_TEST(one.Next() != two.Next());
}

// Aim: boundary seeds (INT_MAX / INT_MIN) are legal and stay in range.
BOOST_AUTO_TEST_CASE(random_boundary_seeds) {
    ppp::Random max_seed(INT_MAX);
    ppp::Random min_seed(INT_MIN);
    for (int i = 0; i < 1000; ++i) {
        BOOST_TEST(max_seed.Next() >= 0);
        BOOST_TEST(min_seed.Next() >= 0);
    }
    max_seed.SetSeed(INT_MIN);
    min_seed.SetSeed(INT_MAX);
    BOOST_TEST(max_seed.Next() >= 0);
    BOOST_TEST(min_seed.Next() >= 0);
}
