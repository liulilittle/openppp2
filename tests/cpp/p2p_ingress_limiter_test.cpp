#define BOOST_TEST_MODULE p2p_ingress_limiter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PIngressLimiter.h>

#include <atomic>
#include <limits>
#include <thread>
#include <vector>

using namespace ppp::p2p;

namespace {

P2PIngressLimiter::SessionId Session(unsigned index) {
    P2PIngressLimiter::SessionId session{};
    session[0] = 1;
    session[14] = static_cast<std::uint8_t>(index >> 8);
    session[15] = static_cast<std::uint8_t>(index);
    return session;
}

boost::asio::ip::address Source(unsigned index) {
    return boost::asio::ip::address_v4(0xc6330001u + index);
}

}

BOOST_AUTO_TEST_CASE(source_burst_and_fractional_refill_obey_four_packets_per_second) {
    P2PIngressLimiter limiter;
    for (unsigned count = 0; count < 8; ++count) BOOST_TEST(limiter.AllowSource(Source(1), 1000));
    BOOST_TEST(!limiter.AllowSource(Source(1), 1000));
    BOOST_TEST(!limiter.AllowSource(Source(1), 1249));
    BOOST_TEST(limiter.AllowSource(Source(1), 1250));
    BOOST_TEST(!limiter.AllowSource(Source(1), 1250));
    for (unsigned count = 0; count < 4; ++count) BOOST_TEST(limiter.AllowSource(Source(1), 2250));
    BOOST_TEST(!limiter.AllowSource(Source(1), 2250));
}

BOOST_AUTO_TEST_CASE(authenticated_session_has_independent_eight_per_second_bucket) {
    P2PIngressLimiter limiter;
    for (unsigned count = 0; count < 16; ++count) BOOST_TEST(limiter.AllowSession(Session(1), 1000));
    BOOST_TEST(!limiter.AllowSession(Session(1), 1000));
    BOOST_TEST(!limiter.AllowSession(Session(1), 1124));
    BOOST_TEST(limiter.AllowSession(Session(1), 1125));
    BOOST_TEST(!limiter.AllowSession(Session(1), 1125));
    for (unsigned count = 0; count < 8; ++count) BOOST_TEST(limiter.AllowSession(Session(1), 2125));
    BOOST_TEST(!limiter.AllowSession(Session(1), 2125));
    BOOST_TEST(limiter.AllowSession(Session(2), 2125));
    BOOST_TEST(limiter.AllowSource(Source(1), 2125));
}

BOOST_AUTO_TEST_CASE(ipv4_mapped_ipv6_cannot_gain_another_source_budget) {
    P2PIngressLimiter limiter;
    const auto v4 = boost::asio::ip::make_address("192.0.2.1");
    const auto mapped = boost::asio::ip::make_address("::ffff:192.0.2.1");
    for (unsigned count = 0; count < 8; ++count) BOOST_TEST(limiter.AllowSource(v4, 1000));
    BOOST_TEST(!limiter.AllowSource(mapped, 1000));
    BOOST_TEST(limiter.AllowSource(boost::asio::ip::make_address("2001:db8::1"), 1000));
    BOOST_TEST(limiter.Snapshot().source_entries == 2u);
}

BOOST_AUTO_TEST_CASE(saturated_tables_drop_unknown_keys_without_evicting_known_entries) {
    P2PIngressLimiter limiter;
    for (unsigned index = 0; index < P2PIngressLimiter::MaxEntries; ++index) {
        BOOST_TEST(limiter.AllowSource(Source(index), 1000));
        BOOST_TEST(limiter.AllowSession(Session(index), 1000));
    }
    BOOST_TEST(limiter.Snapshot().source_entries == 256u);
    BOOST_TEST(limiter.Snapshot().session_entries == 256u);
    BOOST_TEST(!limiter.AllowSource(Source(256), 1000));
    BOOST_TEST(!limiter.AllowSession(Session(256), 1000));
    BOOST_TEST(limiter.AllowSource(Source(0), 1000));
    BOOST_TEST(limiter.AllowSession(Session(0), 1000));
    BOOST_TEST(limiter.Snapshot().source_entries == 256u);
    BOOST_TEST(limiter.Snapshot().session_entries == 256u);
}

BOOST_AUTO_TEST_CASE(sixty_second_idle_expiry_reclaims_space_but_keeps_active_keys) {
    P2PIngressLimiter limiter;
    for (unsigned index = 0; index < 256; ++index) {
        BOOST_TEST(limiter.AllowSource(Source(index), 1000));
        BOOST_TEST(limiter.AllowSession(Session(index), 1000));
    }
    BOOST_TEST(limiter.AllowSource(Source(0), 60000));
    BOOST_TEST(limiter.AllowSession(Session(0), 60000));
    BOOST_TEST(!limiter.AllowSource(Source(256), 60999));
    BOOST_TEST(!limiter.AllowSession(Session(256), 60999));
    BOOST_TEST(limiter.AllowSource(Source(256), 61000));
    BOOST_TEST(limiter.AllowSession(Session(256), 61000));
    BOOST_TEST(limiter.Snapshot().source_entries == 2u);
    BOOST_TEST(limiter.Snapshot().session_entries == 2u);
}

BOOST_AUTO_TEST_CASE(backward_ticks_do_not_refill_or_move_bucket_time_backward) {
    P2PIngressLimiter limiter;
    for (unsigned count = 0; count < 8; ++count) BOOST_TEST(limiter.AllowSource(Source(1), 1000));
    BOOST_TEST(!limiter.AllowSource(Source(1), 500));
    BOOST_TEST(!limiter.AllowSource(Source(1), 999));
    BOOST_TEST(!limiter.AllowSource(Source(1), 1249));
    BOOST_TEST(limiter.AllowSource(Source(1), 1250));
    BOOST_TEST(!limiter.AllowSource(Source(1), 1250));
}

BOOST_AUTO_TEST_CASE(huge_tick_refill_never_overflows_and_is_capped_at_burst) {
    P2PIngressLimiter limiter;
    BOOST_TEST(limiter.AllowSource(Source(1), 0));
    BOOST_TEST(limiter.AllowSession(Session(1), 0));
    const auto now = std::numeric_limits<std::uint64_t>::max();
    for (unsigned count = 0; count < 8; ++count) BOOST_TEST(limiter.AllowSource(Source(1), now));
    BOOST_TEST(!limiter.AllowSource(Source(1), now));
    for (unsigned count = 0; count < 16; ++count) BOOST_TEST(limiter.AllowSession(Session(1), now));
    BOOST_TEST(!limiter.AllowSession(Session(1), now));
}

BOOST_AUTO_TEST_CASE(concurrent_prepost_calls_cannot_overrun_either_burst) {
    P2PIngressLimiter limiter;
    std::atomic<unsigned> source_allowed{0};
    std::atomic<unsigned> session_allowed{0};
    std::vector<std::thread> threads;
    for (unsigned index = 0; index < 32; ++index) {
        threads.emplace_back([&]() {
            if (limiter.AllowSource(Source(1), 1000)) ++source_allowed;
            if (limiter.AllowSession(Session(1), 1000)) ++session_allowed;
        });
    }
    for (auto& thread : threads) thread.join();
    BOOST_TEST(source_allowed.load() == 8u);
    BOOST_TEST(session_allowed.load() == 16u);
    BOOST_TEST(limiter.Snapshot().source_entries == 1u);
    BOOST_TEST(limiter.Snapshot().session_entries == 1u);
}

BOOST_AUTO_TEST_CASE(clear_and_invalid_keys_leave_no_active_buckets) {
    P2PIngressLimiter limiter;
    BOOST_TEST(!limiter.AllowSource(boost::asio::ip::address_v4::any(), 1000));
    BOOST_TEST(!limiter.AllowSource(boost::asio::ip::address_v6::any(), 1000));
    BOOST_TEST(!limiter.AllowSource(boost::asio::ip::make_address("::ffff:0.0.0.0"), 1000));
    BOOST_TEST(!limiter.AllowSession({}, 1000));
    BOOST_TEST(limiter.Snapshot().source_entries == 0u);
    BOOST_TEST(limiter.Snapshot().session_entries == 0u);
    BOOST_TEST(limiter.AllowSource(Source(1), 1000));
    BOOST_TEST(limiter.AllowSession(Session(1), 1000));
    limiter.Clear();
    limiter.Clear();
    BOOST_TEST(limiter.Snapshot().source_entries == 0u);
    BOOST_TEST(limiter.Snapshot().session_entries == 0u);
    BOOST_TEST(limiter.AllowSource(Source(1), 1000));
}
