#define BOOST_TEST_MODULE p2p_zero_rtt_cache_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PZeroRTTCache.h>

#include <chrono>

namespace ppp {

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} // namespace ppp

using namespace ppp::p2p;

namespace {

P2PSessionCache MakeSession(std::uint8_t seed) {
    P2PSessionCache session;
    session.session_id = ppp::Int128(seed);
    session.peer_session_id = ppp::Int128(seed + 1);
    session.token_key[0] = seed;
    session.peer_endpoint = boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address("203.0.113.10"), 45000 + seed);
    session.cipher = P2PCipher::ChaCha20Poly1305;
    session.valid = true;
    return session;
}

} // namespace

BOOST_AUTO_TEST_CASE(store_lookup_and_invalidate) {
    P2PZeroRTTCache cache;
    const auto stored = MakeSession(3);
    cache.Store(0x0a000002u, stored);

    auto hit = cache.Lookup(0x0a000002u);
    BOOST_TEST(hit.valid);
    BOOST_TEST(hit.token_key[0] == 3);
    BOOST_TEST(hit.peer_endpoint.port() == 45003);

    cache.Invalidate(0x0a000002u);
    auto miss = cache.Lookup(0x0a000002u);
    BOOST_TEST(!miss.valid);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_entries_and_zero_vip) {
    P2PZeroRTTCache cache;
    auto invalid = MakeSession(1);
    invalid.valid = false;
    cache.Store(0x0a000002u, invalid);
    BOOST_TEST(!cache.Lookup(0x0a000002u).valid);

    cache.Store(0, MakeSession(2));
    BOOST_TEST(!cache.Lookup(0).valid);
}

BOOST_AUTO_TEST_CASE(clear_empties_cache) {
    P2PZeroRTTCache cache;
    cache.Store(0x0a000002u, MakeSession(4));
    cache.Store(0x0a000003u, MakeSession(5));
    cache.Clear();
    BOOST_TEST(!cache.Lookup(0x0a000002u).valid);
    BOOST_TEST(!cache.Lookup(0x0a000003u).valid);
}
