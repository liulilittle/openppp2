#define BOOST_TEST_MODULE p2p_stun_client_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PStunClient.h>

#include <array>
#include <chrono>
#include <cstring>

namespace ppp {

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void Sleep(int) noexcept {}

} // namespace ppp

using namespace ppp::p2p;

namespace {

void WriteBe16(std::uint8_t* out, std::uint16_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[1] = static_cast<std::uint8_t>(value & 0xff);
}

void WriteBe32(std::uint8_t* out, std::uint32_t value) {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xff);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[3] = static_cast<std::uint8_t>(value & 0xff);
}

std::vector<std::uint8_t> BuildXorMappedResponse(
    const std::uint8_t txn_id[12],
    std::uint32_t ipv4_host_order,
    std::uint16_t port_host_order) {
    std::vector<std::uint8_t> response(32, 0);
    WriteBe16(response.data(), 0x0101);
    WriteBe16(response.data() + 2, 12);
    WriteBe32(response.data() + 4, 0x2112A442u);
    std::memcpy(response.data() + 8, txn_id, 12);

    WriteBe16(response.data() + 20, 0x0020);
    WriteBe16(response.data() + 22, 8);
    response[24] = 0;
    response[25] = 0x01;
    const std::uint16_t xport =
        static_cast<std::uint16_t>(port_host_order ^ 0x2112u);
    WriteBe16(response.data() + 26, xport);
    const std::uint32_t xaddr = ipv4_host_order ^ 0x2112A442u;
    WriteBe32(response.data() + 28, xaddr);
    return response;
}

} // namespace

BOOST_AUTO_TEST_CASE(build_request_writes_binding_header) {
    std::array<std::uint8_t, 20> request{};
    std::array<std::uint8_t, 12> txn{};
    const int written = P2PStunClient::BuildRequest(
        request.data(), static_cast<int>(request.size()), txn.data());
    BOOST_REQUIRE(written == 20);
    BOOST_TEST(request[0] == 0x00);
    BOOST_TEST(request[1] == 0x01);
    BOOST_TEST(request[4] == 0x21);
    BOOST_TEST(request[5] == 0x12);
    BOOST_TEST(request[6] == 0xA4);
    BOOST_TEST(request[7] == 0x42);
    BOOST_TEST(std::memcmp(request.data() + 8, txn.data(), 12) == 0);
}

BOOST_AUTO_TEST_CASE(parse_response_extracts_xor_mapped_address) {
    std::array<std::uint8_t, 12> txn{};
    for (std::size_t i = 0; i < txn.size(); ++i) txn[i] = static_cast<std::uint8_t>(i + 1);
    const auto response = BuildXorMappedResponse(
        txn.data(), 0xc0000201u, 3478);

    boost::asio::ip::udp::endpoint mapped;
    BOOST_REQUIRE(P2PStunClient::ParseResponse(
        response.data(), static_cast<int>(response.size()),
        txn.data(), mapped));
    BOOST_TEST(mapped.address().to_string() == "192.0.2.1");
    BOOST_TEST(mapped.port() == 3478);
}

BOOST_AUTO_TEST_CASE(parse_response_rejects_bad_transaction_id) {
    std::array<std::uint8_t, 12> txn{};
    std::array<std::uint8_t, 12> wrong{};
    for (std::size_t i = 0; i < txn.size(); ++i) {
        txn[i] = static_cast<std::uint8_t>(i + 1);
        wrong[i] = static_cast<std::uint8_t>(i + 2);
    }
    const auto response = BuildXorMappedResponse(
        txn.data(), 0xc0000201u, 3478);

    boost::asio::ip::udp::endpoint mapped;
    BOOST_TEST(!P2PStunClient::ParseResponse(
        response.data(), static_cast<int>(response.size()),
        wrong.data(), mapped));
}
