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

std::uint32_t ReferenceFingerprint(const std::uint8_t* bytes, std::size_t size) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0u);
    }
    return (crc ^ 0xffffffffu) ^ 0x5354554eu;
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

BOOST_AUTO_TEST_CASE(tailnode_request_has_software_and_final_ieee_fingerprint) {
    const std::array<std::uint8_t, 32> vector = {{
        0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x80, 0x22, 0x00, 0x08,
        0x74, 0x61, 0x69, 0x6c, 0x6e, 0x6f, 0x64, 0x65}};
    BOOST_TEST(ReferenceFingerprint(vector.data(), vector.size()) == 0x8aabad90u);

    std::array<std::uint8_t, 40> request{};
    std::array<std::uint8_t, 12> txn{};
    BOOST_REQUIRE(P2PStunClient::BuildRequest(request.data(), request.size(), txn.data(),
        P2PStunClient::RequestProfile::Tailnode) == 40);
    BOOST_TEST(request[2] == 0u);
    BOOST_TEST(request[3] == 20u);
    BOOST_CHECK(std::memcmp(request.data() + 8, txn.data(), txn.size()) == 0);
    BOOST_CHECK(std::memcmp(request.data() + 20, vector.data() + 20, 12) == 0);
    const std::array<std::uint8_t, 4> fingerprint_header = {{0x80, 0x28, 0, 4}};
    BOOST_CHECK(std::memcmp(request.data() + 32, fingerprint_header.data(), 4) == 0);
    std::array<std::uint8_t, 4> expected{};
    WriteBe32(expected.data(), ReferenceFingerprint(request.data(), 32));
    BOOST_CHECK(std::memcmp(request.data() + 36, expected.data(), 4) == 0);
}

BOOST_AUTO_TEST_CASE(standard_profile_stays_bare_with_a_larger_buffer) {
    std::array<std::uint8_t, 40> request;
    request.fill(0x5a);
    std::array<std::uint8_t, 12> txn{};
    BOOST_REQUIRE(P2PStunClient::BuildRequest(request.data(), request.size(), txn.data()) == 20);
    BOOST_TEST(request[2] == 0u);
    BOOST_TEST(request[3] == 0u);
    for (unsigned i = 20; i < request.size(); ++i) BOOST_TEST(request[i] == 0x5au);
}

BOOST_AUTO_TEST_CASE(tailnode_insufficient_capacity_and_invalid_profile_do_not_downgrade) {
    std::array<std::uint8_t, 40> request;
    request.fill(0x5a);
    std::array<std::uint8_t, 12> txn;
    txn.fill(0x5a);
    for (int size : {0, 19, 20, 28, 39}) {
        BOOST_TEST(P2PStunClient::BuildRequest(request.data(), size, txn.data(),
            P2PStunClient::RequestProfile::Tailnode) == 0);
    }
    BOOST_TEST(P2PStunClient::BuildRequest(request.data(), request.size(), txn.data(),
        static_cast<P2PStunClient::RequestProfile>(99)) == 0);
    BOOST_TEST(P2PStunClient::BuildRequest(nullptr, 40, txn.data(),
        P2PStunClient::RequestProfile::Tailnode) == 0);
    BOOST_TEST(P2PStunClient::BuildRequest(request.data(), 40, nullptr,
        P2PStunClient::RequestProfile::Tailnode) == 0);
    for (const auto byte : request) BOOST_TEST(byte == 0x5au);
    for (const auto byte : txn) BOOST_TEST(byte == 0x5au);
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
