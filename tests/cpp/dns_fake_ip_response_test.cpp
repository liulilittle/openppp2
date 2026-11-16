#define BOOST_TEST_MODULE dns_fake_ip_response_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsFakeIpResponse.h>
#include <common/dnslib/message.h>

#include <vector>

namespace client_dns = ppp::app::client::dns;

namespace {

// Query: example.com A IN
const unsigned char kExampleQuery[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01, 0x00, 0x01
};

std::vector<uint8_t> MakeQuery(uint8_t flags2, uint8_t flags3,
    const std::vector<uint8_t>& opt_data = {}, bool include_opt = false,
    uint16_t question_count = 1) {
    std::vector<uint8_t> query = {
        0x12, 0x34, flags2, flags3,
        static_cast<uint8_t>(question_count >> 8), static_cast<uint8_t>(question_count),
        0, 0, 0, 0, 0, static_cast<uint8_t>(include_opt ? 1 : 0)
    };
    const uint8_t question[] = {
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0,
        0, 1, 0, 1
    };
    for (uint16_t i = 0; i < question_count; ++i)
        query.insert(query.end(), std::begin(question), std::end(question));
    if (include_opt) {
        query.insert(query.end(), {0, 0, 41, 4, 208, 0, 0, 128, 0,
            static_cast<uint8_t>(opt_data.size() >> 8), static_cast<uint8_t>(opt_data.size())});
        query.insert(query.end(), opt_data.begin(), opt_data.end());
    }
    return query;
}

bool DecodeMessage(const ppp::vector<ppp::Byte>& packet, ::dns::Message& message) {
    return message.decode(packet.data(), packet.size()) == ::dns::BufferResult::NoError;
}

}  // namespace

BOOST_AUTO_TEST_CASE(should_skip_reverse_and_local_names) {
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("1.2.3.4.in-addr.arpa"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("localhost"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("printer.local"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("nas.lan"));
    BOOST_TEST(client_dns::DnsFakeIpResponse::ShouldUseFakeIp("example.com"));
}

BOOST_AUTO_TEST_CASE(build_a_record_response) {
    const ppp::vector<ppp::Byte> response = client_dns::DnsFakeIpResponse::BuildARecordResponse(
        kExampleQuery, static_cast<int>(sizeof(kExampleQuery)), 0xC6120005u);
    BOOST_TEST(!response.empty());
    BOOST_TEST((response[2] & 0x80) != 0);
    BOOST_TEST(response[response.size() - 4] == 0xC6);
    BOOST_TEST(response[response.size() - 3] == 0x12);
    BOOST_TEST(response[response.size() - 2] == 0x00);
    BOOST_TEST(response[response.size() - 1] == 0x05);
}

BOOST_AUTO_TEST_CASE(parse_first_a_record_network) {
    const ppp::vector<ppp::Byte> response = client_dns::DnsFakeIpResponse::BuildARecordResponse(
        kExampleQuery, static_cast<int>(sizeof(kExampleQuery)), 0xC6120005u);
    const uint32_t parsed = client_dns::DnsFakeIpResponse::ParseFirstARecordNetwork(
        response.data(), static_cast<int>(response.size()));
    BOOST_TEST(parsed == 0xC6120005u);
}

BOOST_AUTO_TEST_CASE(v2_builds_plain_a_response_with_reencoded_question) {
    const auto query = MakeQuery(0x01, 0x00);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(query.data(), query.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Supported);
    const auto response = client_dns::DnsFakeIpResponse::BuildARecordResponseV2(
        query.data(), query.size(), 0xC6120005u);
    BOOST_REQUIRE(!response.empty());
    BOOST_TEST((response[12] & 0xc0) != 0xc0);
    BOOST_TEST((response[2] & 0x80) != 0);
    BOOST_TEST((response[3] & 0x30) == 0);
    ::dns::Message message;
    BOOST_REQUIRE(DecodeMessage(response, message));
    BOOST_REQUIRE_EQUAL(message.questions.size(), 1);
    BOOST_REQUIRE_EQUAL(message.answers.size(), 1);
    BOOST_TEST(message.questions.front().mName == "example.com");
    BOOST_CHECK(message.questions.front().mType == ::dns::RecordType::kA);
    BOOST_TEST(message.mRD == 1);
    BOOST_TEST(message.additions.empty());
    BOOST_TEST(client_dns::DnsFakeIpResponse::ParseFirstARecordNetwork(
        response.data(), response.size()) == 0xC6120005u);
}

BOOST_AUTO_TEST_CASE(v2_preserves_edns_payload_and_do_copies_cd_and_clears_ad) {
    const auto query = MakeQuery(0x01, 0x30, {}, true);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(query.data(), query.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Supported);
    const auto response = client_dns::DnsFakeIpResponse::BuildARecordResponseV2(
        query.data(), query.size(), 0xC6120005u);
    BOOST_REQUIRE(!response.empty());
    BOOST_TEST((response[3] & 0x30) == 0x10);
    ::dns::Message message;
    BOOST_REQUIRE(DecodeMessage(response, message));
    BOOST_REQUIRE_EQUAL(message.additions.size(), 1);
    auto& opt = message.additions.front();
    BOOST_CHECK(opt.mType == ::dns::RecordType::kOPT);
    BOOST_TEST(static_cast<uint16_t>(opt.mClass) == 1232);
    BOOST_TEST(opt.mTtl == 0x8000u);
    BOOST_TEST(opt.getRData<::dns::RDataOPT>()->mData.empty());
}

BOOST_AUTO_TEST_CASE(v2_rejects_corrupt_and_multi_question_queries) {
    auto corrupt = MakeQuery(0x01, 0x00);
    corrupt.pop_back();
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(corrupt.data(), corrupt.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Invalid);

    const auto multi = MakeQuery(0x01, 0x00, {}, false, 2);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(multi.data(), multi.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Invalid);
    BOOST_TEST(client_dns::DnsFakeIpResponse::BuildARecordResponseV2(
        multi.data(), multi.size(), 0xC6120005u).empty());

    const auto response_packet = MakeQuery(0x81, 0x00);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(response_packet.data(), response_packet.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Invalid);
    const auto opcode = MakeQuery(0x09, 0x00);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(opcode.data(), opcode.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Invalid);

    auto non_in = MakeQuery(0x01, 0x00);
    non_in.back() = 3;
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(non_in.data(), non_in.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Invalid);
}

BOOST_AUTO_TEST_CASE(v2_fails_closed_for_unknown_edns_options) {
    const std::vector<uint8_t> unknown_option = {0xfd, 0xe8, 0, 1, 0x01};
    const auto query = MakeQuery(0x01, 0x00, unknown_option, true);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(query.data(), query.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Unsupported);
    BOOST_TEST(client_dns::DnsFakeIpResponse::BuildARecordResponseV2(
        query.data(), query.size(), 0xC6120005u).empty());

    const std::vector<uint8_t> short_cookie = {0, 10, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const auto invalid_cookie = MakeQuery(0x01, 0x00, short_cookie, true);
    BOOST_CHECK(client_dns::DnsFakeIpResponse::InspectAQueryV2(
        invalid_cookie.data(), invalid_cookie.size()) ==
        client_dns::DnsFakeIpResponse::AQueryStatus::Unsupported);
}
