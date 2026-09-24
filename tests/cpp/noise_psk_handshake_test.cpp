#define BOOST_TEST_MODULE noise_psk_handshake_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/noise/NoisePsk.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace noise = ppp::cryptography::noise;

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) {
        value[i] = static_cast<std::uint8_t>(start + i);
    }
    return value;
}

noise::Secret32 Secret(std::uint8_t start) {
    return noise::Secret32(Filled<32>(start));
}

std::vector<std::uint8_t> Prologue(
    noise::Carrier carrier = noise::Carrier::Tcp,
    std::uint8_t session_start = 0x10,
    const std::string& key_id = "primary-2026") {
    std::vector<std::uint8_t> output;
    const auto session_id = Filled<noise::NoiseSessionIdSize>(session_start);
    BOOST_REQUIRE(noise::BuildCanonicalPrologue(carrier, session_id,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), output));
    return output;
}

std::string Hex(const std::vector<std::uint8_t>& value) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : value) stream << std::setw(2) << static_cast<unsigned>(byte);
    return stream.str();
}

struct Exchange {
    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    noise::NoisePskHandshakeResult client_result;
    noise::NoisePskHandshakeResult server_result;
};

Exchange CompleteDeterministicExchange(
    const std::vector<std::uint8_t>& prologue = Prologue()) {
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x40)));

    Exchange exchange;
    BOOST_REQUIRE(client.WriteMessage1(exchange.message1));
    BOOST_REQUIRE(server.ReadMessage1(exchange.message1.data(), exchange.message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(exchange.message2));
    BOOST_REQUIRE(client.ReadMessage2(exchange.message2.data(), exchange.message2.size()));
    BOOST_REQUIRE(client.TakeResult(exchange.client_result));
    BOOST_REQUIRE(server.TakeResult(exchange.server_result));
    return exchange;
}

}

static_assert(!std::is_copy_constructible<noise::Secret32>::value, "secret must be move-only");
static_assert(!std::is_copy_assignable<noise::Secret32>::value, "secret must be move-only");
static_assert(!std::is_copy_constructible<noise::NoisePskHandshake>::value,
    "handshake must not copy secrets");
static_assert(!std::is_copy_constructible<noise::NoisePskHandshakeResult>::value,
    "result must not copy exporter secrets");

BOOST_AUTO_TEST_CASE(canonical_prologue_has_bounded_unambiguous_binary_layout) {
    const auto session_id = Filled<noise::NoiseSessionIdSize>(0x10);
    const std::string key_id = "primary-2026";
    std::vector<std::uint8_t> prologue;
    BOOST_REQUIRE(noise::BuildCanonicalPrologue(noise::Carrier::Tcp, session_id,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), prologue));

    const std::string expected =
        "186f70656e707070322d6e6f6973652d68616e647368616b65"
        "0100010c6e6f6973652d70736b2d7631"
        "101112131415161718191a1b1c1d1e1f"
        "0c7072696d6172792d32303236";
    BOOST_TEST(Hex(prologue) == expected);

    std::vector<std::uint8_t> rejected = {1, 2, 3};
    BOOST_TEST(!noise::BuildCanonicalPrologue(noise::Carrier::Tcp, session_id,
        nullptr, 0, rejected));
    BOOST_TEST(rejected.empty());
    std::array<std::uint8_t, noise::NoiseKeyIdMaxSize + 1> oversized{};
    BOOST_TEST(!noise::BuildCanonicalPrologue(noise::Carrier::Tcp, session_id,
        oversized.data(), oversized.size(), rejected));
    const std::uint8_t key = 1;
    BOOST_TEST(!noise::BuildCanonicalPrologue(static_cast<noise::Carrier>(99), session_id,
        &key, 1, rejected));
}

BOOST_AUTO_TEST_CASE(fixed_nnpsk0_messages_match_the_canonical_vector) {
    const auto exchange = CompleteDeterministicExchange();
    BOOST_TEST(exchange.message1.size() == noise::NoiseHandshakeMessageSize);
    BOOST_TEST(exchange.message2.size() == noise::NoiseHandshakeMessageSize);

    const std::string expected_message1 =
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        "c4d178e06358457a84bdc649e1aec272";
    const std::string expected_message2 =
        "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
        "fae0059d7923f548486c1d50c39d22ad";
    BOOST_TEST(Hex(exchange.message1) == expected_message1);
    BOOST_TEST(Hex(exchange.message2) == expected_message2);

    noise::Bytes32 client_hash{};
    noise::Bytes32 server_hash{};
    BOOST_REQUIRE(exchange.client_result.GetHandshakeHash(client_hash));
    BOOST_REQUIRE(exchange.server_result.GetHandshakeHash(server_hash));
    BOOST_TEST(client_hash == server_hash);
}

BOOST_AUTO_TEST_CASE(wrong_psk_and_every_prologue_input_change_fail_closed) {
    const auto baseline = Prologue();
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), baseline);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    std::vector<std::uint8_t> message1;
    BOOST_REQUIRE(client.WriteMessage1(message1));

    noise::NoisePskHandshake wrong_psk(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x01), baseline);
    BOOST_TEST(!wrong_psk.ReadMessage1(message1.data(), message1.size()));
    BOOST_TEST(!wrong_psk.IsValid());

    const std::array<std::vector<std::uint8_t>, 3> changed = {{
        Prologue(noise::Carrier::WebSocket),
        Prologue(noise::Carrier::Tcp, 0x11),
        Prologue(noise::Carrier::Tcp, 0x10, "secondary-2026"),
    }};
    for (const auto& prologue : changed) {
        noise::NoisePskHandshake server(
            noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
        BOOST_TEST(!server.ReadMessage1(message1.data(), message1.size()));
        BOOST_TEST(!server.IsValid());
    }
}

BOOST_AUTO_TEST_CASE(message1_tamper_truncate_trailing_and_all_zero_key_are_rejected) {
    const auto prologue = Prologue();
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    std::vector<std::uint8_t> message;
    BOOST_REQUIRE(client.WriteMessage1(message));

    auto expect_rejected = [&prologue](const std::vector<std::uint8_t>& candidate) {
        noise::NoisePskHandshake server(
            noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
        BOOST_TEST(!server.ReadMessage1(candidate.data(), candidate.size()));
        BOOST_TEST(!server.IsValid());
    };

    auto tampered_key = message;
    tampered_key[0] ^= 1;
    expect_rejected(tampered_key);
    auto tampered_tag = message;
    tampered_tag.back() ^= 1;
    expect_rejected(tampered_tag);
    auto truncated = message;
    truncated.pop_back();
    expect_rejected(truncated);
    auto trailing = message;
    trailing.push_back(0);
    expect_rejected(trailing);
    auto all_zero_key = message;
    std::fill(all_zero_key.begin(), all_zero_key.begin() + 32, 0);
    const std::array<std::uint8_t, 16> valid_zero_key_tag = {{
        0xcd, 0x8b, 0x62, 0xeb, 0xe8, 0x4c, 0x8b, 0xca,
        0x46, 0x39, 0xe6, 0xdc, 0x53, 0x83, 0xde, 0x1c,
    }};
    std::copy(valid_zero_key_tag.begin(), valid_zero_key_tag.end(),
        all_zero_key.begin() + 32);
    expect_rejected(all_zero_key);
}

BOOST_AUTO_TEST_CASE(message2_tamper_truncate_trailing_and_all_zero_key_are_rejected) {
    const auto prologue = Prologue();
    auto make_client_and_message2 = [&prologue](
        noise::NoisePskHandshake& client, std::vector<std::uint8_t>& message2) {
        noise::NoisePskHandshake server(
            noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
        BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
        BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x40)));
        std::vector<std::uint8_t> message1;
        BOOST_REQUIRE(client.WriteMessage1(message1));
        BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
        BOOST_REQUIRE(server.WriteMessage2(message2));
    };

    const auto expect_rejected = [&prologue, &make_client_and_message2](int variant) {
        noise::NoisePskHandshake client(
            noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
        std::vector<std::uint8_t> message2;
        make_client_and_message2(client, message2);
        if (variant == 0) message2[0] ^= 1;
        if (variant == 1) message2.back() ^= 1;
        if (variant == 2) message2.pop_back();
        if (variant == 3) message2.push_back(0);
        if (variant == 4) std::fill(message2.begin(), message2.begin() + 32, 0);
        BOOST_TEST(!client.ReadMessage2(message2.data(), message2.size()));
        BOOST_TEST(!client.IsValid());
    };
    for (int variant = 0; variant != 5; ++variant) expect_rejected(variant);
}

BOOST_AUTO_TEST_CASE(role_order_replay_and_result_ownership_are_strict) {
    const auto prologue = Prologue();
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x40)));

    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    BOOST_TEST(!server.WriteMessage2(message2));
    BOOST_TEST(!server.WriteMessage1(message1));
    BOOST_REQUIRE(client.WriteMessage1(message1));
    BOOST_TEST(!client.WriteMessage1(message2));
    BOOST_TEST(!client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x60)));
    BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
    BOOST_TEST(!server.ReadMessage1(message1.data(), message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(message2));
    BOOST_TEST(!server.WriteMessage2(message1));
    BOOST_REQUIRE(client.ReadMessage2(message2.data(), message2.size()));
    BOOST_TEST(!client.ReadMessage2(message2.data(), message2.size()));

    noise::NoisePskHandshakeResult result;
    BOOST_REQUIRE(client.TakeResult(result));
    BOOST_TEST(!client.TakeResult(result));
    BOOST_TEST(result.IsValid());
    result.Clear();
    BOOST_TEST(!result.IsValid());
}

BOOST_AUTO_TEST_CASE(secret_import_move_and_clear_cleanse_all_owned_storage) {
    auto source = Filled<32>(0x70);
    noise::Secret32 first(std::move(source));
    BOOST_TEST(first.IsSet());
    BOOST_TEST(std::all_of(source.begin(), source.end(),
        [](std::uint8_t byte) { return byte == 0; }));

    noise::Secret32 second(std::move(first));
    BOOST_TEST(!first.IsSet());
    BOOST_TEST(std::all_of(first.data(), first.data() + first.size(),
        [](std::uint8_t byte) { return byte == 0; }));
    second.Clear();
    BOOST_TEST(!second.IsSet());
    BOOST_TEST(std::all_of(second.data(), second.data() + second.size(),
        [](std::uint8_t byte) { return byte == 0; }));
}

BOOST_AUTO_TEST_CASE(production_default_generates_fresh_evp_ephemeral_keys) {
    const auto prologue = Prologue();
    noise::NoisePskHandshake first(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake second(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    std::vector<std::uint8_t> first_message;
    std::vector<std::uint8_t> second_message;
    BOOST_REQUIRE(first.WriteMessage1(first_message));
    BOOST_REQUIRE(second.WriteMessage1(second_message));
    BOOST_TEST(first_message != second_message);
    BOOST_TEST(!std::all_of(first_message.begin(), first_message.begin() + 32,
        [](std::uint8_t byte) { return byte == 0; }));
}
