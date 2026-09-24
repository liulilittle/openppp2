#define BOOST_TEST_MODULE transport_auth_negotiation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/TransportAuthNegotiation.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace configurations = ppp::configurations;
namespace noise = ppp::cryptography::noise;
namespace protocol = ppp::app::protocol;

namespace ppp {
bool operator==(const ppp::string& left, const std::string& right) {
    return left.size() == right.size() &&
        std::memcmp(left.data(), right.data(), left.size()) == 0;
}

namespace app::protocol {
std::ostream& operator<<(std::ostream& stream, TransportAuthAction value) {
    return stream << static_cast<unsigned>(value);
}
}
}

#if !defined(_WIN32)
namespace {

class TempDirectory final {
public:
    TempDirectory() {
        char path[] = "/tmp/openppp2-transport-auth-negotiation-XXXXXX";
        char* result = mkdtemp(path);
        BOOST_REQUIRE(result != nullptr);
        path_ = result;
    }

    ~TempDirectory() {
        for (const std::string& file : files_) unlink(file.c_str());
        rmdir(path_.c_str());
    }

    std::string Write(const std::string& name, char nibble) {
        const std::string path = path_ + "/" + name;
        std::ofstream stream(path.c_str(), std::ios::binary);
        const std::string encoded(configurations::TransportAuthSecret::Size * 2, nibble);
        stream.write(encoded.data(), static_cast<std::streamsize>(encoded.size()));
        stream.close();
        BOOST_REQUIRE(chmod(path.c_str(), 0600) == 0);
        files_.emplace_back(path);
        return path;
    }

    std::string Missing(const std::string& name) const { return path_ + "/" + name; }

private:
    std::string path_;
    std::vector<std::string> files_;
};

configurations::TransportAuthKeyMetadata Key(
    const std::string& id,
    configurations::TransportAuthKeyState state,
    const std::string& path) {
    configurations::TransportAuthKeyMetadata key;
    key.id = id;
    key.state = state;
    key.secret_file = path;
    return key;
}

std::shared_ptr<const configurations::TransportAuthKeyringSnapshot> Keyring(
    std::vector<configurations::TransportAuthKeyMetadata> keys) {
    configurations::TransportAuthConfiguration configuration;
    configuration.keys = std::move(keys);
    std::string error;
    auto snapshot = configurations::BuildTransportAuthKeyringSnapshot(
        configuration, &error);
    BOOST_REQUIRE_MESSAGE(snapshot, error.c_str());
    return snapshot;
}

const std::string TokenA = "00112233445566778899aabbccddeeff";
const std::string TokenB = "ffeeddccbbaa99887766554433221100";

protocol::TransportAuthNegotiationContext Context(
    protocol::TransportAuthCarrier carrier = protocol::TransportAuthCarrier::Tcp,
    std::uint8_t session_start = 0x10,
    const std::string& token = TokenA) {
    protocol::TransportAuthNegotiationContext context;
    context.carrier = carrier;
    for (std::size_t i = 0; i < context.session_id.size(); ++i) {
        context.session_id[i] = static_cast<std::uint8_t>(session_start + i);
    }
    context.token = token;
    return context;
}

protocol::TransportAuthNegotiationContext ResponderContext(
    protocol::TransportAuthNegotiationContext context) {
    context.token.clear();
    return context;
}

struct Controls final {
    protocol::TransportAuthControl advertisement;
    protocol::TransportAuthControl selection;
    protocol::TransportAuthControl proof;
    protocol::TransportAuthControl acknowledgement;
};

void AdvanceToProof(protocol::TransportAuthInitiator& client,
                    protocol::TransportAuthResponder& server,
                    Controls& controls) {
    BOOST_REQUIRE(client.CreateAdvertisement(controls.advertisement));
    BOOST_REQUIRE(server.ConsumeAdvertisement(
        controls.advertisement, controls.selection));
    BOOST_REQUIRE(client.ConsumeSelection(controls.selection, controls.proof));
}

void CompleteExchange(protocol::TransportAuthInitiator& client,
                      protocol::TransportAuthResponder& server,
                      Controls& controls) {
    AdvanceToProof(client, server, controls);
    BOOST_REQUIRE(server.ConsumeClientProof(controls.proof, controls.acknowledgement));
    BOOST_REQUIRE(client.ConsumeAcknowledgement(controls.acknowledgement));
}

void ExpectSameResult(protocol::TransportAuthInitiator& client,
                      protocol::TransportAuthResponder& server) {
    noise::NoisePskHandshakeResult client_result;
    noise::NoisePskHandshakeResult server_result;
    BOOST_REQUIRE(client.TakeNoiseResult(client_result));
    BOOST_REQUIRE(server.TakeNoiseResult(server_result));
    noise::Bytes32 client_hash{};
    noise::Bytes32 server_hash{};
    BOOST_REQUIRE(client_result.GetHandshakeHash(client_hash));
    BOOST_REQUIRE(server_result.GetHandshakeHash(server_hash));
    BOOST_TEST(client_hash == server_hash);
}

}

BOOST_AUTO_TEST_CASE(tcp_four_step_exchange_gates_both_installable_results) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto context = Context();
    protocol::TransportAuthInitiator client(keys, context);
    protocol::TransportAuthResponder server(keys, ResponderContext(context));
    Controls controls;

    BOOST_REQUIRE(client.CreateAdvertisement(controls.advertisement));
    BOOST_TEST(controls.advertisement.action == protocol::TransportAuthAction::Advertise);
    BOOST_TEST(controls.advertisement.token == TokenA);
    BOOST_TEST(controls.advertisement.sequence == 1u);
    BOOST_REQUIRE(server.ConsumeAdvertisement(
        controls.advertisement, controls.selection));
    BOOST_TEST(controls.selection.action == protocol::TransportAuthAction::Select);
    BOOST_TEST(controls.selection.token == TokenA);
    BOOST_TEST(controls.selection.sequence == 2u);

    noise::NoisePskHandshakeResult premature_client;
    noise::NoisePskHandshakeResult premature_server;
    BOOST_TEST(!client.TakeNoiseResult(premature_client));
    BOOST_TEST(!server.TakeNoiseResult(premature_server));

    BOOST_REQUIRE(client.ConsumeSelection(controls.selection, controls.proof));
    BOOST_TEST(controls.proof.token == TokenA);
    BOOST_TEST(!controls.proof.proof.empty());
    BOOST_TEST(!client.TakeNoiseResult(premature_client));
    BOOST_TEST(!server.TakeNoiseResult(premature_server));

    BOOST_REQUIRE(server.ConsumeClientProof(controls.proof, controls.acknowledgement));
    BOOST_TEST(controls.acknowledgement.token == TokenA);
    BOOST_TEST(controls.acknowledgement.proof.empty());
    BOOST_TEST(server.CanTakeNoiseResult());
    BOOST_TEST(!client.CanTakeNoiseResult());
    BOOST_REQUIRE(client.ConsumeAcknowledgement(controls.acknowledgement));
    ExpectSameResult(client, server);
    BOOST_TEST(!client.TakeNoiseResult(premature_client));
    BOOST_TEST(!server.TakeNoiseResult(premature_server));
}

BOOST_AUTO_TEST_CASE(plain_websocket_uses_noise_but_wss_is_rejected) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});

    const auto websocket_context = Context(protocol::TransportAuthCarrier::WebSocket);
    protocol::TransportAuthInitiator websocket_client(keys, websocket_context);
    protocol::TransportAuthResponder websocket_server(keys, websocket_context);
    Controls controls;
    CompleteExchange(websocket_client, websocket_server, controls);
    ExpectSameResult(websocket_client, websocket_server);

    const auto wss_context = Context(protocol::TransportAuthCarrier::TlsWebSocket);
    protocol::TransportAuthInitiator wss_client(keys, wss_context);
    protocol::TransportAuthResponder wss_server(keys, wss_context);
    protocol::TransportAuthControl output;
    BOOST_TEST(wss_client.IsFailed());
    BOOST_TEST(wss_server.IsFailed());
    BOOST_TEST(!wss_client.CreateAdvertisement(output));
}

BOOST_AUTO_TEST_CASE(responder_accepts_active_and_verify_only_but_initiator_emits_active) {
    TempDirectory temp;
    const std::string current = temp.Write("current", 'a');
    const std::string previous = temp.Write("previous", 'b');
    const auto client_keys = Keyring({Key("previous",
        configurations::TransportAuthKeyState::Active, previous)});
    const auto server_keys = Keyring({
        Key("current", configurations::TransportAuthKeyState::Active, current),
        Key("previous", configurations::TransportAuthKeyState::VerifyOnly, previous),
    });

    const auto context = Context();
    protocol::TransportAuthInitiator client(client_keys, context);
    protocol::TransportAuthResponder server(server_keys, context);
    Controls controls;
    CompleteExchange(client, server, controls);
    BOOST_TEST(controls.advertisement.key_id == "previous");
    BOOST_TEST(controls.selection.key_id == "previous");
    ExpectSameResult(client, server);
}

BOOST_AUTO_TEST_CASE(wrong_psk_unknown_and_revoked_keys_fail_without_selection) {
    TempDirectory temp;
    const std::string client_secret = temp.Write("client", 'a');
    const std::string wrong_secret = temp.Write("wrong", 'b');
    const std::string server_secret = temp.Write("server", 'c');
    const auto context = Context();

    {
        const auto client_keys = Keyring({Key("shared",
            configurations::TransportAuthKeyState::Active, client_secret)});
        const auto server_keys = Keyring({Key("shared",
            configurations::TransportAuthKeyState::Active, wrong_secret)});
        protocol::TransportAuthInitiator client(client_keys, context);
        protocol::TransportAuthResponder server(server_keys, context);
        protocol::TransportAuthControl advertisement;
        protocol::TransportAuthControl reject;
        BOOST_REQUIRE(client.CreateAdvertisement(advertisement));
        BOOST_TEST(!server.ConsumeAdvertisement(advertisement, reject));
        BOOST_TEST(server.IsFailed());
        BOOST_TEST(reject.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(reject.token == TokenA);
    }

    const auto retired_client = Keyring({Key("retired",
        configurations::TransportAuthKeyState::Active, client_secret)});
    const auto server_keys = Keyring({
        Key("current", configurations::TransportAuthKeyState::Active, server_secret),
        Key("retired", configurations::TransportAuthKeyState::Revoked,
            temp.Missing("revoked-not-loaded")),
    });
    protocol::TransportAuthInitiator client(retired_client, context);
    protocol::TransportAuthControl advertisement;
    BOOST_REQUIRE(client.CreateAdvertisement(advertisement));

    for (const ppp::string key_id : {ppp::string("retired"), ppp::string("unknown")}) {
        protocol::TransportAuthResponder server(server_keys, context);
        protocol::TransportAuthControl candidate = advertisement;
        candidate.key_id = key_id;
        protocol::TransportAuthControl reject;
        BOOST_TEST(!server.ConsumeAdvertisement(candidate, reject));
        BOOST_TEST(reject.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(reject.token == TokenA);
        BOOST_TEST(server.IsFailed());
    }
}

BOOST_AUTO_TEST_CASE(proof_tamper_fails_after_selection_and_cannot_downgrade) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto context = Context();
    protocol::TransportAuthInitiator client(keys, context);
    protocol::TransportAuthResponder server(keys, context);
    Controls controls;
    AdvanceToProof(client, server, controls);

    controls.proof.proof[0] = controls.proof.proof[0] == '0' ? '1' : '0';
    BOOST_TEST(!server.ConsumeClientProof(controls.proof, controls.acknowledgement));
    BOOST_TEST(server.IsFailed());
    BOOST_TEST(controls.acknowledgement.action == protocol::TransportAuthAction::Reject);
    BOOST_TEST(controls.acknowledgement.token == TokenA);
    noise::NoisePskHandshakeResult result;
    BOOST_TEST(!server.TakeNoiseResult(result));
    BOOST_TEST(!server.ConsumeClientProof(controls.proof, controls.acknowledgement));
}

BOOST_AUTO_TEST_CASE(order_replay_and_control_tuple_mismatches_are_terminal) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto context = Context();

    protocol::TransportAuthInitiator early_client(keys, context);
    protocol::TransportAuthControl unexpected;
    unexpected.action = protocol::TransportAuthAction::Success;
    unexpected.method = protocol::TransportAuthNoisePskV1Method;
    unexpected.key_id = "primary";
    BOOST_TEST(!early_client.ConsumeAcknowledgement(unexpected));
    BOOST_TEST(early_client.IsFailed());

    protocol::TransportAuthResponder early_server(keys, context);
    protocol::TransportAuthControl reject;
    BOOST_TEST(!early_server.ConsumeClientProof(unexpected, reject));
    BOOST_TEST(early_server.IsFailed());

    protocol::TransportAuthInitiator replay_client(keys, context);
    protocol::TransportAuthResponder replay_server(keys, context);
    Controls replay;
    BOOST_REQUIRE(replay_client.CreateAdvertisement(replay.advertisement));
    BOOST_REQUIRE(replay_server.ConsumeAdvertisement(replay.advertisement, replay.selection));
    BOOST_TEST(!replay_server.ConsumeAdvertisement(replay.advertisement, reject));
    BOOST_TEST(replay_server.IsFailed());
    BOOST_REQUIRE(replay_client.ConsumeSelection(replay.selection, replay.proof));
    BOOST_TEST(!replay_client.ConsumeSelection(replay.selection, replay.proof));
    BOOST_TEST(replay_client.IsFailed());

    for (int variant = 0; variant != 4; ++variant) {
        protocol::TransportAuthInitiator client(keys, context);
        protocol::TransportAuthResponder server(keys, context);
        Controls controls;
        BOOST_REQUIRE(client.CreateAdvertisement(controls.advertisement));
        BOOST_REQUIRE(server.ConsumeAdvertisement(controls.advertisement, controls.selection));
        if (variant == 0) controls.selection.version = 2;
        if (variant == 1) controls.selection.action = protocol::TransportAuthAction::Success;
        if (variant == 2) controls.selection.method = "tls-exporter-v1";
        if (variant == 3) controls.selection.key_id = "other";
        BOOST_TEST(!client.ConsumeSelection(controls.selection, controls.proof));
        BOOST_TEST(client.IsFailed());
        noise::NoisePskHandshakeResult result;
        BOOST_TEST(!client.TakeNoiseResult(result));
    }
}

BOOST_AUTO_TEST_CASE(token_tampering_at_each_step_is_terminal) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto context = Context();

    {
        protocol::TransportAuthInitiator client(keys, context);
        protocol::TransportAuthResponder server(keys, ResponderContext(context));
        protocol::TransportAuthControl advertisement;
        protocol::TransportAuthControl reject;
        BOOST_REQUIRE(client.CreateAdvertisement(advertisement));
        advertisement.token.assign(TokenB.data(), TokenB.size());
        BOOST_TEST(!server.ConsumeAdvertisement(advertisement, reject));
        BOOST_TEST(reject.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(reject.token == TokenB);
    }
    {
        protocol::TransportAuthInitiator client(keys, context);
        protocol::TransportAuthResponder server(keys, ResponderContext(context));
        Controls controls;
        BOOST_REQUIRE(client.CreateAdvertisement(controls.advertisement));
        BOOST_REQUIRE(server.ConsumeAdvertisement(controls.advertisement, controls.selection));
        controls.selection.token.assign(TokenB.data(), TokenB.size());
        BOOST_TEST(!client.ConsumeSelection(controls.selection, controls.proof));
        BOOST_TEST(client.IsFailed());
    }
    {
        protocol::TransportAuthInitiator client(keys, context);
        protocol::TransportAuthResponder server(keys, ResponderContext(context));
        Controls controls;
        AdvanceToProof(client, server, controls);
        controls.proof.token.assign(TokenB.data(), TokenB.size());
        BOOST_TEST(!server.ConsumeClientProof(controls.proof, controls.acknowledgement));
        BOOST_TEST(controls.acknowledgement.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(controls.acknowledgement.token == TokenA);
    }
    {
        protocol::TransportAuthInitiator client(keys, context);
        protocol::TransportAuthResponder server(keys, ResponderContext(context));
        Controls controls;
        AdvanceToProof(client, server, controls);
        BOOST_REQUIRE(server.ConsumeClientProof(controls.proof, controls.acknowledgement));
        controls.acknowledgement.token.assign(TokenB.data(), TokenB.size());
        BOOST_TEST(!client.ConsumeAcknowledgement(controls.acknowledgement));
        BOOST_TEST(client.IsFailed());
    }
}

BOOST_AUTO_TEST_CASE(noncanonical_tokens_are_rejected_without_echo) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    std::array<std::string, 3> invalid_tokens = {{TokenA, TokenA.substr(0, 31), TokenA + "0"}};
    invalid_tokens[0][10] = 'A';

    for (const std::string& token : invalid_tokens) {
        const auto invalid_context = Context(protocol::TransportAuthCarrier::Tcp, 0x10, token);
        protocol::TransportAuthInitiator invalid_client(keys, invalid_context);
        protocol::TransportAuthResponder invalid_server(keys, invalid_context);
        protocol::TransportAuthControl output;
        BOOST_TEST(invalid_client.IsFailed());
        BOOST_TEST(invalid_server.IsFailed());
        BOOST_TEST(!invalid_client.CreateAdvertisement(output));

        const auto valid_context = Context();
        protocol::TransportAuthInitiator client(keys, valid_context);
        protocol::TransportAuthResponder server(keys, ResponderContext(valid_context));
        protocol::TransportAuthControl advertisement;
        protocol::TransportAuthControl reject;
        BOOST_REQUIRE(client.CreateAdvertisement(advertisement));
        advertisement.token.assign(token.data(), token.size());
        BOOST_TEST(!server.ConsumeAdvertisement(advertisement, reject));
        BOOST_TEST(reject.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(reject.token.empty());
    }
}

BOOST_AUTO_TEST_CASE(carrier_session_and_prebound_token_mismatches_fail_closed) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto client_context = Context();

    std::array<protocol::TransportAuthNegotiationContext, 3> mismatches = {{
        ResponderContext(Context(protocol::TransportAuthCarrier::WebSocket)),
        ResponderContext(Context(protocol::TransportAuthCarrier::Tcp, 0x11)),
        Context(protocol::TransportAuthCarrier::Tcp, 0x10, TokenB),
    }};
    for (const auto& server_context : mismatches) {
        protocol::TransportAuthInitiator client(keys, client_context);
        protocol::TransportAuthResponder server(keys, server_context);
        protocol::TransportAuthControl advertisement;
        protocol::TransportAuthControl reject;
        BOOST_REQUIRE(client.CreateAdvertisement(advertisement));
        BOOST_TEST(!server.ConsumeAdvertisement(advertisement, reject));
        BOOST_TEST(server.IsFailed());
        BOOST_TEST(reject.action == protocol::TransportAuthAction::Reject);
        BOOST_TEST(reject.token == TokenA);
    }
}

BOOST_AUTO_TEST_CASE(client_requires_exact_proofless_ack_before_result) {
    TempDirectory temp;
    const auto keys = Keyring({Key("primary", configurations::TransportAuthKeyState::Active,
        temp.Write("primary", 'a'))});
    const auto context = Context();
    protocol::TransportAuthInitiator client(keys, context);
    protocol::TransportAuthResponder server(keys, context);
    Controls controls;
    AdvanceToProof(client, server, controls);
    BOOST_REQUIRE(server.ConsumeClientProof(controls.proof, controls.acknowledgement));

    protocol::TransportAuthControl invalid_ack = controls.acknowledgement;
    invalid_ack.proof.assign(noise::NoiseProofSize * 2, '0');
    BOOST_TEST(!client.ConsumeAcknowledgement(invalid_ack));
    BOOST_TEST(client.IsFailed());
    noise::NoisePskHandshakeResult result;
    BOOST_TEST(!client.TakeNoiseResult(result));
}

#else
BOOST_AUTO_TEST_CASE(posix_keyring_fixture_is_not_available_on_windows) {
    BOOST_TEST(true);
}
#endif
