#define BOOST_TEST_MODULE transport_auth_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/noise/NoisePsk.h>
#include <ppp/p2p/P2PRelayOffer.h>
#include <ppp/p2p/P2PRelayOfferV2.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/transmissions/NoisePskAuthenticatedCarrierBinding.h>

#include <boost/asio/post.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace noise = ppp::cryptography::noise;
namespace protocol = ppp::app::protocol;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;

namespace ppp::transmissions {
std::ostream& operator<<(std::ostream& stream, AuthenticatedCarrierKind value) {
    return stream << static_cast<unsigned>(value);
}
std::ostream& operator<<(std::ostream& stream, AuthenticatedCarrierMethod value) {
    return stream << static_cast<unsigned>(value);
}
}

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

noise::NoisePskHandshakeResult CompleteNoiseResult(
    noise::Carrier carrier = noise::Carrier::Tcp) {
    std::vector<std::uint8_t> prologue;
    const auto session_id = Filled<noise::NoiseSessionIdSize>(0x10);
    const std::string key_id = "transport-auth-test";
    BOOST_REQUIRE(noise::BuildCanonicalPrologue(carrier, session_id,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(),
        prologue));

    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(
        Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(
        Secret(0x40)));

    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    BOOST_REQUIRE(client.WriteMessage1(message1));
    BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(message2));
    BOOST_REQUIRE(client.ReadMessage2(message2.data(), message2.size()));

    noise::NoisePskHandshakeResult result;
    BOOST_REQUIRE(client.TakeResult(result));
    return result;
}

class FakeTransmission final : public transmissions::ITransmission {
public:
    FakeTransmission(const ContextPtr& context, const StrandPtr& strand,
        transmissions::AuthenticatedCarrierKind kind)
        : ITransmission(context, strand,
            std::make_shared<ppp::configurations::AppConfiguration>())
        , kind_(kind) {
    }

    transmissions::AuthenticatedCarrierKind GetAuthenticatedCarrierKind() const noexcept override {
        return kind_;
    }

    bool IsHandshakeComplete() const noexcept override {
        return handshake_complete_;
    }

    void SetHandshakeComplete(bool value) noexcept {
        handshake_complete_ = value;
    }

    bool ShiftToScheduler() noexcept override {
        InvalidateAuthenticatedCarrierBinding();
        return true;
    }

    tcp::endpoint GetRemoteEndPoint() noexcept override {
        return {};
    }

protected:
    std::shared_ptr<ppp::Byte> DoReadBytes(YieldContext&, int) noexcept override {
        return nullptr;
    }

    bool DoWriteBytes(std::shared_ptr<ppp::Byte>, int, int,
        const AsynchronousWriteBytesCallback&) noexcept override {
        return false;
    }

private:
    transmissions::AuthenticatedCarrierKind kind_;
    bool handshake_complete_ = false;
};

template <typename Callback>
void OnStrand(const std::shared_ptr<asio::io_context>& context,
    const FakeTransmission::StrandPtr& strand, Callback&& callback) {
    context->restart();
    asio::post(*strand, std::forward<Callback>(callback));
    context->run();
}

std::shared_ptr<tcp::socket> ConnectedSocket(
    const std::shared_ptr<asio::io_context>& context,
    std::vector<std::shared_ptr<tcp::socket>>& peers) {
    tcp::acceptor acceptor(*context,
        tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    auto client = std::make_shared<tcp::socket>(*context);
    auto server = std::make_shared<tcp::socket>(*context);
    client->connect(acceptor.local_endpoint());
    acceptor.accept(*server);
    peers.push_back(server);
    return client;
}

}

BOOST_AUTO_TEST_CASE(noise_binding_is_one_shot_typed_and_lifecycle_bound) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto transmission = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::Tcp);
    const auto exporter_context = Filled<16>(0x70);
    auto changed_exporter_context = exporter_context;
    changed_exporter_context.back() ^= 1;
    const auto p2p_exporter_context = Filled<ppp::p2p::P2PExporterContext{}.size()>(0x20);
    std::array<std::uint8_t, 32> root{};
    std::array<std::uint8_t, 32> changed_root{};
    std::array<std::uint8_t, 32> candidate{};
    std::array<std::uint8_t, 32> p2p{};

    BOOST_TEST(transmission->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(!transmission->IsServerLoopbackIngress());
    BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::None);
    BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());

    OnStrand(context, strand, [&]() {
        auto premature = CompleteNoiseResult();
        BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(premature)));
        transmission->SetHandshakeComplete(true);
        auto result = CompleteNoiseResult();
        BOOST_REQUIRE(transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));

        BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::NoisePskV1);
        BOOST_TEST(transmission->IsAuthenticatedCarrierBindingActive());
        BOOST_TEST(transmission->HasAuthenticatedSessionExporter());
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            changed_exporter_context.data(), changed_exporter_context.size(),
            changed_root.data(), changed_root.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeCandidateExporterLabel,
            exporter_context.data(), exporter_context.size(),
            candidate.data(), candidate.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            ppp::p2p::P2PWrapExporterLabel,
            p2p_exporter_context.data(), p2p_exporter_context.size(),
            p2p.data(), p2p.size()));
        BOOST_TEST(root != changed_root);
        BOOST_TEST(root != candidate);
        BOOST_TEST(root != p2p);
        BOOST_TEST(candidate != p2p);
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            ppp::p2p::P2PWrapExporterLabel,
            exporter_context.data(), exporter_context.size(),
            p2p.data(), p2p.size()));

        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            "EXPORTER-OPENPPP2-UNKNOWN-v1",
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size()));
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size() - 1,
            root.data(), root.size()));
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size() - 1));

        auto duplicate = CompleteNoiseResult();
        BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(duplicate)));
    });

    BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::NoisePskV1);
    context->restart();
    BOOST_TEST(transmission->IsAuthenticatedCarrierBindingActive());
    BOOST_TEST(transmission->HasAuthenticatedSessionExporter());
    BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
        protocol::SessionResumeRootExporterLabel,
        exporter_context.data(), exporter_context.size(),
        root.data(), root.size()));

    OnStrand(context, strand, [&]() {
        transmission->Dispose();
        BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());
        BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::None);
    });
}

BOOST_AUTO_TEST_CASE(noise_capability_is_visible_across_strands_but_export_is_owner_only) {
    auto context = std::make_shared<asio::io_context>();
    auto owner = std::make_shared<FakeTransmission::StrandPtr::element_type>(asio::make_strand(*context));
    auto foreign = std::make_shared<FakeTransmission::StrandPtr::element_type>(asio::make_strand(*context));
    auto other_context = std::make_shared<asio::io_context>();
    auto other_owner = std::make_shared<FakeTransmission::StrandPtr::element_type>(asio::make_strand(*other_context));
    auto transmission = std::make_shared<FakeTransmission>(context, owner,
        transmissions::AuthenticatedCarrierKind::Tcp);
    transmission->SetHandshakeComplete(true);
    auto binding = std::make_shared<transmissions::NoisePskAuthenticatedCarrierBinding>(
        context, owner, CompleteNoiseResult());
    const auto exporter_context = Filled<ppp::p2p::P2PExporterContextV2{}.size()>(0x20);
    std::array<std::uint8_t, 32> output{};
    OnStrand(context, owner, [&]() {
        BOOST_REQUIRE(transmission->InstallNoiseAuthenticatedCarrierBinding(CompleteNoiseResult()));
        BOOST_REQUIRE(binding->IsAvailable(context, owner));
        BOOST_REQUIRE(binding->Export(context, owner, ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
    });
    BOOST_TEST(!binding->IsAvailable(context, owner));
    BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());
    context->restart();
    BOOST_TEST(binding->IsAvailable(context, owner));
    BOOST_TEST(transmission->HasAuthenticatedSessionExporter());
    const auto unchanged = output;
    BOOST_TEST(!binding->Export(context, owner, ppp::p2p::P2PWrapExporterLabelV2,
        exporter_context.data(), exporter_context.size(), output.data(), output.size()));
    BOOST_CHECK(output == unchanged);
    OnStrand(context, foreign, [&]() {
        BOOST_TEST(transmission->HasAuthenticatedSessionExporter());
        BOOST_TEST(binding->IsAvailable(context, owner));
        BOOST_TEST(!binding->IsAvailable(context, foreign));
        BOOST_TEST(!binding->IsAvailable(other_context, other_owner));
        BOOST_TEST(!binding->Export(context, owner, ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
        BOOST_CHECK(output == unchanged);
    });
    OnStrand(context, owner, [&]() {
        BOOST_TEST(!binding->Export(context, foreign, ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
        BOOST_TEST(!binding->Export(other_context, other_owner, ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
        binding->Invalidate();
        BOOST_TEST(!binding->IsAvailable(context, owner));
        BOOST_TEST(!binding->Export(context, owner, ppp::p2p::P2PWrapExporterLabelV2,
            exporter_context.data(), exporter_context.size(), output.data(), output.size()));
        transmission->Dispose();
        BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());
    });
    context->restart(); context->stop();
    BOOST_TEST(!binding->IsAvailable(context, owner));
}

BOOST_AUTO_TEST_CASE(noise_rejects_non_carriers_and_migration_invalidates) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));

    for (const auto kind : {
            transmissions::AuthenticatedCarrierKind::None,
            transmissions::AuthenticatedCarrierKind::TlsWebSocket}) {
        auto transmission = std::make_shared<FakeTransmission>(context, strand, kind);
        transmission->SetHandshakeComplete(true);
        OnStrand(context, strand, [&]() {
            auto result = CompleteNoiseResult();
            BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
                std::move(result)));
        });
    }

    auto loopback = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::Tcp);
    loopback->SetHandshakeComplete(true);
    loopback->MarkServerLoopbackIngress();
    BOOST_TEST(loopback->IsServerLoopbackIngress());
    OnStrand(context, strand, [&]() {
        auto result = CompleteNoiseResult();
        BOOST_TEST(!loopback->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));
        BOOST_TEST(!loopback->IsAuthenticatedCarrierBindingActive());
        BOOST_TEST(!loopback->HasAuthenticatedSessionExporter());
    });

    auto websocket = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::WebSocket);
    websocket->SetHandshakeComplete(true);
    OnStrand(context, strand, [&]() {
        auto result = CompleteNoiseResult(noise::Carrier::WebSocket);
        BOOST_REQUIRE(websocket->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));
        BOOST_REQUIRE(websocket->HasAuthenticatedSessionExporter());
        BOOST_REQUIRE(websocket->ShiftToScheduler());
        BOOST_TEST(!websocket->HasAuthenticatedSessionExporter());
        BOOST_TEST(websocket->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::None);
    });
}

BOOST_AUTO_TEST_CASE(production_transport_descriptors_are_explicit) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    std::vector<std::shared_ptr<tcp::socket>> peers;

    auto child = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Child);
    auto main = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Main);
    auto server = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Server);
    auto websocket = std::make_shared<transmissions::IWebsocketTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration);
    auto wss = std::make_shared<transmissions::ISslWebsocketTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration);

    BOOST_TEST(child->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::None);
    BOOST_TEST(main->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(server->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(websocket->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::WebSocket);
    BOOST_TEST(wss->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::TlsWebSocket);
    BOOST_TEST(wss->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::TlsExporterV1);
    BOOST_TEST(!wss->IsAuthenticatedCarrierBindingActive());

    child->Dispose();
    main->Dispose();
    server->Dispose();
    websocket->Dispose();
    wss->Dispose();
    context->restart();
    context->poll();
}

BOOST_AUTO_TEST_CASE(tcp_child_send_half_close_preserves_receive) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    std::vector<std::shared_ptr<tcp::socket>> peers;
    auto child = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Child);
    const auto peer = peers.front();

    BOOST_TEST(child->SupportsSendHalfClose());
    OnStrand(context, strand, [&]() {
        BOOST_TEST(child->ShutdownSend());
        BOOST_TEST(child->ShutdownSend());
    });

    std::array<char, 1> eof{};
    boost::system::error_code ec;
    BOOST_TEST(peer->read_some(asio::buffer(eof), ec) == 0U);
    BOOST_TEST(ec == asio::error::eof);

    constexpr std::array<ppp::Byte, 4> reply = { 1, 2, 3, 4 };
    BOOST_REQUIRE(peer->write_some(asio::buffer(reply), ec) == reply.size());
    BOOST_TEST(!ec);
    bool reply_read = false;
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
        nullptr, *context, strand.get(),
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const std::shared_ptr<ppp::Byte> bytes = child->ReadBytes(y, reply.size());
            reply_read = bytes && std::equal(reply.begin(), reply.end(), bytes.get());
        }));
    context->restart();
    context->run();
    BOOST_TEST(reply_read);
    BOOST_TEST(!child->IsReceiveClosed());

    peer->shutdown(tcp::socket::shutdown_send, ec);
    BOOST_TEST(!ec);
    bool eof_read = false;
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
        nullptr, *context, strand.get(),
        [&](ppp::coroutines::YieldContext& y) noexcept {
            eof_read = !child->ReadBytes(y, 1);
        }));
    context->restart();
    context->run();
    BOOST_TEST(eof_read);
    BOOST_TEST(child->IsReceiveClosed());
    BOOST_TEST(child->ShutdownSend());

    child->Dispose();
    context->restart();
    context->poll();
}

// Server-side per-flow relays opt into receive half-close: a client upload
// FIN must not dispose the carrier (the relay still has echo/response bytes to
// send back). Without the opt-in a server carrier keeps its abortive EOF.
namespace {
// Exposes the carrier read entry the protocol layer uses (QoS path, which
// disposes the carrier on a failed read unless receive half-close applies).
class ProbeTcpTransmission final : public transmissions::ITcpipTransmission {
public:
    using transmissions::ITcpipTransmission::ITcpipTransmission;
    using transmissions::ITcpipTransmission::DoReadBytes;
};
}

BOOST_AUTO_TEST_CASE(tcp_server_receive_half_close_is_opt_in) {
    for (const bool opt_in : { false, true }) {
        auto context = std::make_shared<asio::io_context>();
        auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
            asio::make_strand(*context));
        auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
        std::vector<std::shared_ptr<tcp::socket>> peers;
        auto server = std::make_shared<ProbeTcpTransmission>(
            context, strand, ConnectedSocket(context, peers), configuration,
            transmissions::TcpTransmissionRole::Server);
        const auto peer = peers.front();
        BOOST_TEST(!server->SupportsSendHalfClose());
        if (opt_in) {
            BOOST_TEST(server->EnableReceiveHalfClose());
        }

        boost::system::error_code ec;
        peer->shutdown(tcp::socket::shutdown_send, ec);
        BOOST_TEST(!ec);
        bool eof_read = false;
        BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
            nullptr, *context, strand.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                eof_read = !server->DoReadBytes(y, 1);
            }));
        context->restart();
        context->run();
        BOOST_TEST(eof_read);
        BOOST_TEST(server->IsReceiveClosed() == opt_in);

        // The peer observes the carrier's send side: still open after an
        // opted-in half-close, closed (EOF) after the default abortive path.
        peer->non_blocking(true);
        std::array<char, 1> probe{};
        peer->read_some(asio::buffer(probe), ec);
        if (opt_in) {
            BOOST_TEST(ec == asio::error::would_block);
        }
        else {
            BOOST_TEST((ec == asio::error::eof || ec == asio::error::connection_reset));
        }

        server->Dispose();
        context->restart();
        context->poll();
    }
}

BOOST_AUTO_TEST_CASE(tcp_read_ahead_preserves_byte_stream) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    std::vector<std::shared_ptr<tcp::socket>> peers;
    auto carrier = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Child);
    const auto peer = peers.front();

    // Reads that mirror frame decoding: small headers, small and large payloads.
    const std::vector<int> reads = { 3, 100, 3, 70000, 3, 1, 5, 20000 };
    std::vector<ppp::Byte> stream;
    for (int length : reads) {
        for (int i = 0; i < length; i++) {
            stream.push_back(static_cast<ppp::Byte>((stream.size() * 131 + 17) & 0xff));
        }
    }

    // Deliver everything in uneven chunks so reads both span and split socket reads.
    std::thread writer([&]() {
        std::size_t offset = 0;
        std::size_t chunk = 7;
        boost::system::error_code ec;
        while (offset < stream.size() && !ec) {
            std::size_t n = std::min(chunk, stream.size() - offset);
            asio::write(*peer, asio::buffer(stream.data() + offset, n), ec);
            offset += n;
            chunk = chunk * 3 + 1;
        }
    });

    bool matched = true;
    std::size_t consumed = 0;
    BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
        nullptr, *context, strand.get(),
        [&](ppp::coroutines::YieldContext& y) noexcept {
            for (int length : reads) {
                const std::shared_ptr<ppp::Byte> bytes = carrier->ReadBytes(y, length);
                if (!bytes || !std::equal(stream.begin() + consumed, stream.begin() + consumed + length, bytes.get())) {
                    matched = false;
                    return;
                }
                consumed += length;
            }
        }));
    context->restart();
    context->run();
    writer.join();

    BOOST_TEST(matched);
    BOOST_TEST(consumed == stream.size());

    carrier->Dispose();
    context->restart();
    context->poll();
}

BOOST_AUTO_TEST_CASE(tcp_encrypted_frames_round_trip_after_handshake) {
    // Exercises the post-handshake frame encoder (transport cipher written straight into
    // the frame, gathered carrier writes) against the unchanged decoder and read-ahead.
    for (int variant = 0; variant < 4; variant++) {
        const bool delta_encode = (variant & 1) != 0;
        const bool obfuscate = (variant & 2) != 0;
        auto context = std::make_shared<asio::io_context>();
        auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
            asio::make_strand(*context));
        auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
        configuration->key.protocol = "aes-128-cfb";
        configuration->key.protocol_key = "frame-test-protocol";
        configuration->key.transport = "aes-256-cfb";
        configuration->key.transport_key = "frame-test-transport";
        configuration->key.plaintext = false;
        configuration->key.delta_encode = delta_encode;
        configuration->key.masked = obfuscate;
        configuration->key.shuffle_data = obfuscate;

        std::vector<std::shared_ptr<tcp::socket>> peers;
        auto client = std::make_shared<transmissions::ITcpipTransmission>(
            context, strand, ConnectedSocket(context, peers), configuration,
            transmissions::TcpTransmissionRole::Main);
        auto server = std::make_shared<transmissions::ITcpipTransmission>(
            context, strand, peers.front(), configuration,
            transmissions::TcpTransmissionRole::Server);

        const std::vector<int> sizes = { 1, 3, 64, 1400, 9000, 65535, 2, 777 };
        std::vector<std::vector<ppp::Byte>> frames;
        for (std::size_t f = 0; f < sizes.size(); f++) {
            std::vector<ppp::Byte> frame(sizes[f]);
            for (int i = 0; i < sizes[f]; i++) {
                frame[i] = static_cast<ppp::Byte>(f * 37 + i * 11);
            }
            frames.push_back(std::move(frame));
        }

        ppp::Int128 session_id = 0;
        bool server_handshaked = false;
        int written = 0;
        int received = 0;
        bool matched = true;
        BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
            nullptr, *context, strand.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                bool mux = false;
                session_id = client->HandshakeClient(y, mux);
                if (session_id == 0) {
                    return;
                }

                // Queue every frame without waiting so the write queue builds a backlog.
                for (const auto& frame : frames) {
                    if (client->Write(frame.data(), static_cast<int>(frame.size()),
                        [&written](bool ok) noexcept { written += ok ? 1 : 0; })) {
                        continue;
                    }
                    return;
                }
            }));
        BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(
            nullptr, *context, strand.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                server_handshaked = server->HandshakeServer(y, ppp::Int128(0x1234), false);
                if (!server_handshaked) {
                    return;
                }

                for (const auto& frame : frames) {
                    int length = 0;
                    std::shared_ptr<ppp::Byte> packet = server->Read(y, length);
                    if (!packet || length != static_cast<int>(frame.size()) ||
                        !std::equal(frame.begin(), frame.end(), packet.get())) {
                        matched = false;
                        return;
                    }
                    received++;
                }
            }));
        context->restart();
        context->run_for(std::chrono::seconds(20));

        BOOST_TEST((session_id != ppp::Int128(0)));
        BOOST_TEST(server_handshaked);
        BOOST_TEST(matched);
        BOOST_TEST(received == static_cast<int>(frames.size()));
        BOOST_TEST(written == static_cast<int>(frames.size()));

        client->Dispose();
        server->Dispose();
        context->restart();
        context->poll();
    }
}
