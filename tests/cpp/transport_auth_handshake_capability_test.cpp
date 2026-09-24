#define BOOST_TEST_MODULE transport_auth_handshake_capability_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

using Codec = transmissions::TransportAuthHandshakeCapabilityCodec;
using Transmission = transmissions::ISslWebsocketTransmission;
using TransmissionPtr = std::shared_ptr<Transmission>;

std::uint64_t High64(ppp::Int128 value) noexcept {
    return static_cast<std::uint64_t>(value >> 64);
}

bool WaitFor(const std::function<bool()>& predicate,
    std::chrono::milliseconds timeout = 20s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    return predicate();
}

std::shared_ptr<ppp::configurations::AppConfiguration> MakeConfiguration(
    bool server_application, bool policy_enabled) {
    auto configuration =
        std::make_shared<ppp::configurations::AppConfiguration>();
    configuration->tcp.connect.timeout = 5;
    configuration->tcp.connect.nexcept = 0;
    configuration->websocket.host = "localhost";
    configuration->websocket.path = "/transport-auth-capability";
    configuration->websocket.ssl.verify_peer = false;
    configuration->websocket.ssl.ciphersuites.clear();
    if (server_application) {
        configuration->server.transport_auth.enabled = policy_enabled;
        configuration->websocket.ssl.certificate_file =
            OPENPPP2_TEST_CERTIFICATE;
        configuration->websocket.ssl.certificate_key_file =
            OPENPPP2_TEST_PRIVATE_KEY;
        configuration->websocket.ssl.certificate_chain_file =
            OPENPPP2_TEST_CERTIFICATE;
    }
    else {
        configuration->client.transport_auth.enabled = policy_enabled;
        configuration->websocket.ssl.certificate_file.clear();
        configuration->websocket.ssl.certificate_key_file.clear();
        configuration->websocket.ssl.certificate_chain_file.clear();
    }
    return configuration;
}

class ProductionWssPair final {
public:
    ProductionWssPair(ppp::Int128 session_id, bool client_policy,
        bool server_policy, bool mux)
        : context_(std::make_shared<asio::io_context>())
        , guard_(asio::make_work_guard(*context_))
        , session_id_(session_id)
        , mux_(mux) {
        tcp::acceptor acceptor(*context_,
            tcp::endpoint(asio::ip::address_v4::loopback(), 0));
        auto client_socket = std::make_shared<tcp::socket>(*context_);
        auto server_socket = std::make_shared<tcp::socket>(*context_);
        client_socket->connect(acceptor.local_endpoint());
        acceptor.accept(*server_socket);

        client_strand_ = std::make_shared<Transmission::StrandPtr::element_type>(
            asio::make_strand(*context_));
        server_strand_ = std::make_shared<Transmission::StrandPtr::element_type>(
            asio::make_strand(*context_));
        client_ = std::make_shared<Transmission>(context_, client_strand_,
            client_socket, MakeConfiguration(false, client_policy));
        server_ = std::make_shared<Transmission>(context_, server_strand_,
            server_socket, MakeConfiguration(true, server_policy));
    }

    ~ProductionWssPair() noexcept {
        Dispose();
    }

    bool Handshake() {
        for (int i = 0; i < 4; ++i) {
            threads_.emplace_back([context = context_]() noexcept {
                context->run();
            });
        }

        pending_.store(2);
        const bool server_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [this](ppp::coroutines::YieldContext& y) noexcept {
                bool received_mux = false;
                const ppp::Int128 received = server_->HandshakeClient(
                    y, received_mux);
                server_ok_.store(received == session_id_ &&
                    received_mux == mux_);
                pending_.fetch_sub(1);
            });
        const bool client_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [this](ppp::coroutines::YieldContext& y) noexcept {
                client_ok_.store(client_->HandshakeServer(
                    y, session_id_, mux_));
                pending_.fetch_sub(1);
            });
        return server_spawned && client_spawned &&
            WaitFor([this]() { return pending_.load() == 0; }) &&
            server_ok_.load() && client_ok_.load();
    }

    void Dispose() noexcept {
        if (client_) {
            client_->Dispose();
        }
        if (server_) {
            server_->Dispose();
        }
        guard_.reset();
        if (context_) {
            context_->stop();
        }
        for (std::thread& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        threads_.clear();
    }

    TransmissionPtr Client() const noexcept { return client_; }
    TransmissionPtr Server() const noexcept { return server_; }

private:
    std::shared_ptr<asio::io_context> context_;
    asio::executor_work_guard<asio::io_context::executor_type> guard_;
    Transmission::StrandPtr client_strand_;
    Transmission::StrandPtr server_strand_;
    TransmissionPtr client_;
    TransmissionPtr server_;
    ppp::Int128 session_id_;
    bool mux_;
    std::vector<std::thread> threads_;
    std::atomic<int> pending_{0};
    std::atomic<bool> server_ok_{false};
    std::atomic<bool> client_ok_{false};
};

} // namespace

BOOST_AUTO_TEST_CASE(codec_preserves_mux_canary_and_independent_policies) {
    constexpr std::uint64_t canary = 0x1234C0DEC0DEC0DEULL;
    constexpr std::uint64_t entropy = 0xFFEEDDCCBBAA9988ULL;
    const ppp::Int128 original = ppp::MAKE_OWORD(entropy, canary);

    for (const bool client_policy : {false, true}) {
        for (const bool server_policy : {false, true}) {
            for (const bool mux : {false, true}) {
                const ppp::Int128 nmux = Codec::EncodeClientNmux(
                    original, mux, client_policy);
                BOOST_TEST(High64(nmux) == canary);
                BOOST_TEST((static_cast<std::uint64_t>(nmux) & 1ULL) ==
                    (mux ? 1ULL : 0ULL));

                bool supports = false;
                bool policy = false;
                BOOST_TEST(Codec::DecodeClientNmux(
                    nmux, supports, policy));
                BOOST_TEST(supports);
                BOOST_TEST(policy == client_policy);

                const ppp::Int128 ivv = Codec::EncodeServerIvv(
                    original, server_policy);
                BOOST_TEST(static_cast<bool>(ivv));
                BOOST_TEST(High64(ivv) == canary);
                supports = false;
                policy = false;
                BOOST_TEST(Codec::DecodeServerIvv(ivv, supports, policy));
                BOOST_TEST(supports);
                BOOST_TEST(policy == server_policy);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(codec_rejects_legacy_and_opposite_direction_markers) {
    for (std::uint64_t i = 0; i < 1024; ++i) {
        const ppp::Int128 legacy = ppp::MAKE_OWORD(i * 0x9E3779B97F4A7C15ULL,
            0xABC0000000000000ULL + i);
        bool supports = true;
        bool policy = true;
        BOOST_TEST(!Codec::DecodeClientNmux(legacy, supports, policy));
        BOOST_TEST(!supports);
        BOOST_TEST(!policy);

        supports = true;
        policy = true;
        BOOST_TEST(!Codec::DecodeServerIvv(legacy, supports, policy));
        BOOST_TEST(!supports);
        BOOST_TEST(!policy);
    }

    const ppp::Int128 original = ppp::MAKE_OWORD(0x123456789ABCDEF0ULL,
        0x1234C0DEC0DEC0DEULL);
    const ppp::Int128 nmux = Codec::EncodeClientNmux(original, true, true);
    const ppp::Int128 ivv = Codec::EncodeServerIvv(original, true);
    bool supports = true;
    bool policy = true;
    BOOST_TEST(!Codec::DecodeServerIvv(nmux, supports, policy));
    BOOST_TEST(!supports);
    BOOST_TEST(!policy);
    supports = true;
    policy = true;
    BOOST_TEST(!Codec::DecodeClientNmux(ivv, supports, policy));
    BOOST_TEST(!supports);
    BOOST_TEST(!policy);
}

BOOST_AUTO_TEST_CASE(production_wss_handshake_publishes_peer_policy_matrix) {
    int iteration = 0;
    for (const bool client_policy : {false, true}) {
        for (const bool server_policy : {false, true}) {
            const bool mux = (iteration & 1) != 0;
            ProductionWssPair pair(
                static_cast<ppp::Int128>(0x55110000 + iteration),
                client_policy, server_policy, mux);
            BOOST_TEST(!pair.Client()->PeerSupportsTransportAuthV1());
            BOOST_TEST(!pair.Server()->PeerSupportsTransportAuthV1());
            BOOST_REQUIRE(pair.Handshake());

            BOOST_TEST(pair.Server()->PeerSupportsTransportAuthV1());
            BOOST_TEST(pair.Server()->PeerEnablesTransportAuthV1() ==
                client_policy);
            BOOST_TEST(pair.Client()->PeerSupportsTransportAuthV1());
            BOOST_TEST(pair.Client()->PeerEnablesTransportAuthV1() ==
                server_policy);
            BOOST_TEST(static_cast<unsigned>(
                pair.Client()->GetAuthenticatedCarrierKind()) ==
                static_cast<unsigned>(
                    transmissions::AuthenticatedCarrierKind::TlsWebSocket));
            BOOST_TEST(static_cast<unsigned>(
                pair.Client()->GetAuthenticatedCarrierMethod()) ==
                static_cast<unsigned>(
                    transmissions::AuthenticatedCarrierMethod::TlsExporterV1));
            BOOST_TEST(static_cast<unsigned>(
                pair.Server()->GetAuthenticatedCarrierKind()) ==
                static_cast<unsigned>(
                    transmissions::AuthenticatedCarrierKind::TlsWebSocket));
            BOOST_TEST(static_cast<unsigned>(
                pair.Server()->GetAuthenticatedCarrierMethod()) ==
                static_cast<unsigned>(
                    transmissions::AuthenticatedCarrierMethod::TlsExporterV1));

            pair.Dispose();
            BOOST_TEST(!pair.Client()->PeerSupportsTransportAuthV1());
            BOOST_TEST(!pair.Client()->PeerEnablesTransportAuthV1());
            BOOST_TEST(!pair.Server()->PeerSupportsTransportAuthV1());
            BOOST_TEST(!pair.Server()->PeerEnablesTransportAuthV1());
            ++iteration;
        }
    }
}
