#define BOOST_TEST_MODULE session_resume_production_wss_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/IAuthenticatedCarrierBinding.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace protocol = ppp::app::protocol;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

using Transmission = transmissions::ISslWebsocketTransmission;
using TransmissionPtr = std::shared_ptr<Transmission>;

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

protocol::SessionResumeId MakeSessionId() noexcept {
    protocol::SessionResumeId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<std::uint8_t>(0x20 + i);
    }
    return id;
}

std::shared_ptr<ppp::configurations::AppConfiguration> MakeConfiguration(
    bool server) {
    auto configuration =
        std::make_shared<ppp::configurations::AppConfiguration>();
    configuration->tcp.connect.timeout = 5;
    configuration->tcp.connect.nexcept = 0;
    configuration->websocket.host = "localhost";
    configuration->websocket.path = "/session-resume-production";
    configuration->websocket.ssl.verify_peer = false;
    configuration->websocket.ssl.ciphersuites.clear();
    if (server) {
        configuration->websocket.ssl.certificate_file =
            OPENPPP2_TEST_CERTIFICATE;
        configuration->websocket.ssl.certificate_key_file =
            OPENPPP2_TEST_PRIVATE_KEY;
        configuration->websocket.ssl.certificate_chain_file =
            OPENPPP2_TEST_CERTIFICATE;
    }
    else {
        configuration->websocket.ssl.certificate_file.clear();
        configuration->websocket.ssl.certificate_key_file.clear();
        configuration->websocket.ssl.certificate_chain_file.clear();
    }
    return configuration;
}

class ProductionWssPair final {
public:
    explicit ProductionWssPair(ppp::Int128 session_id)
        : context_(std::make_shared<asio::io_context>())
        , guard_(asio::make_work_guard(*context_))
        , session_id_(session_id) {
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
            client_socket, MakeConfiguration(false));
        server_ = std::make_shared<Transmission>(context_, server_strand_,
            server_socket, MakeConfiguration(true));
    }

    ~ProductionWssPair() noexcept {
        Dispose();
    }

    bool Handshake() {
        if (!threads_.empty()) {
            return handshake_ok_.load();
        }
        for (int i = 0; i < 4; ++i) {
            threads_.emplace_back([context = context_]() noexcept {
                context->run();
            });
        }

        pending_.store(2);
        const bool server_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [this](ppp::coroutines::YieldContext& y) noexcept {
                bool mux = false;
                const ppp::Int128 received = server_->HandshakeClient(y, mux);
                server_handshake_ok_.store(received == session_id_ && !mux);
                pending_.fetch_sub(1);
            });
        const bool client_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [this](ppp::coroutines::YieldContext& y) noexcept {
                client_handshake_ok_.store(
                    client_->HandshakeServer(y, session_id_, false));
                pending_.fetch_sub(1);
            });
        if (!server_spawned || !client_spawned ||
            !WaitFor([this]() { return pending_.load() == 0; })) {
            return false;
        }
        const bool ok = server_handshake_ok_.load() &&
            client_handshake_ok_.load();
        handshake_ok_.store(ok);
        return ok;
    }

    template <typename Value, typename Derive>
    bool DeriveOnBoth(Value& client_value, Value& server_value,
        Derive&& derive) {
        std::atomic<int> pending{2};
        std::atomic<bool> client_ok{false};
        std::atomic<bool> server_ok{false};
        const bool client_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [&, derive](ppp::coroutines::YieldContext&) mutable noexcept {
                client_ok.store(derive(client_, client_value));
                pending.fetch_sub(1);
            });
        const bool server_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [&, derive](ppp::coroutines::YieldContext&) mutable noexcept {
                server_ok.store(derive(server_, server_value));
                pending.fetch_sub(1);
            });
        return client_spawned && server_spawned &&
            WaitFor([&pending]() { return pending.load() == 0; }) &&
            client_ok.load() && server_ok.load();
    }

    bool RoundTrip(const std::string& payload) {
        std::atomic<int> pending{2};
        std::atomic<bool> write_ok{false};
        std::atomic<bool> read_ok{false};
        std::string received;

        const bool read_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                int length = 0;
                std::shared_ptr<ppp::Byte> packet = server_->Read(y, length);
                if (packet && length > 0) {
                    received.assign(reinterpret_cast<const char*>(packet.get()),
                        static_cast<std::size_t>(length));
                    read_ok.store(received == payload);
                }
                pending.fetch_sub(1);
            });
        const bool write_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                write_ok.store(client_->Write(
                    y, payload.data(), static_cast<int>(payload.size())));
                pending.fetch_sub(1);
            });
        return read_spawned && write_spawned &&
            WaitFor([&pending]() { return pending.load() == 0; }) &&
            write_ok.load() && read_ok.load();
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
    std::vector<std::thread> threads_;
    std::atomic<int> pending_{0};
    std::atomic<bool> server_handshake_ok_{false};
    std::atomic<bool> client_handshake_ok_{false};
    std::atomic<bool> handshake_ok_{false};
};

auto RetainedRootDeriver(const protocol::SessionResumeId& id) {
    return [id](const TransmissionPtr& transmission,
        protocol::SessionResumeSecret& output) noexcept {
        return protocol::DeriveSessionResumeRetainedRoot(
            [transmission](const char* label, const std::uint8_t* context,
                std::size_t context_length, std::uint8_t* result,
                std::size_t result_length) noexcept {
                return transmission->ExportAuthenticatedSessionKey(label,
                    context, context_length, result, result_length);
            }, id, output);
    };
}

auto CandidateDeriver(const protocol::SessionResumeId& id) {
    return [id](const TransmissionPtr& transmission,
        protocol::SessionResumeCandidateBinding& output) noexcept {
        return protocol::DeriveSessionResumeCandidateBinding(
            [transmission](const char* label, const std::uint8_t* context,
                std::size_t context_length, std::uint8_t* result,
                std::size_t result_length) noexcept {
                return transmission->ExportAuthenticatedSessionKey(label,
                    context, context_length, result, result_length);
            }, id, output);
    };
}

} // namespace

BOOST_AUTO_TEST_CASE(exporter_is_gated_by_application_handshake_and_dispose) {
    const ppp::Int128 session_id = static_cast<ppp::Int128>(0x12345678);
    const protocol::SessionResumeId id = MakeSessionId();
    ProductionWssPair pair(session_id);
    std::shared_ptr<transmissions::IAuthenticatedCarrierBinding> binding = pair.Client();

    std::array<std::uint8_t, 32> output{};
    BOOST_TEST(!binding->HasAuthenticatedSessionExporter());
    BOOST_TEST(!binding->ExportAuthenticatedSessionKey(
        "openppp2-test", id.data(), id.size(), output.data(), output.size()));

    BOOST_REQUIRE(pair.Handshake());
    BOOST_TEST(pair.Client()->IsHandshakeComplete());
    BOOST_TEST(pair.Server()->IsHandshakeComplete());
    BOOST_TEST(binding->HasAuthenticatedSessionExporter());
    BOOST_TEST(pair.Server()->HasAuthenticatedSessionExporter());

    protocol::SessionResumeSecret client_root{};
    protocol::SessionResumeSecret server_root{};
    BOOST_REQUIRE(pair.DeriveOnBoth(
        client_root, server_root, RetainedRootDeriver(id)));
    BOOST_TEST(std::memcmp(client_root.data(), server_root.data(),
        protocol::SessionResumeSecretSize) == 0);

    pair.Dispose();
    BOOST_TEST(!binding->HasAuthenticatedSessionExporter());
    output.fill(0);
    BOOST_TEST(!binding->ExportAuthenticatedSessionKey(
        "openppp2-test", id.data(), id.size(), output.data(), output.size()));
}

BOOST_AUTO_TEST_CASE(loopback_ingress_disables_wss_tls_exporter) {
    const ppp::Int128 session_id = static_cast<ppp::Int128>(0xabcdef);
    const protocol::SessionResumeId id = MakeSessionId();
    ProductionWssPair pair(session_id);
    BOOST_REQUIRE(pair.Handshake());
    BOOST_TEST(pair.Server()->HasAuthenticatedSessionExporter());

    pair.Server()->MarkServerLoopbackIngress();
    BOOST_TEST(pair.Server()->IsServerLoopbackIngress());
    BOOST_TEST(!pair.Server()->HasAuthenticatedSessionExporter());

    std::array<std::uint8_t, 32> output{};
    BOOST_TEST(!pair.Server()->ExportAuthenticatedSessionKey(
        protocol::SessionResumeRootExporterLabel,
        id.data(), id.size(), output.data(), output.size()));
    pair.Dispose();
}

BOOST_AUTO_TEST_CASE(production_framed_io_and_new_carrier_binding) {
    const ppp::Int128 session_id = static_cast<ppp::Int128>(0x22334455);
    const protocol::SessionResumeId id = MakeSessionId();
    ProductionWssPair old_pair(session_id);
    BOOST_REQUIRE(old_pair.Handshake());
    BOOST_REQUIRE(old_pair.RoundTrip(
        R"({"session-resume":{"version":1,"action":"probe"}})"));

    protocol::SessionResumeSecret client_root{};
    protocol::SessionResumeSecret server_root{};
    BOOST_REQUIRE(old_pair.DeriveOnBoth(
        client_root, server_root, RetainedRootDeriver(id)));
    BOOST_TEST(std::memcmp(client_root.data(), server_root.data(),
        protocol::SessionResumeSecretSize) == 0);
    protocol::SessionResumeCandidateBinding old_client_binding{};
    protocol::SessionResumeCandidateBinding old_server_binding{};
    BOOST_REQUIRE(old_pair.DeriveOnBoth(old_client_binding,
        old_server_binding, CandidateDeriver(id)));
    BOOST_TEST(old_client_binding == old_server_binding);
    old_pair.Dispose();

    ProductionWssPair new_pair(session_id);
    BOOST_REQUIRE(new_pair.Handshake());
    protocol::SessionResumeCandidateBinding new_client_binding{};
    protocol::SessionResumeCandidateBinding new_server_binding{};
    BOOST_REQUIRE(new_pair.DeriveOnBoth(new_client_binding,
        new_server_binding, CandidateDeriver(id)));
    BOOST_TEST(new_client_binding == new_server_binding);
    BOOST_TEST(new_client_binding != old_client_binding);

    protocol::SessionResumeTranscriptFields request;
    request.action = protocol::SessionResumeAction::ResumeRequest;
    request.capabilities = protocol::SessionResumeControl::CapabilityV1;
    request.session_id = id;
    request.generation = 1;
    request.candidate_binding = new_client_binding;
    BOOST_REQUIRE(protocol::GenerateSessionResumeNonce(request.client_nonce));
    protocol::SessionResumeProof proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(
        client_root, request, proof));
    BOOST_TEST(protocol::VerifySessionResumeProof(server_root, request, proof));

    protocol::SessionResumeTranscriptFields rebound = request;
    rebound.candidate_binding = old_server_binding;
    BOOST_TEST(!protocol::VerifySessionResumeProof(server_root, rebound, proof));
}

BOOST_AUTO_TEST_CASE(repeated_production_handshake_io_and_teardown) {
    const protocol::SessionResumeId id = MakeSessionId();
    for (int iteration = 0; iteration < 5; ++iteration) {
        ProductionWssPair pair(static_cast<ppp::Int128>(0x33445500 + iteration));
        BOOST_REQUIRE(pair.Handshake());
        BOOST_REQUIRE(pair.RoundTrip("roaming-lifecycle-" +
            std::to_string(iteration)));
        protocol::SessionResumeCandidateBinding client_binding{};
        protocol::SessionResumeCandidateBinding server_binding{};
        BOOST_REQUIRE(pair.DeriveOnBoth(client_binding,
            server_binding, CandidateDeriver(id)));
        BOOST_TEST(client_binding == server_binding);
        pair.Dispose();
        BOOST_TEST(!pair.Client()->HasAuthenticatedSessionExporter());
        BOOST_TEST(!pair.Server()->HasAuthenticatedSessionExporter());
    }
}
