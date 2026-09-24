#define BOOST_TEST_MODULE session_resume_establish_transaction_wss_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/server/SessionRecoveryState.h>
#include <ppp/app/server/SessionResumeEstablishTransaction.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace protocol = ppp::app::protocol;
namespace server = ppp::app::server;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

using Transmission = transmissions::ISslWebsocketTransmission;
using TransmissionPtr = std::shared_ptr<Transmission>;
using Control = protocol::SessionResumeControl;
using Fields = protocol::SessionResumeTranscriptFields;

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
        id[i] = static_cast<std::uint8_t>(0x30 + i);
    }
    return id;
}

std::shared_ptr<ppp::configurations::AppConfiguration> MakeConfiguration(
    bool server_side) {
    auto configuration =
        std::make_shared<ppp::configurations::AppConfiguration>();
    configuration->tcp.connect.timeout = 5;
    configuration->tcp.connect.nexcept = 0;
    configuration->websocket.host = "localhost";
    configuration->websocket.path = "/session-resume-establish";
    configuration->websocket.ssl.verify_peer = false;
    configuration->websocket.ssl.ciphersuites.clear();
    if (server_side) {
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

        std::atomic<int> pending{2};
        std::atomic<bool> client_ok{false};
        std::atomic<bool> server_ok{false};
        const bool server_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                bool mux = false;
                server_ok.store(server_->HandshakeClient(y, mux) == session_id_ &&
                    !mux);
                pending.fetch_sub(1);
            });
        const bool client_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                client_ok.store(client_->HandshakeServer(y, session_id_, false));
                pending.fetch_sub(1);
            });
        const bool ok = server_spawned && client_spawned &&
            WaitFor([&pending]() { return pending.load() == 0; }) &&
            server_ok.load() && client_ok.load();
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

    template <typename Server, typename Client>
    bool Exchange(Server&& server, Client&& client,
        bool& server_ok, bool& client_ok) {
        std::atomic<int> pending{2};
        std::atomic<bool> server_result{false};
        std::atomic<bool> client_result{false};
        const bool server_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                server_result.store(server(y));
                pending.fetch_sub(1);
            });
        const bool client_spawned = ppp::coroutines::YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [&](ppp::coroutines::YieldContext& y) noexcept {
                client_result.store(client(y));
                pending.fetch_sub(1);
            });
        const bool completed = server_spawned && client_spawned &&
            WaitFor([&pending]() { return pending.load() == 0; });
        server_ok = server_result.load();
        client_ok = client_result.load();
        return completed;
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
    std::atomic<bool> handshake_ok_{false};
};

template <std::size_t Size>
ppp::string EncodeHex(const std::array<std::uint8_t, Size>& value) {
    static constexpr char Hex[] = "0123456789abcdef";
    ppp::string text(Size * 2, '\0');
    for (std::size_t i = 0; i < Size; ++i) {
        text[i * 2] = Hex[value[i] >> 4];
        text[i * 2 + 1] = Hex[value[i] & 0x0f];
    }
    return text;
}

template <std::size_t Size>
bool DecodeHex(const ppp::string& text,
    std::array<std::uint8_t, Size>& output) noexcept {
    if (text.size() != Size * 2) {
        return false;
    }
    auto nibble = [](char value, std::uint8_t& decoded) noexcept {
        if (value >= '0' && value <= '9') {
            decoded = static_cast<std::uint8_t>(value - '0');
            return true;
        }
        if (value >= 'a' && value <= 'f') {
            decoded = static_cast<std::uint8_t>(value - 'a' + 10);
            return true;
        }
        return false;
    };
    for (std::size_t i = 0; i < Size; ++i) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!nibble(text[i * 2], high) || !nibble(text[i * 2 + 1], low)) {
            return false;
        }
        output[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

template <std::size_t Size>
bool IsZero(const std::array<std::uint8_t, Size>& value) noexcept {
    return std::all_of(value.begin(), value.end(),
        [](std::uint8_t byte) { return byte == 0; });
}

void FillControl(const Fields& fields,
    const protocol::SessionResumeProof& proof, Control& control) {
    control.Clear();
    control.version = Control::ProtocolVersion;
    control.action = fields.action;
    control.capabilities = fields.capabilities;
    control.session_id = EncodeHex(fields.session_id);
    control.generation = fields.generation;
    control.client_nonce = EncodeHex(fields.client_nonce);
    if (fields.action != protocol::SessionResumeAction::ResumeRequest &&
        fields.action != protocol::SessionResumeAction::GenerationSync) {
        control.server_nonce = EncodeHex(fields.server_nonce);
    }
    control.candidate_binding = EncodeHex(fields.candidate_binding);
    control.proof = EncodeHex(proof);
}

bool DecodeControl(const Control& control,
    protocol::SessionResumeAction expected_action,
    const protocol::SessionResumeId& expected_session_id,
    Fields& fields, protocol::SessionResumeProof& proof) noexcept {
    if (!control.Valid() || !control.reason.empty() ||
        control.action != expected_action ||
        control.capabilities != Control::CapabilityV1 ||
        control.session_id != EncodeHex(expected_session_id) ||
        !DecodeHex(control.client_nonce, fields.client_nonce) ||
        (!control.server_nonce.empty() &&
            !DecodeHex(control.server_nonce, fields.server_nonce)) ||
        !DecodeHex(control.candidate_binding, fields.candidate_binding) ||
        !DecodeHex(control.proof, proof)) {
        return false;
    }
    fields.action = expected_action;
    fields.capabilities = control.capabilities;
    fields.session_id = expected_session_id;
    fields.generation = control.generation;
    return true;
}

std::vector<ppp::Byte> EncodeInformation(const Control& control) {
    protocol::VirtualEthernetInformation information;
    information.Clear();
    information.BandwidthQoS = 0;
    information.IncomingTraffic = std::numeric_limits<ppp::UInt64>::max();
    information.OutgoingTraffic = std::numeric_limits<ppp::UInt64>::max();
    information.ExpiredTime = std::numeric_limits<ppp::UInt32>::max();

    protocol::VirtualEthernetInformationExtensions extensions;
    extensions.Clear();
    extensions.SessionResume = control;
    const ppp::string json = extensions.ToJson();

    information.BandwidthQoS =
        ppp::net::Ipep::HostToNetworkOrder(information.BandwidthQoS);
    information.ExpiredTime = htonl(information.ExpiredTime);
    information.IncomingTraffic =
        ppp::net::Ipep::HostToNetworkOrder(information.IncomingTraffic);
    information.OutgoingTraffic =
        ppp::net::Ipep::HostToNetworkOrder(information.OutgoingTraffic);

    std::vector<ppp::Byte> frame(1 + sizeof(information) + json.size());
    frame[0] = static_cast<ppp::Byte>(
        protocol::VirtualEthernetLinklayer::PacketAction_INFO);
    std::memcpy(frame.data() + 1, &information, sizeof(information));
    std::memcpy(frame.data() + 1 + sizeof(information),
        json.data(), json.size());
    return frame;
}

bool SendControl(const TransmissionPtr& transmission,
    ppp::coroutines::YieldContext& y, const Control& control) noexcept {
    if (!transmission || !control.Valid()) {
        return false;
    }
    const std::vector<ppp::Byte> frame = EncodeInformation(control);
    return transmission->Write(y, frame.data(), static_cast<int>(frame.size()));
}

bool ReadControl(const TransmissionPtr& transmission,
    ppp::coroutines::YieldContext& y, Control& control) noexcept {
    int length = 0;
    std::shared_ptr<ppp::Byte> packet = transmission->Read(y, length);
    protocol::VirtualEthernetLinklayer::InformationEnvelope envelope;
    if (!packet || !protocol::VirtualEthernetLinklayer::DecodeInformation(
            packet.get(), length, envelope)) {
        return false;
    }
    protocol::VirtualEthernetInformationExtensions extensions =
        envelope.Extensions;
    control = extensions.SessionResume;
    extensions.SessionResume.Clear();
    return control.HasAny() && !extensions.HasAny();
}

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

class RecoveryOperations final : public server::SessionResumeEstablishOperations {
public:
    RecoveryOperations(const TransmissionPtr& old_carrier,
        const TransmissionPtr& candidate_carrier,
        ppp::coroutines::YieldContext& y,
        protocol::SessionResumeSecret& retained_root,
        const protocol::SessionResumeId& session_id,
        const protocol::SessionResumeCandidateBinding& candidate_binding,
        bool fail_committed_write = false,
        bool fail_publish = false) noexcept
        : active_carrier_(old_carrier)
        , candidate_carrier_(candidate_carrier)
        , y_(y)
        , retained_root_(retained_root)
        , session_id_(session_id)
        , candidate_binding_(candidate_binding)
        , fail_committed_write_(fail_committed_write)
        , fail_publish_(fail_publish) {
        suspended_ = recovery_.Suspend(1, 100, 1000);
    }

    bool ReadControl(Control& control) noexcept override {
        return ::ReadControl(candidate_carrier_, y_, control);
    }

    bool SendControl(const Control& control) noexcept override {
        if (control.action == protocol::SessionResumeAction::ResumeCommitted &&
            fail_committed_write_) {
            return false;
        }
        const bool sent = ::SendControl(candidate_carrier_, y_, control);
        if (sent && control.action ==
                protocol::SessionResumeAction::ResumeCommitted) {
            committed_written_ = true;
        }
        if (sent && control.action ==
                protocol::SessionResumeAction::GenerationSync) {
            ++generation_sync_count_;
        }
        return sent;
    }

    server::SessionResumeTransactionBeginStatus Begin(
        const Control& request, std::uint64_t& reservation_token,
        Control& response) noexcept override {
        reservation_token = 0;
        Fields request_fields;
        protocol::SessionResumeProof request_proof{};
        if (!DecodeControl(request,
                protocol::SessionResumeAction::ResumeRequest, session_id_,
                request_fields, request_proof) ||
            request_fields.candidate_binding != candidate_binding_ ||
            !IsZero(request_fields.server_nonce) ||
            !protocol::VerifySessionResumeProof(
                retained_root_, request_fields, request_proof) ||
            !recovery_.IsSuspended(120)) {
            return server::SessionResumeTransactionBeginStatus::Rejected;
        }

        Fields response_fields = request_fields;
        response_fields.action =
            request_fields.generation == recovery_.GetGeneration()
            ? protocol::SessionResumeAction::ResumeAccept
            : protocol::SessionResumeAction::GenerationSync;
        response_fields.generation = recovery_.GetGeneration();
        response_fields.server_nonce.fill(0);
        if (response_fields.action ==
                protocol::SessionResumeAction::ResumeAccept &&
            !protocol::GenerateSessionResumeNonce(
                response_fields.server_nonce)) {
            return server::SessionResumeTransactionBeginStatus::Rejected;
        }

        protocol::SessionResumeProof response_proof{};
        if (!protocol::ComputeSessionResumeProof(
                retained_root_, response_fields, response_proof)) {
            return server::SessionResumeTransactionBeginStatus::Rejected;
        }
        FillControl(response_fields, response_proof, response);
        if (response_fields.action ==
                protocol::SessionResumeAction::GenerationSync) {
            return server::SessionResumeTransactionBeginStatus::GenerationSync;
        }

        reservation_token = ++next_token_;
        if (!recovery_.ReserveResume(response_fields.generation, 120,
                reservation_token)) {
            return server::SessionResumeTransactionBeginStatus::Rejected;
        }
        accepted_ = response_fields;
        attempt_active_ = true;
        return server::SessionResumeTransactionBeginStatus::Accepted;
    }

    bool Commit(const Control& confirm, std::uint64_t reservation_token,
        Control& committed) noexcept override {
        Fields confirm_fields;
        protocol::SessionResumeProof confirm_proof{};
        if (!attempt_active_ ||
            !DecodeControl(confirm,
                protocol::SessionResumeAction::ResumeConfirm, session_id_,
                confirm_fields, confirm_proof) ||
            confirm_fields.generation != accepted_.generation ||
            confirm_fields.client_nonce != accepted_.client_nonce ||
            confirm_fields.server_nonce != accepted_.server_nonce ||
            confirm_fields.candidate_binding != accepted_.candidate_binding ||
            !protocol::VerifySessionResumeProof(
                retained_root_, confirm_fields, confirm_proof) ||
            !recovery_.CanCommitResume(
                accepted_.generation, 120, reservation_token) ||
            !recovery_.MarkResumeCommitted(reservation_token, 120, 100)) {
            return false;
        }

        Fields committed_fields = accepted_;
        committed_fields.action =
            protocol::SessionResumeAction::ResumeCommitted;
        committed_fields.generation = accepted_.generation + 1;
        protocol::SessionResumeProof committed_proof{};
        if (!protocol::ComputeSessionResumeProof(
                retained_root_, committed_fields, committed_proof)) {
            return false;
        }
        FillControl(committed_fields, committed_proof, committed);
        return committed.Valid();
    }

    bool Publish(std::uint64_t reservation_token) noexcept override {
        publish_after_committed_write_ = committed_written_;
        if (fail_publish_) {
            return false;
        }
        return server::CommitSessionResumeAndPublish(recovery_,
            accepted_.generation, 120, reservation_token,
            [&](std::uint64_t) noexcept {
                active_carrier_ = candidate_carrier_;
                attempt_active_ = false;
                published_ = true;
            });
    }

    void Cancel(std::uint64_t reservation_token) noexcept override {
        ++cancel_count_;
        if (recovery_.CancelResume(reservation_token)) {
            attempt_active_ = false;
        }
    }

    server::SessionRecoveryState recovery_;
    TransmissionPtr active_carrier_;
    const TransmissionPtr candidate_carrier_;
    ppp::coroutines::YieldContext& y_;
    protocol::SessionResumeSecret& retained_root_;
    const protocol::SessionResumeId session_id_;
    const protocol::SessionResumeCandidateBinding candidate_binding_;
    Fields accepted_;
    std::uint64_t next_token_ = 40;
    const std::uint64_t logical_session_identity_ = 0x1122334455667788ull;
    const std::uint32_t assigned_ip_nat_identity_ = 0x0a000002u;
    const std::uint64_t udp_manager_identity_ = 0x8877665544332211ull;
    unsigned int generation_sync_count_ = 0;
    unsigned int cancel_count_ = 0;
    bool suspended_ = false;
    bool attempt_active_ = false;
    bool committed_written_ = false;
    bool publish_after_committed_write_ = false;
    bool published_ = false;
    const bool fail_committed_write_;
    const bool fail_publish_;
};

Control MakeRequest(protocol::SessionResumeSecret& root,
    const protocol::SessionResumeId& session_id,
    const protocol::SessionResumeCandidateBinding& binding,
    std::uint64_t generation) {
    Fields fields;
    fields.action = protocol::SessionResumeAction::ResumeRequest;
    fields.capabilities = Control::CapabilityV1;
    fields.session_id = session_id;
    fields.generation = generation;
    fields.candidate_binding = binding;
    protocol::GenerateSessionResumeNonce(fields.client_nonce);
    protocol::SessionResumeProof proof{};
    protocol::ComputeSessionResumeProof(root, fields, proof);
    Control request;
    FillControl(fields, proof, request);
    return request;
}

bool RunClientResume(const TransmissionPtr& transmission,
    ppp::coroutines::YieldContext& y,
    protocol::SessionResumeSecret& retained_root,
    const protocol::SessionResumeId& session_id,
    const protocol::SessionResumeCandidateBinding& binding,
    std::uint64_t initial_generation,
    bool expect_committed,
    bool corrupt_confirm = false) noexcept {
    Control request = MakeRequest(retained_root, session_id, binding,
        initial_generation);
    if (!SendControl(transmission, y, request)) {
        return false;
    }

    Control response;
    if (!ReadControl(transmission, y, response)) {
        return false;
    }
    if (response.action == protocol::SessionResumeAction::GenerationSync) {
        Fields sync_fields;
        protocol::SessionResumeProof sync_proof{};
        if (!DecodeControl(response,
                protocol::SessionResumeAction::GenerationSync, session_id,
                sync_fields, sync_proof) ||
            !protocol::VerifySessionResumeProof(
                retained_root, sync_fields, sync_proof) ||
            sync_fields.client_nonce != [&]() {
                Fields request_fields;
                protocol::SessionResumeProof ignored{};
                DecodeControl(request,
                    protocol::SessionResumeAction::ResumeRequest, session_id,
                    request_fields, ignored);
                return request_fields.client_nonce;
            }()) {
            return false;
        }
        request = MakeRequest(retained_root, session_id, binding,
            sync_fields.generation);
        if (!SendControl(transmission, y, request) ||
            !ReadControl(transmission, y, response)) {
            return false;
        }
    }

    Fields accepted_fields;
    protocol::SessionResumeProof accepted_proof{};
    if (!DecodeControl(response,
            protocol::SessionResumeAction::ResumeAccept, session_id,
            accepted_fields, accepted_proof) ||
        accepted_fields.candidate_binding != binding ||
        !protocol::VerifySessionResumeProof(
            retained_root, accepted_fields, accepted_proof)) {
        return false;
    }

    Fields confirm_fields = accepted_fields;
    confirm_fields.action = protocol::SessionResumeAction::ResumeConfirm;
    protocol::SessionResumeProof confirm_proof{};
    if (!protocol::ComputeSessionResumeProof(
            retained_root, confirm_fields, confirm_proof)) {
        return false;
    }
    Control confirm;
    FillControl(confirm_fields, confirm_proof, confirm);
    if (corrupt_confirm && !confirm.proof.empty()) {
        confirm.proof[0] = confirm.proof[0] == '0' ? '1' : '0';
    }
    if (!SendControl(transmission, y, confirm)) {
        return false;
    }
    if (!expect_committed) {
        return true;
    }

    Control committed;
    Fields committed_fields;
    protocol::SessionResumeProof committed_proof{};
    return ReadControl(transmission, y, committed) &&
        DecodeControl(committed,
            protocol::SessionResumeAction::ResumeCommitted, session_id,
            committed_fields, committed_proof) &&
        committed_fields.generation == accepted_fields.generation + 1 &&
        protocol::VerifySessionResumeProof(
            retained_root, committed_fields, committed_proof);
}

struct RoamingFixture final {
    explicit RoamingFixture(ppp::Int128 application_session_id)
        : old_pair(application_session_id)
        , new_pair(application_session_id) {
    }

    bool Prepare() {
        if (!old_pair.Handshake()) {
            return false;
        }
        if (!old_pair.DeriveOnBoth(old_client_root, old_server_root,
                RetainedRootDeriver(session_id))) {
            return false;
        }
        if (!old_pair.DeriveOnBoth(old_client_binding, old_server_binding,
                CandidateDeriver(session_id))) {
            return false;
        }
        old_server_carrier = old_pair.Server();
        old_pair.Dispose();

        return new_pair.Handshake() &&
            new_pair.DeriveOnBoth(new_client_binding, new_server_binding,
                CandidateDeriver(session_id));
    }

    protocol::SessionResumeId session_id = MakeSessionId();
    ProductionWssPair old_pair;
    ProductionWssPair new_pair;
    TransmissionPtr old_server_carrier;
    protocol::SessionResumeSecret old_client_root;
    protocol::SessionResumeSecret old_server_root;
    protocol::SessionResumeCandidateBinding old_client_binding{};
    protocol::SessionResumeCandidateBinding old_server_binding{};
    protocol::SessionResumeCandidateBinding new_client_binding{};
    protocol::SessionResumeCandidateBinding new_server_binding{};
};

} // namespace

BOOST_AUTO_TEST_CASE(new_production_wss_carrier_publishes_after_committed_write) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0x51525354));
    BOOST_REQUIRE(fixture.Prepare());
    BOOST_TEST(fixture.new_client_binding == fixture.new_server_binding);
    BOOST_TEST(fixture.new_client_binding != fixture.old_client_binding);

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                server::SessionResumeTransactionOutcome::Resumed;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            return RunClientResume(fixture.new_pair.Client(), y,
                fixture.old_client_root, fixture.session_id,
                fixture.new_client_binding, 1, true);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(operations->suspended_);
    BOOST_TEST(operations->published_);
    BOOST_TEST(operations->committed_written_);
    BOOST_TEST(operations->publish_after_committed_write_);
    BOOST_TEST(operations->recovery_.GetGeneration() == 2u);
    BOOST_TEST(operations->active_carrier_ == fixture.new_pair.Server());
    BOOST_TEST(operations->logical_session_identity_ == 0x1122334455667788ull);
    BOOST_TEST(operations->assigned_ip_nat_identity_ == 0x0a000002u);
    BOOST_TEST(operations->udp_manager_identity_ == 0x8877665544332211ull);
}

BOOST_AUTO_TEST_CASE(stale_generation_syncs_once_then_resumes) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0x61626364));
    BOOST_REQUIRE(fixture.Prepare());

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                server::SessionResumeTransactionOutcome::Resumed;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            return RunClientResume(fixture.new_pair.Client(), y,
                fixture.old_client_root, fixture.session_id,
                fixture.new_client_binding, 0, true);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(operations->generation_sync_count_ == 1u);
    BOOST_TEST(operations->recovery_.GetGeneration() == 2u);
}

BOOST_AUTO_TEST_CASE(committed_write_failure_cancels_without_publication) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0x71727374));
    BOOST_REQUIRE(fixture.Prepare());

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding, true);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                server::SessionResumeTransactionOutcome::PreserveSuspended;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            return RunClientResume(fixture.new_pair.Client(), y,
                fixture.old_client_root, fixture.session_id,
                fixture.new_client_binding, 1, false);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(!operations->published_);
    BOOST_TEST(!operations->committed_written_);
    BOOST_TEST(operations->cancel_count_ == 1u);
    BOOST_TEST(operations->recovery_.GetGeneration() == 1u);
    BOOST_TEST(operations->recovery_.IsSuspended(120));
    BOOST_TEST(operations->active_carrier_ == fixture.old_server_carrier);
}

BOOST_AUTO_TEST_CASE(bad_confirm_cancels_without_generation_change) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0x81828384));
    BOOST_REQUIRE(fixture.Prepare());

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                server::SessionResumeTransactionOutcome::Rejected;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            return RunClientResume(fixture.new_pair.Client(), y,
                fixture.old_client_root, fixture.session_id,
                fixture.new_client_binding, 1, false, true);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(!operations->published_);
    BOOST_TEST(operations->cancel_count_ == 1u);
    BOOST_TEST(operations->recovery_.GetGeneration() == 1u);
    BOOST_TEST(operations->recovery_.IsSuspended(120));
}

BOOST_AUTO_TEST_CASE(old_carrier_binding_is_rejected_on_new_wss_carrier) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0x91929394));
    BOOST_REQUIRE(fixture.Prepare());

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                    server::SessionResumeTransactionOutcome::Rejected &&
                result.fallback_reason ==
                    server::SessionResumeFallbackReason::BeginRejected;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            Control request = MakeRequest(fixture.old_client_root,
                fixture.session_id, fixture.old_client_binding, 1);
            return SendControl(fixture.new_pair.Client(), y, request);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(!operations->published_);
    BOOST_TEST(operations->cancel_count_ == 0u);
    BOOST_TEST(operations->recovery_.GetGeneration() == 1u);
    BOOST_TEST(operations->recovery_.IsSuspended(120));
}

BOOST_AUTO_TEST_CASE(publish_failure_is_fatal_and_cancels_reservation) {
    RoamingFixture fixture(static_cast<ppp::Int128>(0xa1a2a3a4));
    BOOST_REQUIRE(fixture.Prepare());

    bool server_ok = false;
    bool client_ok = false;
    std::unique_ptr<RecoveryOperations> operations;
    server::SessionResumeTransactionResult result;
    BOOST_REQUIRE(fixture.new_pair.Exchange(
        [&](ppp::coroutines::YieldContext& y) noexcept {
            operations = std::make_unique<RecoveryOperations>(
                fixture.old_server_carrier, fixture.new_pair.Server(), y,
                fixture.old_server_root, fixture.session_id,
                fixture.new_server_binding, false, true);
            result = server::RunSessionResumeEstablishTransaction(*operations);
            return result.outcome ==
                server::SessionResumeTransactionOutcome::Fatal;
        },
        [&](ppp::coroutines::YieldContext& y) noexcept {
            return RunClientResume(fixture.new_pair.Client(), y,
                fixture.old_client_root, fixture.session_id,
                fixture.new_client_binding, 1, true);
        }, server_ok, client_ok));

    BOOST_TEST(server_ok);
    BOOST_TEST(client_ok);
    BOOST_REQUIRE(operations);
    BOOST_TEST(!operations->published_);
    BOOST_TEST(operations->committed_written_);
    BOOST_TEST(operations->publish_after_committed_write_);
    BOOST_TEST(operations->cancel_count_ == 1u);
    BOOST_TEST(operations->recovery_.GetGeneration() == 1u);
    BOOST_TEST(operations->recovery_.IsSuspended(120));
}
