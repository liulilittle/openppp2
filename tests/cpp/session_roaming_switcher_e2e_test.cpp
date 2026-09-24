#include <ppp/stdafx.h>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/tcp.h>
#include <ppp/p2p/P2PDefs.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace asio = boost::asio;
namespace protocol = ppp::app::protocol;
namespace server = ppp::app::server;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;
using namespace std::chrono_literals;

namespace {

using Transmission = transmissions::ISslWebsocketTransmission;
using TransmissionPtr = std::shared_ptr<Transmission>;
using StrandPtr = Transmission::StrandPtr;
using Control = protocol::SessionResumeControl;
using Fields = protocol::SessionResumeTranscriptFields;
using YieldContext = ppp::coroutines::YieldContext;

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Predicate>
bool WaitFor(Predicate&& predicate, std::chrono::milliseconds timeout = 20s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    return predicate();
}

std::shared_ptr<ppp::configurations::AppConfiguration> MakeWssConfiguration(
    bool server_side) {
    auto configuration =
        std::make_shared<ppp::configurations::AppConfiguration>();
    Require(configuration->Normalize(), "WSS configuration normalization failed");
    configuration->tcp.connect.timeout = 5;
    configuration->tcp.connect.nexcept = 0;
    configuration->websocket.host = "localhost";
    configuration->websocket.path = "/session-roaming-e2e";
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

std::shared_ptr<ppp::configurations::AppConfiguration>
MakeSwitcherConfiguration() {
    auto configuration =
        std::make_shared<ppp::configurations::AppConfiguration>();
    configuration->ip.interface_ = "127.0.0.1";
    configuration->tcp.connect.timeout = 5;
    configuration->tcp.connect.nexcept = 0;
    configuration->udp.dns.cache = false;
    configuration->server.subnet = true;
    configuration->server.session_resume.enabled = true;
    configuration->server.session_resume.grace_ms = 20000;
    Require(configuration->Normalize(),
        "switcher configuration normalization failed");
    return configuration;
}

class SharedContextWssPair final {
public:
    SharedContextWssPair(
        const std::shared_ptr<asio::io_context>& context,
        const ppp::Int128& session_id)
        : context_(context)
        , session_id_(session_id) {
        Require(static_cast<bool>(context_), "WSS pair context is null");

        tcp::acceptor acceptor(*context_,
            tcp::endpoint(asio::ip::address_v4::loopback(), 0));
        auto client_socket = std::make_shared<tcp::socket>(*context_);
        auto server_socket = std::make_shared<tcp::socket>(*context_);
        client_socket->connect(acceptor.local_endpoint());
        client_native_handle_ = client_socket->native_handle();
        client_native_handle_valid_ = true;
        acceptor.accept(*server_socket);

        client_strand_ = std::make_shared<StrandPtr::element_type>(
            asio::make_strand(*context_));
        server_strand_ = std::make_shared<StrandPtr::element_type>(
            asio::make_strand(*context_));
        client_ = std::make_shared<Transmission>(context_, client_strand_,
            client_socket, MakeWssConfiguration(false));
        server_ = std::make_shared<Transmission>(context_, server_strand_,
            server_socket, MakeWssConfiguration(true));
    }

    ~SharedContextWssPair() noexcept {
        Dispose();
    }

    bool Handshake() {
        std::atomic<int> pending{2};
        std::atomic<bool> client_ok{false};
        std::atomic<bool> server_ok{false};
        const bool server_spawned = YieldContext::Spawn(
            nullptr, *context_, server_strand_.get(),
            [&](YieldContext& y) noexcept {
                bool mux = false;
                server_ok.store(server_->HandshakeClient(y, mux) == session_id_ &&
                    !mux);
                pending.fetch_sub(1);
            });
        const bool client_spawned = YieldContext::Spawn(
            nullptr, *context_, client_strand_.get(),
            [&](YieldContext& y) noexcept {
                client_ok.store(client_->HandshakeServer(y, session_id_, false));
                pending.fetch_sub(1);
            });
        const bool completed = WaitFor([&]() { return pending.load() == 0; });
        const bool ok = server_spawned && client_spawned && completed &&
            server_ok.load() && client_ok.load();
        if (!ok) {
            std::cerr << "WSS handshake details: server_spawned="
                      << server_spawned << " client_spawned=" << client_spawned
                      << " pending=" << pending.load()
                      << " server_ok=" << server_ok.load()
                      << " client_ok=" << client_ok.load() << '\n';
        }
        return ok;
    }

    void AbortClient() noexcept {
        if (!client_native_handle_valid_) {
            return;
        }
#if defined(_WIN32)
        ::shutdown(client_native_handle_, SD_SEND);
#else
        ::shutdown(client_native_handle_, SHUT_WR);
#endif
        client_native_handle_valid_ = false;
    }

    void Dispose() noexcept {
        if (client_) {
            client_->Dispose();
        }
        if (server_) {
            server_->Dispose();
        }
    }

    const TransmissionPtr& Client() const noexcept { return client_; }
    const TransmissionPtr& Server() const noexcept { return server_; }
    const StrandPtr& ClientStrand() const noexcept { return client_strand_; }
    const StrandPtr& ServerStrand() const noexcept { return server_strand_; }

private:
    std::shared_ptr<asio::io_context> context_;
    ppp::Int128 session_id_;
    tcp::socket::native_handle_type client_native_handle_{};
    bool client_native_handle_valid_ = false;
    StrandPtr client_strand_;
    StrandPtr server_strand_;
    TransmissionPtr client_;
    TransmissionPtr server_;
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
        if (!nibble(text[i * 2], high) ||
            !nibble(text[i * 2 + 1], low)) {
            output.fill(0);
            return false;
        }
        output[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
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
    if (fields.action != protocol::SessionResumeAction::Accepted) {
        control.candidate_binding = EncodeHex(fields.candidate_binding);
    }
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
    YieldContext& y, const Control& control) noexcept {
    if (!transmission || !control.Valid()) {
        return false;
    }
    const std::vector<ppp::Byte> frame = EncodeInformation(control);
    return transmission->Write(y, frame.data(), static_cast<int>(frame.size()));
}

bool ReadControl(const TransmissionPtr& transmission,
    YieldContext& y, Control& control) noexcept {
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

bool DeriveRetainedRoot(const TransmissionPtr& transmission,
    const protocol::SessionResumeId& id,
    protocol::SessionResumeSecret& output) noexcept {
    return protocol::DeriveSessionResumeRetainedRoot(
        [transmission](const char* label, const std::uint8_t* context,
            std::size_t context_length, std::uint8_t* result,
            std::size_t result_length) noexcept {
            return transmission->ExportAuthenticatedSessionKey(
                label, context, context_length, result, result_length);
        }, id, output);
}

bool DeriveCandidateBinding(const TransmissionPtr& transmission,
    const protocol::SessionResumeId& id,
    protocol::SessionResumeCandidateBinding& output) noexcept {
    return protocol::DeriveSessionResumeCandidateBinding(
        [transmission](const char* label, const std::uint8_t* context,
            std::size_t context_length, std::uint8_t* result,
            std::size_t result_length) noexcept {
            return transmission->ExportAuthenticatedSessionKey(
                label, context, context_length, result, result_length);
        }, id, output);
}

Control MakeResumeRequest(protocol::SessionResumeSecret& root,
    const protocol::SessionResumeId& session_id,
    const protocol::SessionResumeCandidateBinding& binding,
    std::uint64_t generation) {
    Fields fields;
    fields.action = protocol::SessionResumeAction::ResumeRequest;
    fields.capabilities = Control::CapabilityV1;
    fields.session_id = session_id;
    fields.generation = generation;
    fields.candidate_binding = binding;
    Require(protocol::GenerateSessionResumeNonce(fields.client_nonce),
        "resume request nonce generation failed");
    protocol::SessionResumeProof proof{};
    Require(protocol::ComputeSessionResumeProof(root, fields, proof),
        "resume request proof generation failed");
    Control request;
    FillControl(fields, proof, request);
    return request;
}

bool RunClientResume(const TransmissionPtr& transmission,
    YieldContext& y,
    protocol::SessionResumeSecret& retained_root,
    const protocol::SessionResumeId& session_id,
    const protocol::SessionResumeCandidateBinding& binding,
    std::uint64_t initial_generation) noexcept {
    Control request = MakeResumeRequest(retained_root, session_id, binding,
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
                retained_root, sync_fields, sync_proof)) {
            return false;
        }
        request = MakeResumeRequest(retained_root, session_id, binding,
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
    if (!SendControl(transmission, y, confirm)) {
        return false;
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

class TestVirtualEthernetSwitcher final :
    public server::VirtualEthernetSwitcher {
public:
    explicit TestVirtualEthernetSwitcher(
        const AppConfigurationPtr& configuration) noexcept
        : VirtualEthernetSwitcher(configuration) {
    }

    bool EstablishForTest(const ITransmissionPtr& transmission,
        const ppp::Int128& session_id,
        const VirtualEthernetInformationPtr& information,
        YieldContext& y) noexcept {
        return Establish(transmission, session_id, information, y);
    }

    VirtualEthernetExchangerPtr Captured(const ppp::Int128& id) noexcept {
        std::lock_guard<std::mutex> lock(captured_mutex_);
        const auto iterator = captured_.find(id);
        return iterator == captured_.end() ? nullptr : iterator->second;
    }

protected:
    VirtualEthernetExchangerPtr NewExchanger(
        const ITransmissionPtr& transmission,
        const ppp::Int128& session_id) noexcept override {
        if (!transmission) {
            return nullptr;
        }
        auto exchanger = ppp::make_shared_object<server::VirtualEthernetExchanger>(
            GetReference(), GetConfiguration(), transmission, session_id);
        if (exchanger) {
            std::lock_guard<std::mutex> lock(captured_mutex_);
            captured_[session_id] = exchanger;
        }
        return exchanger;
    }

private:
    std::mutex captured_mutex_;
    std::map<ppp::Int128, VirtualEthernetExchangerPtr> captured_;
};

struct AsyncResult final {
    std::atomic<bool> done{false};
    std::atomic<bool> ok{false};
    std::atomic<std::uint32_t> error{
        static_cast<std::uint32_t>(ppp::diagnostics::ErrorCode::Success)};
};

template <typename Function>
std::shared_ptr<AsyncResult> SpawnOperation(
    const std::shared_ptr<asio::io_context>& context,
    const StrandPtr& strand,
    Function&& function) {
    auto result = std::make_shared<AsyncResult>();
    const bool spawned = YieldContext::Spawn(
        nullptr, *context, strand.get(),
        [result, operation = std::forward<Function>(function)](
            YieldContext& y) mutable noexcept {
            result->ok.store(operation(y));
            result->error.store(static_cast<std::uint32_t>(
                ppp::diagnostics::GetLastErrorCode()));
            result->done.store(true);
        });
    if (!spawned) {
        result->done.store(true);
    }
    return result;
}

void Await(const std::shared_ptr<AsyncResult>& result, const char* message) {
    Require(result && WaitFor([&]() { return result->done.load(); }), message);
    Require(result->ok.load(), message);
}

std::shared_ptr<protocol::VirtualEthernetInformation> MakeInformation() {
    auto information =
        std::make_shared<protocol::VirtualEthernetInformation>();
    information->Clear();
    information->BandwidthQoS = 0;
    information->IncomingTraffic = std::numeric_limits<ppp::UInt64>::max();
    information->OutgoingTraffic = std::numeric_limits<ppp::UInt64>::max();
    information->ExpiredTime = std::numeric_limits<ppp::UInt32>::max();
    return information;
}

bool AcceptFreshOffer(const TransmissionPtr& transmission,
    const protocol::SessionResumeId& session_id,
    protocol::SessionResumeSecret& retained_root,
    YieldContext& y) noexcept {
    protocol::VirtualEthernetLinklayer::InformationEnvelope envelope;
    if (!protocol::VirtualEthernetLinklayer::ReadInformation(
            transmission, envelope, y)) {
        return false;
    }

    const Control& offer = envelope.Extensions.SessionResume;
    protocol::SessionResumeNonce server_nonce{};
    if (!offer.Valid() ||
        offer.action != protocol::SessionResumeAction::Offer ||
        offer.capabilities != Control::CapabilityV1 ||
        offer.session_id != EncodeHex(session_id) ||
        offer.generation != 0 ||
        !offer.client_nonce.empty() ||
        !offer.candidate_binding.empty() ||
        !offer.proof.empty() ||
        !offer.reason.empty() ||
        !DecodeHex(offer.server_nonce, server_nonce) ||
        !DeriveRetainedRoot(transmission, session_id, retained_root)) {
        return false;
    }

    Fields fields;
    fields.action = protocol::SessionResumeAction::Accepted;
    fields.capabilities = Control::CapabilityV1;
    fields.session_id = session_id;
    fields.server_nonce = server_nonce;
    if (!protocol::GenerateSessionResumeNonce(fields.client_nonce)) {
        return false;
    }
    protocol::SessionResumeProof proof{};
    if (!protocol::ComputeSessionResumeProof(retained_root, fields, proof)) {
        return false;
    }

    Control accepted;
    FillControl(fields, proof, accepted);
    return SendControl(transmission, y, accepted);
}

class ClientFrameObserver final : public protocol::VirtualEthernetLinklayer {
public:
    enum class Kind {
        None,
        Nat,
        Udp,
    };

    ClientFrameObserver(const AppConfigurationPtr& configuration,
        const ContextPtr& context, const ppp::Int128& id) noexcept
        : VirtualEthernetLinklayer(configuration, context, id) {
    }

    bool ReadOne(const TransmissionPtr& transmission, YieldContext& y) noexcept {
        int length = 0;
        std::shared_ptr<ppp::Byte> packet = transmission->Read(y, length);
        if (!packet || length < 1) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            kind_ = Kind::None;
            payload_.clear();
            source_ = udp::endpoint();
            destination_ = udp::endpoint();
        }
        return PacketInput(transmission, packet.get(), length, y);
    }

    Kind GetKind() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return kind_;
    }

    std::vector<ppp::Byte> GetPayload() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return payload_;
    }

    udp::endpoint GetSource() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return source_;
    }

    udp::endpoint GetDestination() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return destination_;
    }

protected:
    bool OnNat(const ITransmissionPtr&, ppp::Byte* packet,
        int packet_length, YieldContext&) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        kind_ = Kind::Nat;
        payload_.assign(packet, packet + packet_length);
        return true;
    }

    bool OnSendTo(const ITransmissionPtr&,
        const udp::endpoint& source,
        const udp::endpoint& destination,
        ppp::Byte* packet, int packet_length,
        YieldContext&) noexcept override {
        std::lock_guard<std::mutex> lock(mutex_);
        kind_ = Kind::Udp;
        source_ = source;
        destination_ = destination;
        payload_.assign(packet, packet + packet_length);
        return true;
    }

private:
    mutable std::mutex mutex_;
    Kind kind_ = Kind::None;
    std::vector<ppp::Byte> payload_;
    udp::endpoint source_;
    udp::endpoint destination_;
};

std::vector<ppp::Byte> BuildTcpPacket(
    std::uint32_t source, std::uint32_t destination,
    std::uint32_t sequence, const std::vector<ppp::Byte>& payload) {
    using ppp::net::native::ip_hdr;
    using ppp::net::native::tcp_hdr;
    constexpr int IpHeaderLength = 20;
    constexpr int TcpHeaderLength = 20;
    const int packet_length = IpHeaderLength + TcpHeaderLength +
        static_cast<int>(payload.size());
    std::vector<ppp::Byte> packet(packet_length, 0);

    auto* ip = reinterpret_cast<ip_hdr*>(packet.data());
    ip->v_hl = 0x45;
    ip->len = htons(static_cast<std::uint16_t>(packet_length));
    ip->id = htons(7);
    ip->flags = htons(ip_hdr::IP_DF);
    ip->ttl = 64;
    ip->proto = ip_hdr::IP_PROTO_TCP;
    ip->src = htonl(source);
    ip->dest = htonl(destination);
    ip->chksum = ppp::net::native::inet_chksum(ip, IpHeaderLength);

    auto* tcp_header = reinterpret_cast<tcp_hdr*>(packet.data() + IpHeaderLength);
    tcp_header->src = htons(32001);
    tcp_header->dest = htons(443);
    tcp_header->seqno = htonl(sequence);
    tcp_header->ackno = htonl(9000);
    tcp_header->hdrlen_rsvd_flags = htons(
        static_cast<std::uint16_t>((TcpHeaderLength / 4) << 12) |
        tcp_hdr::TCP_ACK);
    tcp_header->wnd = htons(32768);
    std::copy(payload.begin(), payload.end(),
        packet.begin() + IpHeaderLength + TcpHeaderLength);
    tcp_header->chksum = ppp::net::native::inet_chksum_pseudo(
        reinterpret_cast<unsigned char*>(tcp_header), IPPROTO_TCP,
        TcpHeaderLength + static_cast<int>(payload.size()),
        ip->src, ip->dest);
    return packet;
}

class DelayedUdpEcho final {
public:
    explicit DelayedUdpEcho(const std::shared_ptr<asio::io_context>& context)
        : context_(context)
        , socket_(*context_, udp::endpoint(asio::ip::address_v4::loopback(), 0))
        , endpoint_(socket_.local_endpoint()) {
        thread_ = std::thread([this]() noexcept { Run(); });
    }

    ~DelayedUdpEcho() noexcept {
        Stop();
    }

    udp::endpoint Endpoint() const noexcept { return endpoint_; }

    bool WaitForCount(std::size_t count) {
        return WaitFor([&]() {
            std::lock_guard<std::mutex> lock(mutex_);
            return requests_.size() >= count;
        });
    }

    void ReleaseFirst() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            release_first_ = true;
        }
        condition_.notify_all();
    }

    udp::endpoint RemoteAt(std::size_t index) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return remotes_.at(index);
    }

    std::vector<ppp::Byte> ResponseAt(std::size_t index) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ppp::Byte> response{'e', 'c', 'h', 'o', ':'};
        response.insert(response.end(), requests_.at(index).begin(),
            requests_.at(index).end());
        return response;
    }

    void Stop() noexcept {
        bool expected = false;
        if (!stopped_.compare_exchange_strong(expected, true)) {
            return;
        }
        condition_.notify_all();

        try {
            udp::socket wake(*context_);
            wake.open(udp::v4());
            const ppp::Byte byte = 0;
            wake.send_to(asio::buffer(&byte, 1), endpoint_);
        }
        catch (...) {
        }
        if (thread_.joinable()) {
            thread_.join();
        }
        boost::system::error_code ignored;
        socket_.close(ignored);
    }

private:
    void Run() noexcept {
        try {
            for (std::size_t index = 0; index < 2 && !stopped_.load(); ++index) {
                std::array<ppp::Byte, 2048> buffer{};
                udp::endpoint remote;
                boost::system::error_code ec;
                const std::size_t length = socket_.receive_from(
                    asio::buffer(buffer), remote, 0, ec);
                if (ec || stopped_.load()) {
                    return;
                }

                std::vector<ppp::Byte> request(
                    buffer.begin(), buffer.begin() + length);
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    requests_.push_back(request);
                    remotes_.push_back(remote);
                }

                if (index == 0) {
                    std::unique_lock<std::mutex> lock(mutex_);
                    condition_.wait(lock, [&]() {
                        return release_first_ || stopped_.load();
                    });
                    if (stopped_.load()) {
                        return;
                    }
                }

                std::vector<ppp::Byte> response{'e', 'c', 'h', 'o', ':'};
                response.insert(response.end(), request.begin(), request.end());
                socket_.send_to(asio::buffer(response), remote, 0, ec);
                if (ec) {
                    return;
                }
            }
        }
        catch (...) {
        }
    }

private:
    std::shared_ptr<asio::io_context> context_;
    udp::socket socket_;
    udp::endpoint endpoint_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::vector<ppp::Byte>> requests_;
    std::vector<udp::endpoint> remotes_;
    bool release_first_ = false;
    std::atomic<bool> stopped_{false};
    std::thread thread_;
};

struct FreshSession final {
    protocol::SessionResumeId resume_id{};
    protocol::SessionResumeSecret retained_root;
    std::shared_ptr<AsyncResult> establish;
    std::shared_ptr<server::VirtualEthernetExchanger> exchanger;
};

FreshSession EstablishFresh(
    const std::shared_ptr<TestVirtualEthernetSwitcher>& switcher,
    SharedContextWssPair& pair,
    const ppp::Int128& session_id) {
    Require(pair.Handshake(), "production WSS handshake failed");

    FreshSession session;
    ppp::p2p::Int128ToBytes(session_id, session.resume_id.data());
    session.establish = SpawnOperation(
        switcher->GetContext(), pair.ServerStrand(),
        [switcher, transmission = pair.Server(), session_id](
            YieldContext& y) noexcept {
            return switcher->EstablishForTest(
                transmission, session_id, MakeInformation(), y);
        });

    auto fresh = SpawnOperation(
        switcher->GetContext(), pair.ClientStrand(),
        [&session, transmission = pair.Client()](YieldContext& y) noexcept {
            return AcceptFreshOffer(transmission, session.resume_id,
                session.retained_root, y);
        });
    Await(fresh, "fresh authenticated resume offer was not accepted");

    Require(WaitFor([&]() {
        session.exchanger = switcher->Captured(session_id);
        return static_cast<bool>(session.exchanger);
    }), "fresh exchanger was not captured");
    Require(session.exchanger->GetCarrierGeneration() == 1,
        "fresh exchanger generation is not one");
    Require(session.exchanger->GetTransmission() == pair.Server(),
        "fresh exchanger did not retain its server carrier");
    return session;
}

void SendLan(const std::shared_ptr<protocol::VirtualEthernetLinklayer>& sender,
    SharedContextWssPair& pair, std::uint32_t address,
    std::uint32_t mask) {
    auto operation = SpawnOperation(
        sender->GetContext(), pair.ClientStrand(),
        [sender, transmission = pair.Client(), address, mask](
            YieldContext& y) noexcept {
            return sender->DoLan(transmission, htonl(address), htonl(mask), y);
        });
    Await(operation, "LAN announcement failed");
}

void ForwardAndObserveTcp(
    const std::shared_ptr<protocol::VirtualEthernetLinklayer>& sender,
    SharedContextWssPair& source_pair,
    const std::shared_ptr<ClientFrameObserver>& observer,
    SharedContextWssPair& destination_pair,
    const std::vector<ppp::Byte>& packet) {
    auto read = SpawnOperation(
        observer->GetContext(), destination_pair.ClientStrand(),
        [observer, transmission = destination_pair.Client()](
            YieldContext& y) noexcept {
            return observer->ReadOne(transmission, y);
        });
    auto write = SpawnOperation(
        sender->GetContext(), source_pair.ClientStrand(),
        [sender, transmission = source_pair.Client(), packet](
            YieldContext& y) mutable noexcept {
            return sender->DoNat(transmission,
                const_cast<ppp::Byte*>(packet.data()),
                static_cast<int>(packet.size()), y);
        });
    Await(write, "TCP NAT packet send failed");
    Await(read, "TCP NAT packet was not forwarded to destination client");
    Require(observer->GetKind() == ClientFrameObserver::Kind::Nat,
        "forwarded TCP packet did not use NAT action");
    Require(observer->GetPayload() == packet,
        "forwarded TCP packet changed unexpectedly");
}

void RunE2E() {
    auto configuration = MakeSwitcherConfiguration();
    auto switcher = std::make_shared<TestVirtualEthernetSwitcher>(configuration);
    auto context = switcher->GetContext();
    Require(static_cast<bool>(context), "switcher default context is null");

    const ppp::Int128 session_a_id =
        ppp::MAKE_OWORD(0x0102030405060708ull, 0x1112131415161718ull);
    const ppp::Int128 session_b_id =
        ppp::MAKE_OWORD(0x2122232425262728ull, 0x3132333435363738ull);

    SharedContextWssPair pair_a(context, session_a_id);
    SharedContextWssPair pair_b_old(context, session_b_id);
    FreshSession session_a = EstablishFresh(switcher, pair_a, session_a_id);
    FreshSession session_b = EstablishFresh(switcher, pair_b_old, session_b_id);

    auto sender_a = std::make_shared<protocol::VirtualEthernetLinklayer>(
        configuration, context, session_a_id);
    auto sender_b = std::make_shared<protocol::VirtualEthernetLinklayer>(
        configuration, context, session_b_id);
    auto observer_b = std::make_shared<ClientFrameObserver>(
        configuration, context, session_b_id);

    constexpr std::uint32_t AddressA = 0x0a4d0001u;
    constexpr std::uint32_t AddressB = 0x0a4d0002u;
    constexpr std::uint32_t Mask = 0xffffff00u;
    SendLan(sender_a, pair_a, AddressA, Mask);
    SendLan(sender_b, pair_b_old, AddressB, Mask);

    DelayedUdpEcho udp_echo(context);
    const udp::endpoint virtual_source(
        asio::ip::make_address_v4("10.77.0.2"), 40000);
    const std::vector<ppp::Byte> first_udp{'d', 'e', 'l', 'a', 'y', 'e', 'd'};
    auto first_udp_send = SpawnOperation(
        context, pair_b_old.ClientStrand(),
        [sender_b, transmission = pair_b_old.Client(), virtual_source,
            destination = udp_echo.Endpoint(), first_udp](
            YieldContext& y) mutable noexcept {
            return sender_b->DoSendTo(transmission, virtual_source,
                destination, const_cast<ppp::Byte*>(first_udp.data()),
                static_cast<int>(first_udp.size()), y);
        });
    Await(first_udp_send, "pre-roam UDP relay send failed");
    Require(udp_echo.WaitForCount(1),
        "UDP echo fixture did not receive pre-roam datagram");
    const udp::endpoint retained_relay_endpoint = udp_echo.RemoteAt(0);

    const std::vector<ppp::Byte> before_payload{'b', 'e', 'f', 'o', 'r', 'e'};
    const std::vector<ppp::Byte> before_packet = BuildTcpPacket(
        AddressA, AddressB, 1000, before_payload);
    ForwardAndObserveTcp(sender_a, pair_a, observer_b, pair_b_old,
        before_packet);

    const auto exchanger_identity = session_b.exchanger.get();
    const auto statistics_identity = session_b.exchanger->GetStatistics();
    Require(static_cast<bool>(statistics_identity),
        "fresh exchanger statistics are null");
    Require(!session_b.establish->done.load(),
        "old server carrier stopped before simulated link loss");
    Require(pair_b_old.Server()->IsHandshakeComplete(),
        "old server handshake state was cleared before simulated link loss");

    pair_b_old.AbortClient();
    Require(WaitFor([&]() { return session_b.establish->done.load(); }),
        "old server establish coroutine did not stop after carrier loss");
    Require(session_b.establish->ok.load(),
        "old carrier loss was treated as a terminal session failure");
    const bool suspended = WaitFor([&]() {
        return session_b.exchanger->GetTransmission() == nullptr &&
            session_b.exchanger->IsSuspended(
                ppp::threading::Executors::GetTickCount());
    });
    if (!suspended) {
        std::cerr << "suspend details: transmission="
                  << static_cast<bool>(session_b.exchanger->GetTransmission())
                  << " suspended=" << session_b.exchanger->IsSuspended(
                         ppp::threading::Executors::GetTickCount())
                  << " generation="
                  << session_b.exchanger->GetCarrierGeneration()
                  << " disposed=" << session_b.exchanger->IsDisposed()
                  << " establish_error=" << session_b.establish->error.load()
                  << '\n';
    }
    Require(suspended, "exchanger did not enter suspended roaming state");
    Require(session_b.exchanger->GetCarrierGeneration() == 1,
        "carrier generation changed before resume commit");
    Require(session_b.exchanger->GetStatistics() == statistics_identity,
        "statistics identity changed while suspended");

    SharedContextWssPair pair_b_new(context, session_b_id);
    Require(pair_b_new.Handshake(), "replacement production WSS handshake failed");
    protocol::SessionResumeCandidateBinding candidate_binding{};
    auto derive_binding = SpawnOperation(
        context, pair_b_new.ClientStrand(),
        [transmission = pair_b_new.Client(), &session_b, &candidate_binding](
            YieldContext&) noexcept {
            return DeriveCandidateBinding(
                transmission, session_b.resume_id, candidate_binding);
        });
    Await(derive_binding, "replacement candidate binding derivation failed");

    auto resumed_establish = SpawnOperation(
        context, pair_b_new.ServerStrand(),
        [switcher, transmission = pair_b_new.Server(), session_b_id](
            YieldContext& y) noexcept {
            return switcher->EstablishForTest(
                transmission, session_b_id, nullptr, y);
        });
    auto resumed_client = SpawnOperation(
        context, pair_b_new.ClientStrand(),
        [&session_b, candidate_binding,
            transmission = pair_b_new.Client()](YieldContext& y) noexcept {
            return RunClientResume(transmission, y, session_b.retained_root,
                session_b.resume_id, candidate_binding, 1);
        });
    Await(resumed_client, "authenticated replacement carrier resume failed");
    Require(WaitFor([&]() {
        return session_b.exchanger->GetTransmission() == pair_b_new.Server() &&
            session_b.exchanger->GetCarrierGeneration() == 2;
    }), "replacement carrier was not published");
    Require(switcher->Captured(session_b_id).get() == exchanger_identity,
        "resume replaced the logical exchanger object");
    Require(session_b.exchanger->GetStatistics() == statistics_identity,
        "resume replaced the logical statistics object");
    Require(pair_b_new.Server()->Statistics == statistics_identity,
        "replacement carrier was not rebound to retained statistics");

    auto delayed_read = SpawnOperation(
        context, pair_b_new.ClientStrand(),
        [observer_b, transmission = pair_b_new.Client()](
            YieldContext& y) noexcept {
            return observer_b->ReadOne(transmission, y);
        });
    udp_echo.ReleaseFirst();
    Await(delayed_read,
        "delayed UDP response did not cross the replacement carrier");
    Require(observer_b->GetKind() == ClientFrameObserver::Kind::Udp,
        "delayed UDP response did not use SENDTO action");
    Require(observer_b->GetPayload() == udp_echo.ResponseAt(0),
        "delayed UDP response payload was corrupted");
    Require(observer_b->GetSource() == virtual_source,
        "delayed UDP response virtual source changed");
    Require(observer_b->GetDestination() == udp_echo.Endpoint(),
        "delayed UDP response remote destination changed");

    const std::vector<ppp::Byte> after_payload{'a', 'f', 't', 'e', 'r'};
    const std::vector<ppp::Byte> after_packet = BuildTcpPacket(
        AddressA, AddressB,
        1000 + static_cast<std::uint32_t>(before_payload.size()),
        after_payload);
    ForwardAndObserveTcp(sender_a, pair_a, observer_b, pair_b_new,
        after_packet);

    const std::vector<ppp::Byte> second_udp{'p', 'o', 's', 't'};
    auto second_read = SpawnOperation(
        context, pair_b_new.ClientStrand(),
        [observer_b, transmission = pair_b_new.Client()](
            YieldContext& y) noexcept {
            return observer_b->ReadOne(transmission, y);
        });
    auto second_send = SpawnOperation(
        context, pair_b_new.ClientStrand(),
        [sender_b, transmission = pair_b_new.Client(), virtual_source,
            destination = udp_echo.Endpoint(), second_udp](
            YieldContext& y) mutable noexcept {
            return sender_b->DoSendTo(transmission, virtual_source,
                destination, const_cast<ppp::Byte*>(second_udp.data()),
                static_cast<int>(second_udp.size()), y);
        });
    Await(second_send, "post-roam UDP relay send failed");
    Require(udp_echo.WaitForCount(2),
        "UDP echo fixture did not receive post-roam datagram");
    Await(second_read, "post-roam UDP response was not returned");
    Require(observer_b->GetKind() == ClientFrameObserver::Kind::Udp,
        "post-roam UDP response did not use SENDTO action");
    Require(observer_b->GetPayload() == udp_echo.ResponseAt(1),
        "post-roam UDP response payload was corrupted");
    Require(udp_echo.RemoteAt(1) == retained_relay_endpoint,
        "post-roam UDP used a new relay port instead of the retained port");

    udp_echo.Stop();
    std::atomic<bool> disposed{false};
    switcher->Dispose([&]() noexcept { disposed.store(true); });
    Require(WaitFor([&]() { return disposed.load(); }),
        "switcher asynchronous disposal did not complete");
    pair_a.Dispose();
    pair_b_old.Dispose();
    pair_b_new.Dispose();
    Require(WaitFor([&]() {
        return session_a.establish->done.load() &&
            resumed_establish->done.load();
    }), "active establish coroutines did not stop during cleanup");
}

} // namespace

int main() {
    ppp::global::cctor();

    std::atomic<int> test_result{1};
    std::thread test_thread;
    try {
        const int executor_result = ppp::threading::Executors::Run(
            nullptr,
            [&](int, const char*[]) noexcept -> int {
                test_thread = std::thread([&]() noexcept {
                    try {
                        RunE2E();
                        std::cout << "session roaming switcher E2E: PASS\n";
                        test_result.store(0);
                    }
                    catch (const std::exception& error) {
                        std::cerr << "session roaming switcher E2E: FAIL: "
                                  << error.what() << '\n';
                        test_result.store(1);
                    }
                    catch (...) {
                        std::cerr << "session roaming switcher E2E: FAIL: "
                                     "unknown exception\n";
                        test_result.store(1);
                    }
                    ppp::threading::Executors::Exit();
                });
                return 0;
            });
        if (test_thread.joinable()) {
            test_thread.join();
        }
        if (executor_result != 0) {
            return executor_result;
        }
        return test_result.load();
    }
    catch (const std::exception& error) {
        if (test_thread.joinable()) {
            test_thread.join();
        }
        std::cerr << "session roaming switcher E2E: FAIL: "
                  << error.what() << '\n';
        return 1;
    }
}
