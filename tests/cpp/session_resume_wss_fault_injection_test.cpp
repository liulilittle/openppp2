#define BOOST_TEST_MODULE session_resume_wss_fault_injection_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/server/SessionRecoveryState.h>
#include <ppp/ssl/TlsSessionExporter.h>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace protocol = ppp::app::protocol;
namespace server = ppp::app::server;
using tcp = asio::ip::tcp;
using WssStream = websocket::stream<asio::ssl::stream<tcp::socket>>;

namespace {

constexpr std::uint64_t InitialGeneration = 1;
constexpr std::uint64_t ReservationToken = 71;

protocol::SessionResumeId MakeSessionId() noexcept {
    protocol::SessionResumeId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<std::uint8_t>(i + 1);
    }
    return id;
}

template <std::size_t N>
ppp::string EncodeHex(const std::array<std::uint8_t, N>& input) {
    static constexpr char Hex[] = "0123456789abcdef";
    ppp::string output;
    output.resize(N * 2);
    for (std::size_t i = 0; i < N; ++i) {
        output[i * 2] = Hex[input[i] >> 4];
        output[i * 2 + 1] = Hex[input[i] & 0x0f];
    }
    return output;
}

int DecodeNibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

template <std::size_t N>
bool DecodeHex(const ppp::string& input, std::array<std::uint8_t, N>& output) noexcept {
    if (input.size() != N * 2) {
        output.fill(0);
        return false;
    }
    std::array<std::uint8_t, N> decoded{};
    for (std::size_t i = 0; i < N; ++i) {
        const int high = DecodeNibble(input[i * 2]);
        const int low = DecodeNibble(input[i * 2 + 1]);
        if (high < 0 || low < 0) {
            output.fill(0);
            OPENSSL_cleanse(decoded.data(), decoded.size());
            return false;
        }
        decoded[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    output = decoded;
    OPENSSL_cleanse(decoded.data(), decoded.size());
    return true;
}

protocol::SessionResumeControl EncodeControl(
    const protocol::SessionResumeTranscriptFields& fields,
    const protocol::SessionResumeProof& proof) {
    protocol::SessionResumeControl control;
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
    if (!control.Valid()) {
        throw std::runtime_error("invalid session resume control");
    }
    return control;
}

bool DecodeControl(const protocol::SessionResumeControl& control,
    protocol::SessionResumeTranscriptFields& fields,
    protocol::SessionResumeProof& proof) noexcept {
    fields = {};
    proof.fill(0);
    if (!control.Valid()) {
        return false;
    }
    fields.action = control.action;
    fields.capabilities = control.capabilities;
    fields.generation = control.generation;
    return DecodeHex(control.session_id, fields.session_id) &&
        DecodeHex(control.client_nonce, fields.client_nonce) &&
        (control.server_nonce.empty() ||
            DecodeHex(control.server_nonce, fields.server_nonce)) &&
        DecodeHex(control.candidate_binding, fields.candidate_binding) &&
        DecodeHex(control.proof, proof);
}

protocol::SessionResumeProof MakeProof(
    const protocol::SessionResumeSecret& root,
    const protocol::SessionResumeTranscriptFields& fields) {
    protocol::SessionResumeProof proof{};
    if (!protocol::ComputeSessionResumeProof(root, fields, proof)) {
        throw std::runtime_error("cannot compute session resume proof");
    }
    return proof;
}

protocol::SessionResumeExporter MakeExporter(WssStream& stream,
    bool application_handshake_complete = true) {
    ::ssl_st* ssl = stream.next_layer().native_handle();
    return [ssl, application_handshake_complete](const char* label,
        const std::uint8_t* context, std::size_t context_length,
        std::uint8_t* output, std::size_t output_length) noexcept {
        return ppp::ssl::ExportAuthenticatedTlsSessionKey(
            application_handshake_complete, ssl, label, context,
            context_length, output, output_length);
    };
}

class WssPair final {
public:
    WssPair()
        : client_context_(asio::ssl::context::tls_client)
        , server_context_(asio::ssl::context::tls_server) {
        server_context_.set_options(asio::ssl::context::default_workarounds);
        server_context_.use_certificate_chain_file(OPENPPP2_TEST_CERTIFICATE);
        server_context_.use_private_key_file(
            OPENPPP2_TEST_PRIVATE_KEY, asio::ssl::context::pem);
        client_context_.set_verify_mode(asio::ssl::verify_none);

        tcp::acceptor acceptor(server_io_,
            tcp::endpoint(asio::ip::address_v4::loopback(), 0));
        const tcp::endpoint endpoint = acceptor.local_endpoint();
        std::exception_ptr server_error;
        std::thread server_thread([&]() {
            try {
                tcp::socket socket(server_io_);
                acceptor.accept(socket);
                server_ = std::make_unique<WssStream>(
                    std::move(socket), server_context_);
                server_->next_layer().handshake(asio::ssl::stream_base::server);
                server_->accept();
                server_->binary(true);
            }
            catch (...) {
                server_error = std::current_exception();
            }
        });

        try {
            tcp::socket socket(client_io_);
            socket.connect(endpoint);
            client_ = std::make_unique<WssStream>(
                std::move(socket), client_context_);
            client_->next_layer().handshake(asio::ssl::stream_base::client);
            client_->handshake("localhost", "/session-resume");
            client_->binary(true);
        }
        catch (...) {
            CloseLowest(client_.get());
            acceptor.close();
            server_thread.join();
            throw;
        }
        server_thread.join();
        if (server_error) {
            std::rethrow_exception(server_error);
        }
        if (!client_ || !server_) {
            throw std::runtime_error("incomplete WSS fixture");
        }
    }

    ~WssPair() noexcept {
        CloseLowest(client_.get());
        CloseLowest(server_.get());
    }

    WssStream& Client() noexcept { return *client_; }
    WssStream& Server() noexcept { return *server_; }

private:
    static void CloseLowest(WssStream* stream) noexcept {
        if (!stream) {
            return;
        }
        beast::error_code error;
        tcp::socket& socket = beast::get_lowest_layer(*stream);
        socket.cancel(error);
        socket.shutdown(tcp::socket::shutdown_both, error);
        socket.close(error);
    }

    asio::io_context client_io_;
    asio::io_context server_io_;
    asio::ssl::context client_context_;
    asio::ssl::context server_context_;
    std::unique_ptr<WssStream> client_;
    std::unique_ptr<WssStream> server_;
};

enum class FrameFault {
    Pass,
    DropOnce,
    Duplicate,
    ReplayStored,
    CloseBeforeWrite,
};

class ScriptedControlChannel final {
public:
    explicit ScriptedControlChannel(WssStream& stream) noexcept
        : stream_(stream) {
    }

    int Send(const protocol::SessionResumeControl& control, FrameFault fault) {
        protocol::VirtualEthernetInformationExtensions extensions;
        extensions.SessionResume = control;
        const ppp::string payload = extensions.ToJson();
        if (payload.empty()) {
            throw std::runtime_error("cannot serialize session resume extensions");
        }

        if (fault == FrameFault::DropOnce) {
            stored_ = payload;
            return 0;
        }
        if (fault == FrameFault::CloseBeforeWrite) {
            beast::error_code error;
            beast::get_lowest_layer(stream_).close(error);
            return 0;
        }
        const ppp::string& wire = fault == FrameFault::ReplayStored
            ? stored_ : payload;
        if (wire.empty()) {
            throw std::runtime_error("no stored frame to replay");
        }
        const int copies = fault == FrameFault::Duplicate ? 2 : 1;
        for (int i = 0; i < copies; ++i) {
            stream_.write(asio::buffer(wire));
        }
        stored_ = payload;
        return copies;
    }

    static protocol::SessionResumeControl Receive(WssStream& stream) {
        beast::flat_buffer buffer;
        stream.read(buffer);
        const std::string wire = beast::buffers_to_string(buffer.data());
        const ppp::string payload(wire.begin(), wire.end());
        protocol::VirtualEthernetInformationExtensions extensions;
        if (!protocol::VirtualEthernetInformationExtensions::FromJson(
                extensions, payload) ||
            !extensions.SessionResume.HasAny()) {
            throw std::runtime_error("invalid session resume WSS frame");
        }
        return extensions.SessionResume;
    }

private:
    WssStream& stream_;
    ppp::string stored_;
};

struct RootPair {
    protocol::SessionResumeSecret client;
    protocol::SessionResumeSecret server;
};

bool DeriveRoots(WssPair& pair, const protocol::SessionResumeId& id,
    RootPair& roots) {
    return protocol::DeriveSessionResumeRetainedRoot(
            MakeExporter(pair.Client()), id, roots.client) &&
        protocol::DeriveSessionResumeRetainedRoot(
            MakeExporter(pair.Server()), id, roots.server);
}

bool DeriveCandidate(WssPair& pair, const protocol::SessionResumeId& id,
    protocol::SessionResumeCandidateBinding& client,
    protocol::SessionResumeCandidateBinding& server) {
    return protocol::DeriveSessionResumeCandidateBinding(
            MakeExporter(pair.Client()), id, client) &&
        protocol::DeriveSessionResumeCandidateBinding(
            MakeExporter(pair.Server()), id, server);
}

protocol::SessionResumeTranscriptFields MakeRequest(
    const protocol::SessionResumeId& id,
    const protocol::SessionResumeCandidateBinding& candidate,
    std::uint64_t generation) {
    protocol::SessionResumeTranscriptFields fields;
    fields.action = protocol::SessionResumeAction::ResumeRequest;
    fields.capabilities = protocol::SessionResumeControl::CapabilityV1;
    fields.session_id = id;
    fields.generation = generation;
    fields.candidate_binding = candidate;
    if (!protocol::GenerateSessionResumeNonce(fields.client_nonce)) {
        throw std::runtime_error("cannot generate client nonce");
    }
    return fields;
}

bool ReceiveAndVerify(WssStream& stream,
    protocol::SessionResumeAction expected_action,
    const protocol::SessionResumeSecret& root,
    protocol::SessionResumeTranscriptFields& fields) {
    const protocol::SessionResumeControl control =
        ScriptedControlChannel::Receive(stream);
    protocol::SessionResumeProof proof{};
    if (!DecodeControl(control, fields, proof) ||
        fields.action != expected_action) {
        return false;
    }
    return protocol::VerifySessionResumeProof(root, fields, proof);
}

} // namespace

BOOST_AUTO_TEST_CASE(real_wss_exporter_and_happy_resume_commit_once) {
    const protocol::SessionResumeId id = MakeSessionId();
    WssPair fresh;
    RootPair roots;
    BOOST_REQUIRE(DeriveRoots(fresh, id, roots));

    protocol::SessionResumeTranscriptFields root_check = MakeRequest(
        id, protocol::SessionResumeCandidateBinding{}, InitialGeneration);
    const protocol::SessionResumeProof root_check_proof =
        MakeProof(roots.client, root_check);
    BOOST_REQUIRE(protocol::VerifySessionResumeProof(
        roots.server, root_check, root_check_proof));

    WssPair resumed;
    protocol::SessionResumeCandidateBinding client_candidate{};
    protocol::SessionResumeCandidateBinding server_candidate{};
    BOOST_REQUIRE(DeriveCandidate(
        resumed, id, client_candidate, server_candidate));
    BOOST_TEST(client_candidate == server_candidate);

    ScriptedControlChannel client_channel(resumed.Client());
    ScriptedControlChannel server_channel(resumed.Server());
    server::SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(InitialGeneration, 100, 1000));

    protocol::SessionResumeTranscriptFields request = MakeRequest(
        id, client_candidate, InitialGeneration);
    BOOST_REQUIRE(client_channel.Send(
        EncodeControl(request, MakeProof(roots.client, request)),
        FrameFault::Pass) == 1);

    protocol::SessionResumeTranscriptFields received_request;
    BOOST_REQUIRE(ReceiveAndVerify(resumed.Server(),
        protocol::SessionResumeAction::ResumeRequest,
        roots.server, received_request));
    BOOST_TEST(received_request.candidate_binding == server_candidate);
    BOOST_REQUIRE(state.ReserveResume(
        InitialGeneration, 120, ReservationToken));

    protocol::SessionResumeTranscriptFields accepted = received_request;
    accepted.action = protocol::SessionResumeAction::ResumeAccept;
    BOOST_REQUIRE(protocol::GenerateSessionResumeNonce(accepted.server_nonce));
    BOOST_REQUIRE(server_channel.Send(
        EncodeControl(accepted, MakeProof(roots.server, accepted)),
        FrameFault::Pass) == 1);

    protocol::SessionResumeTranscriptFields received_accept;
    BOOST_REQUIRE(ReceiveAndVerify(resumed.Client(),
        protocol::SessionResumeAction::ResumeAccept,
        roots.client, received_accept));
    BOOST_TEST(received_accept.client_nonce == request.client_nonce);

    protocol::SessionResumeTranscriptFields confirm = received_accept;
    confirm.action = protocol::SessionResumeAction::ResumeConfirm;
    BOOST_REQUIRE(client_channel.Send(
        EncodeControl(confirm, MakeProof(roots.client, confirm)),
        FrameFault::Pass) == 1);

    protocol::SessionResumeTranscriptFields received_confirm;
    BOOST_REQUIRE(ReceiveAndVerify(resumed.Server(),
        protocol::SessionResumeAction::ResumeConfirm,
        roots.server, received_confirm));
    BOOST_REQUIRE(state.CanCommitResume(
        InitialGeneration, 130, ReservationToken));

    protocol::SessionResumeTranscriptFields committed = received_confirm;
    committed.action = protocol::SessionResumeAction::ResumeCommitted;
    committed.generation = InitialGeneration + 1;
    const int committed_writes = server_channel.Send(
        EncodeControl(committed, MakeProof(roots.server, committed)),
        FrameFault::Pass);
    BOOST_REQUIRE(committed_writes == 1);

    int publish_count = 0;
    bool published_after_write = false;
    BOOST_REQUIRE(server::CommitSessionResumeAndPublish(
        state, InitialGeneration, 140, ReservationToken,
        [&](std::uint64_t generation) noexcept {
            ++publish_count;
            published_after_write = committed_writes == 1 && generation == 2;
        }));

    protocol::SessionResumeTranscriptFields received_committed;
    BOOST_REQUIRE(ReceiveAndVerify(resumed.Client(),
        protocol::SessionResumeAction::ResumeCommitted,
        roots.client, received_committed));
    BOOST_TEST(received_committed.generation == 2u);
    BOOST_TEST(state.GetGeneration() == 2u);
    BOOST_TEST(publish_count == 1);
    BOOST_TEST(published_after_write);
    BOOST_TEST(!server::CommitSessionResumeAndPublish(
        state, InitialGeneration, 150, ReservationToken,
        [](std::uint64_t) noexcept {}));
}

BOOST_AUTO_TEST_CASE(dropped_frames_cancel_without_generation_change) {
    const protocol::SessionResumeId id = MakeSessionId();
    WssPair pair;
    RootPair roots;
    BOOST_REQUIRE(DeriveRoots(pair, id, roots));
    protocol::SessionResumeCandidateBinding client_candidate{};
    protocol::SessionResumeCandidateBinding server_candidate{};
    BOOST_REQUIRE(DeriveCandidate(
        pair, id, client_candidate, server_candidate));

    ScriptedControlChannel client_channel(pair.Client());
    ScriptedControlChannel server_channel(pair.Server());
    protocol::SessionResumeTranscriptFields request = MakeRequest(
        id, client_candidate, InitialGeneration);
    const protocol::SessionResumeControl request_control =
        EncodeControl(request, MakeProof(roots.client, request));

    server::SessionRecoveryState request_drop;
    BOOST_REQUIRE(request_drop.Suspend(1, 100, 1000));
    BOOST_TEST(client_channel.Send(
        request_control, FrameFault::DropOnce) == 0);
    BOOST_TEST(!request_drop.HasResumeReservation());
    BOOST_TEST(request_drop.GetGeneration() == 1u);

    server::SessionRecoveryState accept_drop;
    BOOST_REQUIRE(accept_drop.Suspend(1, 100, 1000));
    BOOST_REQUIRE(accept_drop.ReserveResume(1, 120, 81));
    BOOST_TEST(!accept_drop.ReserveResume(1, 120, 82));
    protocol::SessionResumeTranscriptFields accepted = request;
    accepted.action = protocol::SessionResumeAction::ResumeAccept;
    BOOST_REQUIRE(protocol::GenerateSessionResumeNonce(accepted.server_nonce));
    BOOST_TEST(server_channel.Send(EncodeControl(
        accepted, MakeProof(roots.server, accepted)), FrameFault::DropOnce) == 0);
    BOOST_REQUIRE(accept_drop.CancelResume(81));
    BOOST_TEST(accept_drop.GetGeneration() == 1u);
    BOOST_TEST(accept_drop.ReserveResume(1, 121, 82));
    BOOST_REQUIRE(accept_drop.CancelResume(82));

    server::SessionRecoveryState confirm_drop;
    BOOST_REQUIRE(confirm_drop.Suspend(1, 100, 1000));
    BOOST_REQUIRE(confirm_drop.ReserveResume(1, 120, 83));
    protocol::SessionResumeTranscriptFields confirm = accepted;
    confirm.action = protocol::SessionResumeAction::ResumeConfirm;
    BOOST_TEST(client_channel.Send(EncodeControl(
        confirm, MakeProof(roots.client, confirm)), FrameFault::DropOnce) == 0);
    BOOST_REQUIRE(confirm_drop.CancelResume(83));
    BOOST_TEST(confirm_drop.GetGeneration() == 1u);

    server::SessionRecoveryState committed_drop;
    BOOST_REQUIRE(committed_drop.Suspend(1, 100, 1000));
    BOOST_REQUIRE(committed_drop.ReserveResume(1, 120, 84));
    BOOST_REQUIRE(committed_drop.MarkResumeCommitted(84, 130, 10));
    protocol::SessionResumeTranscriptFields committed = confirm;
    committed.action = protocol::SessionResumeAction::ResumeCommitted;
    committed.generation = 2;
    const int writes = server_channel.Send(EncodeControl(
        committed, MakeProof(roots.server, committed)), FrameFault::DropOnce);
    BOOST_TEST(writes == 0);
    if (writes == 0) {
        BOOST_REQUIRE(committed_drop.CancelResume(84));
    }
    BOOST_TEST(committed_drop.GetGeneration() == 1u);
    BOOST_TEST(committed_drop.IsSuspended(131));
}

BOOST_AUTO_TEST_CASE(duplicate_replay_stale_and_concurrent_candidates_fail_closed) {
    const protocol::SessionResumeId id = MakeSessionId();
    WssPair old_pair;
    RootPair roots;
    BOOST_REQUIRE(DeriveRoots(old_pair, id, roots));
    protocol::SessionResumeCandidateBinding old_client_candidate{};
    protocol::SessionResumeCandidateBinding old_server_candidate{};
    BOOST_REQUIRE(DeriveCandidate(old_pair, id,
        old_client_candidate, old_server_candidate));

    WssPair new_pair;
    protocol::SessionResumeCandidateBinding new_client_candidate{};
    protocol::SessionResumeCandidateBinding new_server_candidate{};
    BOOST_REQUIRE(DeriveCandidate(new_pair, id,
        new_client_candidate, new_server_candidate));
    BOOST_TEST(old_client_candidate != new_client_candidate);
    BOOST_TEST(new_client_candidate == new_server_candidate);

    ScriptedControlChannel client_channel(new_pair.Client());
    protocol::SessionResumeTranscriptFields request = MakeRequest(
        id, new_client_candidate, InitialGeneration);
    BOOST_REQUIRE(client_channel.Send(EncodeControl(
        request, MakeProof(roots.client, request)), FrameFault::Duplicate) == 2);

    server::SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 1000));
    for (int copy = 0; copy < 2; ++copy) {
        protocol::SessionResumeTranscriptFields duplicate;
        BOOST_REQUIRE(ReceiveAndVerify(new_pair.Server(),
            protocol::SessionResumeAction::ResumeRequest,
            roots.server, duplicate));
        if (copy == 0) {
            BOOST_REQUIRE(state.ReserveResume(1, 120, ReservationToken));
        }
        else {
            BOOST_TEST(!state.ReserveResume(1, 120, ReservationToken + 1));
        }
    }
    BOOST_REQUIRE(state.CancelResume(ReservationToken));

    protocol::SessionResumeTranscriptFields replay = MakeRequest(
        id, old_client_candidate, InitialGeneration);
    const protocol::SessionResumeProof replay_proof =
        MakeProof(roots.client, replay);
    protocol::SessionResumeTranscriptFields rebound = replay;
    rebound.candidate_binding = new_server_candidate;
    BOOST_TEST(!protocol::VerifySessionResumeProof(
        roots.server, rebound, replay_proof));

    protocol::SessionResumeTranscriptFields stale = MakeRequest(
        id, new_client_candidate, 0);
    protocol::SessionResumeTranscriptFields sync = stale;
    sync.action = protocol::SessionResumeAction::GenerationSync;
    sync.generation = 1;
    const protocol::SessionResumeProof sync_proof =
        MakeProof(roots.server, sync);
    BOOST_REQUIRE(protocol::VerifySessionResumeProof(
        roots.client, sync, sync_proof));
    const protocol::SessionResumeNonce old_nonce = stale.client_nonce;
    protocol::SessionResumeTranscriptFields retry = MakeRequest(
        id, new_client_candidate, sync.generation);
    BOOST_TEST(retry.client_nonce != old_nonce);

    protocol::SessionResumeTranscriptFields forged_sync = sync;
    forged_sync.client_nonce = retry.client_nonce;
    BOOST_TEST(!protocol::VerifySessionResumeProof(
        roots.client, forged_sync, sync_proof));

    server::SessionRecoveryState concurrent;
    BOOST_REQUIRE(concurrent.Suspend(1, 100, 1000));
    BOOST_REQUIRE(concurrent.ReserveResume(1, 120, 91));
    BOOST_TEST(!concurrent.ReserveResume(1, 120, 92));
    BOOST_REQUIRE(concurrent.CancelResume(91));
    BOOST_REQUIRE(concurrent.ReserveResume(1, 121, 92));
}

BOOST_AUTO_TEST_CASE(grace_boundaries_and_application_gate_are_fail_closed) {
    server::SessionRecoveryState before_deadline;
    BOOST_REQUIRE(before_deadline.Suspend(1, 100, 50));
    BOOST_TEST(before_deadline.CanResume(1, 149));

    server::SessionRecoveryState at_deadline;
    BOOST_REQUIRE(at_deadline.Suspend(1, 100, 50));
    BOOST_TEST(!at_deadline.CanResume(1, 150));
    BOOST_TEST(at_deadline.IsExpired(150));

    server::SessionRecoveryState after_deadline;
    BOOST_REQUIRE(after_deadline.Suspend(1, 100, 50));
    BOOST_TEST(!after_deadline.CanResume(1, 151));

    server::SessionRecoveryState publish_grace;
    BOOST_REQUIRE(publish_grace.Suspend(1, 100, 50));
    BOOST_REQUIRE(publish_grace.ReserveResume(1, 140, 101));
    BOOST_REQUIRE(publish_grace.MarkResumeCommitted(101, 145, 20));
    BOOST_TEST(publish_grace.CanCommitResume(1, 164, 101));
    BOOST_TEST(!publish_grace.CanCommitResume(1, 165, 101));

    const protocol::SessionResumeId id = MakeSessionId();
    WssPair pair;
    protocol::SessionResumeCandidateBinding output{};
    BOOST_TEST(!protocol::DeriveSessionResumeCandidateBinding(
        MakeExporter(pair.Client(), false), id, output));
    const protocol::SessionResumeCandidateBinding zero{};
    BOOST_TEST(output == zero);
}
