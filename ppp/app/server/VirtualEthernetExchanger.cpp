#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/mux/MuxCoordinator.h>
#include <ppp/app/server/udp/ServerDatagramPortManager.h>
#include <ppp/app/server/udp/StaticDatagramPortManager.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocolStatic.h>
#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/app/protocol/VirtualEthernetIPv6.h>
#include <ppp/app/protocol/VirtualEthernetPathMtu.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <openssl/crypto.h>

/**
 * @file VirtualEthernetExchanger.cpp
 * @brief Implements per-session packet forwarding, NAT, DNS relay and mapping handlers.
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::native::ip_hdr                                    ip_hdr;
typedef ppp::net::native::icmp_hdr                                  icmp_hdr;
typedef ppp::net::packet::IPFrame                                   IPFrame;
typedef ppp::net::packet::IcmpFrame                                 IcmpFrame;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::collections::Dictionary                                Dictionary;

namespace {
    using ppp::app::protocol::SessionResumeAction;
    using ppp::app::protocol::SessionResumeCandidateBinding;
    using ppp::app::protocol::SessionResumeControl;
    using ppp::app::protocol::SessionResumeExporter;
    using ppp::app::protocol::SessionResumeId;
    using ppp::app::protocol::SessionResumeNonce;
    using ppp::app::protocol::SessionResumePendingAttempt;
    using ppp::app::protocol::SessionResumeProof;
    using ppp::app::protocol::SessionResumeTranscriptFields;

    template<std::size_t Size>
    static bool DecodeLowerHex(const ppp::string& text,
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

        std::array<std::uint8_t, Size> decoded{};
        for (std::size_t i = 0; i < Size; ++i) {
            std::uint8_t high = 0;
            std::uint8_t low = 0;
            if (!nibble(text[i * 2], high) || !nibble(text[i * 2 + 1], low)) {
                OPENSSL_cleanse(decoded.data(), decoded.size());
                return false;
            }
            decoded[i] = static_cast<std::uint8_t>((high << 4) | low);
        }
        output = decoded;
        OPENSSL_cleanse(decoded.data(), decoded.size());
        return true;
    }

    template<std::size_t Size>
    static ppp::string EncodeLowerHex(const std::array<std::uint8_t, Size>& value) {
        static constexpr char Hex[] = "0123456789abcdef";
        ppp::string text;
        text.resize(Size * 2);
        for (std::size_t i = 0; i < Size; ++i) {
            text[i * 2] = Hex[value[i] >> 4];
            text[i * 2 + 1] = Hex[value[i] & 0x0f];
        }
        return text;
    }

    template<std::size_t Size>
    static bool IsZero(const std::array<std::uint8_t, Size>& value) noexcept {
        std::uint8_t combined = 0;
        for (std::uint8_t byte : value) {
            combined |= byte;
        }
        return combined == 0;
    }

    static bool BuildSessionResumeId(const ppp::Int128& id,
        SessionResumeId& binary, ppp::string& canonical) noexcept {
        ppp::string guid = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(id);
        canonical.clear();
        canonical.reserve(ppp::app::protocol::SessionResumeIdSize * 2);
        for (char value : guid) {
            if (value != '-') {
                canonical.push_back(value);
            }
        }
        return DecodeLowerHex(canonical, binary);
    }

    static bool IsConfiguredRecoveryCarrier(
        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
        const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
        if (!configuration || !configuration->server.session_resume.enabled ||
            !transmission || transmission->IsServerLoopbackIngress() ||
            !transmission->IsAuthenticatedCarrierBindingActive() ||
            !transmission->HasAuthenticatedSessionExporter()) {
            return false;
        }

        using ppp::transmissions::AuthenticatedCarrierKind;
        using ppp::transmissions::AuthenticatedCarrierMethod;
        const AuthenticatedCarrierKind kind = transmission->GetAuthenticatedCarrierKind();
        const AuthenticatedCarrierMethod method = transmission->GetAuthenticatedCarrierMethod();
        return (kind == AuthenticatedCarrierKind::TlsWebSocket &&
                method == AuthenticatedCarrierMethod::TlsExporterV1) ||
            ((kind == AuthenticatedCarrierKind::Tcp ||
                 kind == AuthenticatedCarrierKind::WebSocket) &&
                method == AuthenticatedCarrierMethod::NoisePskV1);
    }

    static bool IsRecoveryCapableCarrier(
        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
        const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
        if (!configuration || !configuration->server.session_resume.enabled ||
            !transmission || transmission->IsServerLoopbackIngress()) {
            return false;
        }

        using ppp::transmissions::AuthenticatedCarrierKind;
        using ppp::transmissions::AuthenticatedCarrierMethod;
        const AuthenticatedCarrierKind kind = transmission->GetAuthenticatedCarrierKind();
        const AuthenticatedCarrierMethod method = transmission->GetAuthenticatedCarrierMethod();
        return (kind == AuthenticatedCarrierKind::TlsWebSocket &&
                method == AuthenticatedCarrierMethod::TlsExporterV1) ||
            ((kind == AuthenticatedCarrierKind::Tcp ||
                 kind == AuthenticatedCarrierKind::WebSocket) &&
                method == AuthenticatedCarrierMethod::NoisePskV1);
    }

    static bool IsEligibleRecoveryCarrier(
        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
        const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
        return IsConfiguredRecoveryCarrier(configuration, transmission);
    }

    static SessionResumeExporter MakeSessionResumeExporter(
        const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
        return [transmission](const char* label, const std::uint8_t* context,
            std::size_t context_length, std::uint8_t* output,
            std::size_t output_length) noexcept {
                return transmission && transmission->ExportAuthenticatedSessionKey(
                    label, context, context_length, output, output_length);
            };
    }

    static void FillResumeControl(const SessionResumeTranscriptFields& fields,
        const SessionResumeProof& proof, SessionResumeControl& control) {
        control.Clear();
        control.version = SessionResumeControl::ProtocolVersion;
        control.action = fields.action;
        control.capabilities = fields.capabilities;
        control.session_id = EncodeLowerHex(fields.session_id);
        control.generation = fields.generation;
        control.client_nonce = EncodeLowerHex(fields.client_nonce);
        if (fields.action != SessionResumeAction::ResumeRequest &&
            fields.action != SessionResumeAction::GenerationSync) {
            control.server_nonce = EncodeLowerHex(fields.server_nonce);
        }
        control.candidate_binding = EncodeLowerHex(fields.candidate_binding);
        control.proof = EncodeLowerHex(proof);
    }

    static bool DecodeResumeControl(const SessionResumeControl& control,
        SessionResumeAction expected_action, const SessionResumeId& expected_session_id,
        SessionResumeTranscriptFields& fields, SessionResumeProof& proof) noexcept {
        if (!control.Valid() || !control.reason.empty() ||
            control.version != SessionResumeControl::ProtocolVersion ||
            control.action != expected_action ||
            control.capabilities != SessionResumeControl::CapabilityV1 ||
            control.session_id != EncodeLowerHex(expected_session_id) ||
            !DecodeLowerHex(control.client_nonce, fields.client_nonce) ||
            (!control.server_nonce.empty() &&
                !DecodeLowerHex(control.server_nonce, fields.server_nonce)) ||
            !DecodeLowerHex(control.candidate_binding, fields.candidate_binding) ||
            !DecodeLowerHex(control.proof, proof)) {
            return false;
        }

        fields.action = expected_action;
        fields.capabilities = control.capabilities;
        fields.session_id = expected_session_id;
        fields.generation = control.generation;
        return true;
    }

    /**
     * @brief Extracts the destination port from a first-fragment IPv6 TCP/UDP packet.
     * @param packet Raw IPv6 packet buffer.
     * @param packet_length Packet length in bytes.
     * @param next_header Parsed IPv6 next-header protocol value.
     * @param payload_length Parsed IPv6 payload length in bytes.
     * @param destination_port Output destination TCP/UDP port.
     * @param transport_protocol Output TCP/UDP protocol value found after IPv6 extension headers.
     * @param reject Output flag set when malformed or non-initial fragmented traffic cannot be safely filtered.
     * @return True when the packet carries enough TCP/UDP bytes to read the destination port.
     */
    static bool TryGetIPv6TransportDestinationPort(const ppp::Byte* packet, int packet_length, ppp::Byte next_header, int payload_length, int& destination_port, ppp::Byte& transport_protocol, bool& reject) noexcept {
        reject = false;
        transport_protocol = 0;
        if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
            return false;
        }

        int offset = ppp::ipv6::IPv6_HEADER_MIN_SIZE;
        int remaining = std::min<int>(payload_length, packet_length - ppp::ipv6::IPv6_HEADER_MIN_SIZE);
        for (;;) {
            if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
                break;
            }

            if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING || next_header == IPPROTO_DSTOPTS) {
                if (remaining < 2) {
                    reject = true;
                    return false;
                }

                int header_length = (static_cast<int>(packet[offset + 1]) + 1) * 8;
                if (header_length < 8 || remaining < header_length) {
                    reject = true;
                    return false;
                }

                next_header = packet[offset];
                offset += header_length;
                remaining -= header_length;
                continue;
            }

            if (next_header == IPPROTO_FRAGMENT) {
                if (remaining < 8) {
                    reject = true;
                    return false;
                }

                int fragment_offset_and_flags = (static_cast<int>(packet[offset + 2]) << 8) | static_cast<int>(packet[offset + 3]);
                if ((fragment_offset_and_flags & 0xfff8) != 0) {
                    reject = true;
                    return false;
                }

                next_header = packet[offset];
                offset += 8;
                remaining -= 8;
                continue;
            }

            if (next_header == IPPROTO_AH) {
                if (remaining < 2) {
                    reject = true;
                    return false;
                }

                int header_length = (static_cast<int>(packet[offset + 1]) + 2) * 4;
                if (header_length < 8 || remaining < header_length) {
                    reject = true;
                    return false;
                }

                next_header = packet[offset];
                offset += header_length;
                remaining -= header_length;
                continue;
            }

            return false;
        }

        transport_protocol = next_header;
        if (remaining < 4) {
            reject = true;
            return false;
        }

        const ppp::Byte* transport = packet + offset;
        destination_port = (static_cast<int>(transport[2]) << 8) | static_cast<int>(transport[3]);
        return destination_port > IPEndPoint::MinPort && destination_port <= IPEndPoint::MaxPort;
    }

    /**
     * @brief Converts matching ICMPv6 gateway echo requests into echo replies in-place.
     * @param packet Raw IPv6 packet buffer.
     * @param packet_length Packet length in bytes.
     * @param gateway Expected gateway destination address.
     * @return True when packet was transformed to a valid echo reply.
     */
    static bool HandleIPv6GatewayEchoReply(ppp::Byte* packet, int packet_length, const boost::asio::ip::address_v6& gateway) noexcept {
        if (NULLPTR == packet || packet_length < 48) {
            return false;
        }

        ppp::app::protocol::VirtualEthernetIPv6MinimalHeader* header = reinterpret_cast<ppp::app::protocol::VirtualEthernetIPv6MinimalHeader*>(packet);
        boost::asio::ip::address_v6 source;
        boost::asio::ip::address_v6 destination;
        ppp::Byte next_header = 0;
        int payload_length = 0;
        if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination, &next_header, &payload_length) || next_header != IPPROTO_ICMPV6) {
            return false;
        }

        if (destination != gateway) {
            return false;
        }

        icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(packet + ppp::ipv6::IPv6_HEADER_MIN_SIZE);
        int icmp_length = payload_length;
        if (icmp_length < static_cast<int>(sizeof(icmp_hdr))) {
            return false;
        }

        if (icmp->icmp_type != 128 || icmp->icmp_code != 0) {
            return false;
        }

        boost::asio::ip::address_v6::bytes_type source_bytes = source.to_bytes();
        boost::asio::ip::address_v6::bytes_type gateway_bytes = gateway.to_bytes();
        memcpy(header->Source, gateway_bytes.data(), gateway_bytes.size());
        memcpy(header->Destination, source_bytes.data(), source_bytes.size());
        header->HopLimit = ppp::ipv6::IPv6_DEFAULT_HOP_LIMIT;

        icmp->icmp_type = 129;
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = ppp::app::protocol::VirtualEthernetIPv6PseudoChecksum(reinterpret_cast<unsigned char*>(icmp), icmp_length, gateway, source, IPPROTO_ICMPV6);
        return true;
    }
}

namespace ppp {
    namespace app {
        namespace server {
            using ppp::telemetry::Level;

            /**
             * @brief Initializes exchanger state for one virtual session.
             */
            VirtualEthernetExchanger::VirtualEthernetExchanger(
                const VirtualEthernetSwitcherPtr&                       switcher,
                const AppConfigurationPtr&                              configuration,
                const ITransmissionPtr&                                 transmission,
                const Int128&                                           id) noexcept
                : VirtualEthernetLinklayer(configuration, transmission->GetContext(), id)
                , address_(IPEndPoint::NoneAddress)
                , switcher_(switcher)
                , transmission_(transmission)
                , static_echo_session_id_(0) {

                ppp::string canonical_session_id;
                BuildSessionResumeId(id, recovery_session_id_, canonical_session_id);

                std::shared_ptr<boost::asio::io_context> context = transmission->GetContext();
                buffer_ = Executors::GetCachedBuffer(context);
                mux_coordinator_ = std::make_unique<ppp::app::mux::MuxCoordinator>();
                firewall_ = switcher->GetFirewall();
                managed_server_ = switcher->GetManagedServer();
                datagram_manager_ = std::make_unique<udp::ServerDatagramPortManager>(BuildServerUdpRelayHostPorts());
                static_datagram_manager_ = std::make_unique<udp::StaticDatagramPortManager>(BuildStaticUdpRelayHostPorts());

                for (;;) {
                    ITransmissionPtr transmission = GetTransmission();
                    if (NULLPTR != transmission) {
                        std::shared_ptr<ITransmissionStatistics> statistics = transmission->Statistics;
                        if (NULLPTR != statistics) {
                            statistics_ = statistics;
                            break;
                        }
                    }

                    statistics_ = switcher->GetStatistics();
                    break;
                }

                static_echo_source_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);

                ppp::telemetry::Log(Level::kInfo, "exchanger", "constructed");
                ppp::telemetry::Count("exchanger.create", 1);
            }

            VirtualEthernetExchanger::ITransmissionPtr VirtualEthernetExchanger::GetTransmission() noexcept {
                std::lock_guard<std::mutex> lock(carrier_mutex_);
                return transmission_;
            }

            std::uint64_t VirtualEthernetExchanger::GetCarrierGeneration() noexcept {
                std::lock_guard<std::mutex> lock(carrier_mutex_);
                return recovery_state_.GetGeneration();
            }

            bool VirtualEthernetExchanger::PrepareFreshResumeOffer(
                const ITransmissionPtr& transmission, SessionResumeControl& offer) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (disposed_ || NULLPTR == transmission || transmission->GetContext() != GetContext() ||
                    !IsEligibleRecoveryCarrier(configuration, transmission) ||
                    IsZero(recovery_session_id_)) {
                    return false;
                }

                ppp::app::protocol::SessionResumeSecret root;
                SessionResumeNonce server_nonce{};
                if (!ppp::app::protocol::DeriveSessionResumeRetainedRoot(
                        MakeSessionResumeExporter(transmission), recovery_session_id_, root) ||
                    !ppp::app::protocol::GenerateSessionResumeNonce(server_nonce)) {
                    return false;
                }

                const UInt64 now = Executors::GetTickCount();
                const UInt64 timeout = static_cast<UInt64>(
                    std::max(1, configuration->tcp.connect.timeout)) * 1000;
                const UInt64 maximum = std::numeric_limits<UInt64>::max();
                const UInt64 deadline = timeout > maximum - now
                    ? maximum : now + timeout;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    if (disposed_ || transmission_ != transmission ||
                        recovery_state_.GetState() != SessionRecoveryState::State::Active ||
                        recovery_armed_ || pending_fresh_root_.IsSet() ||
                        pending_fresh_transmission_ || resume_attempt_.IsActive()) {
                        OPENSSL_cleanse(server_nonce.data(), server_nonce.size());
                        return false;
                    }
                    pending_fresh_root_ = std::move(root);
                    pending_fresh_server_nonce_ = server_nonce;
                    pending_fresh_transmission_ = transmission;
                    pending_fresh_deadline_ = deadline;
                }

                offer.Clear();
                offer.version = SessionResumeControl::ProtocolVersion;
                offer.action = SessionResumeAction::Offer;
                offer.capabilities = SessionResumeControl::CapabilityV1;
                offer.session_id = EncodeLowerHex(recovery_session_id_);
                offer.generation = 0;
                offer.server_nonce = EncodeLowerHex(server_nonce);
                OPENSSL_cleanse(server_nonce.data(), server_nonce.size());
                return true;
            }

            VirtualEthernetExchanger::ResumeBeginStatus VirtualEthernetExchanger::BeginResume(
                const ITransmissionPtr& transmission, const SessionResumeControl& request,
                const SessionResumeCandidateBinding& candidate, UInt64 now,
                std::uint64_t& reservation_token, SessionResumeControl& response) noexcept {
                reservation_token = 0;
                response.Clear();

                AppConfigurationPtr configuration = GetConfiguration();
                if (disposed_ || NULLPTR == transmission || transmission->GetContext() != GetContext() ||
                    !IsEligibleRecoveryCarrier(configuration, transmission)) {
                    return ResumeBeginStatus::Rejected;
                }

                SessionResumePendingAttempt request_attempt;
                SessionResumeTranscriptFields& request_fields = request_attempt.fields;
                SessionResumeProof& request_proof = request_attempt.proof;
                if (!DecodeResumeControl(request, SessionResumeAction::ResumeRequest,
                        recovery_session_id_, request_fields, request_proof) ||
                    request_fields.candidate_binding != candidate ||
                    !IsZero(request_fields.server_nonce)) {
                    return ResumeBeginStatus::Rejected;
                }

                std::lock_guard<std::mutex> lock(carrier_mutex_);
                if (disposed_ || !recovery_armed_ || !retained_root_.IsSet() ||
                    transmission_ || resume_attempt_.IsActive() ||
                    !recovery_state_.IsSuspended(now) ||
                    !ppp::app::protocol::VerifySessionResumeProof(
                        retained_root_, request_fields, request_proof)) {
                    return ResumeBeginStatus::Rejected;
                }

                SessionResumePendingAttempt response_attempt;
                SessionResumeTranscriptFields& response_fields = response_attempt.fields;
                SessionResumeProof& response_proof = response_attempt.proof;
                response_fields.action = request_fields.generation == recovery_state_.GetGeneration()
                    ? SessionResumeAction::ResumeAccept
                    : SessionResumeAction::GenerationSync;
                response_fields.capabilities = SessionResumeControl::CapabilityV1;
                response_fields.session_id = recovery_session_id_;
                response_fields.generation = recovery_state_.GetGeneration();
                response_fields.client_nonce = request_fields.client_nonce;
                response_fields.candidate_binding = request_fields.candidate_binding;

                SessionResumeNonce server_nonce{};
                if (response_fields.action == SessionResumeAction::ResumeAccept &&
                    !ppp::app::protocol::GenerateSessionResumeNonce(server_nonce)) {
                    return ResumeBeginStatus::Rejected;
                }
                response_fields.server_nonce = server_nonce;

                if (!ppp::app::protocol::ComputeSessionResumeProof(
                        retained_root_, response_fields, response_proof)) {
                    OPENSSL_cleanse(server_nonce.data(), server_nonce.size());
                    return ResumeBeginStatus::Rejected;
                }

                if (response_fields.action == SessionResumeAction::GenerationSync) {
                    FillResumeControl(response_fields, response_proof, response);
                    OPENSSL_cleanse(response_proof.data(), response_proof.size());
                    return ResumeBeginStatus::GenerationSync;
                }

                do {
                    ++next_resume_token_;
                } while (next_resume_token_ == 0);
                if (!recovery_state_.ReserveResume(
                        response_fields.generation, now, next_resume_token_)) {
                    OPENSSL_cleanse(server_nonce.data(), server_nonce.size());
                    OPENSSL_cleanse(response_proof.data(), response_proof.size());
                    return ResumeBeginStatus::Rejected;
                }

                resume_attempt_.Clear();
                resume_attempt_.active = true;
                resume_attempt_.fields = response_fields;
                resume_attempt_.proof = response_proof;
                resume_candidate_ = transmission;
                reservation_token = next_resume_token_;
                FillResumeControl(response_fields, response_proof, response);
                OPENSSL_cleanse(server_nonce.data(), server_nonce.size());
                OPENSSL_cleanse(response_proof.data(), response_proof.size());
                return ResumeBeginStatus::Reserved;
            }

            /** @brief Bounded window for publishing the data plane after a committed resume. */
            static constexpr std::uint64_t kResumePublishGraceMs = 10000;

            bool VirtualEthernetExchanger::CommitResume(
                const ITransmissionPtr& transmission, const SessionResumeControl& confirm,
                const SessionResumeCandidateBinding& candidate,
                std::uint64_t reservation_token, UInt64 now,
                SessionResumeControl& committed) noexcept {
                committed.Clear();
                AppConfigurationPtr configuration = GetConfiguration();
                if (reservation_token == 0 || disposed_ || NULLPTR == transmission ||
                    transmission->GetContext() != GetContext() ||
                    !IsEligibleRecoveryCarrier(configuration, transmission)) {
                    return false;
                }

                SessionResumePendingAttempt confirm_attempt;
                SessionResumeTranscriptFields& confirm_fields = confirm_attempt.fields;
                SessionResumeProof& confirm_proof = confirm_attempt.proof;
                if (!DecodeResumeControl(confirm, SessionResumeAction::ResumeConfirm,
                        recovery_session_id_, confirm_fields, confirm_proof) ||
                    confirm_fields.candidate_binding != candidate) {
                    return false;
                }

                bool candidate_valid = false;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    const SessionResumeTranscriptFields& accepted = resume_attempt_.fields;
                    candidate_valid = !disposed_ && resume_candidate_ == transmission &&
                        resume_attempt_.IsActive() && NULLPTR == transmission_ &&
                        NULLPTR == resume_replacement_echo_ &&
                        recovery_state_.CanCommitResume(
                            accepted.generation, now, reservation_token) &&
                        confirm_fields.generation == accepted.generation &&
                        confirm_fields.client_nonce == accepted.client_nonce &&
                        confirm_fields.server_nonce == accepted.server_nonce &&
                        confirm_fields.candidate_binding == accepted.candidate_binding &&
                        ppp::app::protocol::VerifySessionResumeProof(
                            retained_root_, confirm_fields, confirm_proof);
                }
                if (!candidate_valid) {
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr replacement_echo =
                    NewEchoTransmissions(transmission);
                if (NULLPTR == replacement_echo) {
                    return false;
                }

                bool prepared = false;
                const UInt64 prepare_now = std::max<UInt64>(now, Executors::GetTickCount());
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    const SessionResumeTranscriptFields& accepted = resume_attempt_.fields;
                    if (!disposed_ && resume_candidate_ == transmission &&
                        resume_attempt_.IsActive() && NULLPTR == transmission_ &&
                        NULLPTR == resume_replacement_echo_ &&
                        recovery_state_.CanCommitResume(
                            accepted.generation, prepare_now, reservation_token) &&
                        confirm_fields.generation == accepted.generation &&
                        confirm_fields.client_nonce == accepted.client_nonce &&
                        confirm_fields.server_nonce == accepted.server_nonce &&
                        confirm_fields.candidate_binding == accepted.candidate_binding &&
                        ppp::app::protocol::VerifySessionResumeProof(
                            retained_root_, confirm_fields, confirm_proof) &&
                        accepted.generation != std::numeric_limits<std::uint64_t>::max()) {
                        SessionResumePendingAttempt committed_attempt;
                        SessionResumeTranscriptFields& committed_fields =
                            committed_attempt.fields;
                        SessionResumeProof& committed_proof = committed_attempt.proof;
                        committed_fields = accepted;
                        committed_fields.action = SessionResumeAction::ResumeCommitted;
                        committed_fields.generation = accepted.generation + 1;
                        SessionResumeControl prepared_committed;
                        if (ppp::app::protocol::ComputeSessionResumeProof(
                                retained_root_, committed_fields, committed_proof)) {
                            FillResumeControl(
                                committed_fields, committed_proof, prepared_committed);
                            if (prepared_committed.Valid() &&
                                recovery_state_.MarkResumeCommitted(
                                    reservation_token, prepare_now,
                                    kResumePublishGraceMs)) {
                                resume_replacement_echo_ = std::move(replacement_echo);
                                resume_replacement_statistics_ = transmission->Statistics;
                                committed = std::move(prepared_committed);
                                prepared = true;
                            }
                        }
                    }
                }

                if (!prepared) {
                    replacement_echo->Dispose();
                }
                return prepared;
            }

            bool VirtualEthernetExchanger::PublishCommittedResume(
                const ITransmissionPtr& transmission,
                std::uint64_t reservation_token, UInt64 now) noexcept {
                if (reservation_token == 0 || disposed_ || NULLPTR == transmission) {
                    return false;
                }

                bool resumed = false;
                VirtualInternetControlMessageProtocolPtr previous_echo;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    const SessionResumeTranscriptFields& accepted = resume_attempt_.fields;
                    if (!disposed_ && resume_candidate_ == transmission &&
                        resume_attempt_.IsActive() && NULLPTR == transmission_ &&
                        NULLPTR != resume_replacement_echo_ &&
                        recovery_state_.CanCommitResume(
                            accepted.generation, now, reservation_token)) {
                        resumed = CommitSessionResumeAndPublish(
                            recovery_state_, accepted.generation, now,
                            reservation_token,
                            [&](std::uint64_t committed_generation) noexcept {
                                (void)committed_generation;
                                if (NULLPTR == statistics_) {
                                    statistics_ = resume_replacement_statistics_;
                                }
                                elif (NULLPTR != resume_replacement_statistics_ &&
                                    resume_replacement_statistics_ != statistics_) {
                                    statistics_->AddIncomingTraffic(
                                        resume_replacement_statistics_->IncomingTraffic.load());
                                    statistics_->AddOutgoingTraffic(
                                        resume_replacement_statistics_->OutgoingTraffic.load());
                                }
                                if (NULLPTR != statistics_) {
                                    transmission->Statistics = statistics_;
                                }

                                datagram_manager_->RebindTransmission(transmission);
                                previous_echo = std::move(echo_);
                                echo_ = std::move(resume_replacement_echo_);
                                resume_replacement_statistics_.reset();
                                transmission_ = transmission;
                                resume_attempt_.Clear();
                                resume_candidate_.reset();
                            });
                    }
                }

                if (!resumed) {
                    return false;
                }
                if (NULLPTR != previous_echo) {
                    previous_echo->Dispose();
                }

                ppp::telemetry::Count("server.session.resumed", 1);
                ppp::telemetry::Log(Level::kInfo, "exchanger", "session carrier resumed");
                return true;
            }

            void VirtualEthernetExchanger::CancelResume(
                const ITransmissionPtr& transmission,
                std::uint64_t reservation_token) noexcept {
                if (reservation_token == 0) {
                    return;
                }

                VirtualInternetControlMessageProtocolPtr replacement_echo;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    if (resume_candidate_ == transmission &&
                        recovery_state_.CancelResume(reservation_token)) {
                        resume_attempt_.Clear();
                        resume_candidate_.reset();
                        replacement_echo = std::move(resume_replacement_echo_);
                        resume_replacement_statistics_.reset();
                    }
                }
                if (NULLPTR != replacement_echo) {
                    replacement_echo->Dispose();
                }
            }

            VirtualEthernetExchanger::CarrierStopResult VirtualEthernetExchanger::OnCarrierStopped(
                const ITransmissionPtr& transmission, std::uint64_t generation,
                ppp::diagnostics::ErrorCode error, UInt64 now) noexcept {
                auto is_recoverable_error = [](ppp::diagnostics::ErrorCode value) noexcept {
                    using ErrorCode = ppp::diagnostics::ErrorCode;
                    switch (value) {
                    case ErrorCode::TunnelReadFailed:
                    case ErrorCode::TunnelWriteFailed:
                    case ErrorCode::SocketDisconnected:
                    case ErrorCode::SocketReadFailed:
                    case ErrorCode::SocketWriteFailed:
                    case ErrorCode::SocketTimeout:
                    case ErrorCode::TcpReceiveFailed:
                    case ErrorCode::WebSocketClosed:
                    case ErrorCode::WebSocketReadFailed:
                    case ErrorCode::WebSocketWriteFailed:
                        return true;
                    default:
                        return false;
                    }
                };

                AppConfigurationPtr configuration = GetConfiguration();
                const bool eligible = IsRecoveryCapableCarrier(configuration, transmission);
                const UInt64 grace = eligible
                    ? static_cast<UInt64>(configuration->server.session_resume.grace_ms)
                    : 0;

                VirtualInternetControlMessageProtocolPtr previous_echo;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    if (recovery_state_.GetGeneration() != generation || transmission_ != transmission) {
                        return CarrierStopResult::Stale;
                    }

                    if (disposed_ || !eligible || !recovery_armed_ ||
                        !retained_root_.IsSet() || resume_attempt_.IsActive() ||
                        !is_recoverable_error(error) ||
                        !recovery_state_.Suspend(generation, now, grace)) {
                        retained_root_.Clear();
                        pending_fresh_root_.Clear();
                        OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                            pending_fresh_server_nonce_.size());
                        pending_fresh_transmission_.reset();
                        pending_fresh_deadline_ = 0;
                        recovery_armed_ = false;
                        resume_attempt_.Clear();
                        resume_candidate_.reset();
                        return CarrierStopResult::Terminal;
                    }

                    pending_fresh_root_.Clear();
                    OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                        pending_fresh_server_nonce_.size());
                    pending_fresh_transmission_.reset();
                    pending_fresh_deadline_ = 0;
                    transmission_.reset();
                    previous_echo = std::move(echo_);
                }

                datagram_manager_->RebindTransmission(NULLPTR);
                {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::ReleaseAllObjects(mappings_);
                    mappings_.clear();
                }

                if (std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Take(); NULLPTR != mux) {
                    mux->close_exec();
                }
                if (NULLPTR != previous_echo) {
                    previous_echo->Dispose();
                }

                // Static echo is carrier-adjacent state, not part of the retained
                // logical L3/NAT/UDP relay session. The client negotiates it again
                // after resume commit, so release its socket, ports and allocation.
                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> previous_static_echo =
                    std::move(static_echo_);
                if (NULLPTR != previous_static_echo) {
                    previous_static_echo->Dispose();
                }
                static_datagram_manager_->Release();
                static_echo_source_ep_ = boost::asio::ip::udp::endpoint(
                    boost::asio::ip::address_v4::any(), 0);
                static_allocated_context_.reset();
                const int freed_static_echo_id = static_echo_session_id_.exchange(0);
                if (freed_static_echo_id != 0 && NULLPTR != switcher_) {
                    switcher_->StaticEchoUnallocated(freed_static_echo_id);
                }

                ppp::telemetry::Count("server.session.suspended", 1);
                ppp::telemetry::Log(Level::kInfo, "exchanger", "session carrier suspended");
                return CarrierStopResult::Suspended;
            }

            bool VirtualEthernetExchanger::IsRecoveryExpired(UInt64 now) noexcept {
                std::lock_guard<std::mutex> lock(carrier_mutex_);
                return recovery_state_.IsExpired(now);
            }

            bool VirtualEthernetExchanger::IsSuspended(UInt64 now) noexcept {
                std::lock_guard<std::mutex> lock(carrier_mutex_);
                return recovery_state_.IsSuspended(now);
            }

            udp::ServerUdpRelayHostPorts VirtualEthernetExchanger::BuildServerUdpRelayHostPorts() noexcept {
                // The manager is a member owned by this exchanger, so its callbacks may capture the
                // raw exchanger pointer: they never outlive the exchanger, and this is invoked from the
                // constructor where shared_from_this() is not yet available.
                VirtualEthernetExchanger* self = this;

                udp::ServerUdpRelayHostPorts host;
                host.create_port =
                    [self](const udp::ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                        return self->NewDatagramPort(transmission, source);
                    };
                // Keep the switcher logger / debug telemetry on the exchanger side so the manager stays
                // pure mechanism; fired once when a fresh port's socket opens (was inline in SendPacketToDestination).
                host.on_port_opened =
                    [self](const udp::ITransmissionPtr& transmission, const udp::VirtualEthernetDatagramPortPtr& port) noexcept {
                        VirtualEthernetLoggerPtr logger = self->switcher_->GetLogger();
                        if (NULLPTR != logger) {
                            logger->Port(self->GetId(), transmission, port->GetSourceEndPoint(), port->GetLocalEndPoint());
                        }

                        ppp::telemetry::Log(Level::kDebug, "exchanger", "datagram port opened");
                    };
                host.get_configuration = [self]() noexcept { return self->GetConfiguration(); };
                // do_send_to mirrors the link-layer SENDTO; the port supplies its own transmission and
                // coroutine yield context. release_port lets a port deregister itself on finalize.
                host.do_send_to =
                    [self](const udp::ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source,
                           const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length,
                           ppp::coroutines::YieldContext& y) noexcept {
                        return self->DoSendTo(transmission, source, destination, packet, packet_length, y);
                    };
                host.release_port =
                    [self](const boost::asio::ip::udp::endpoint& source) noexcept { self->ReleaseDatagramPort(source); };
                host.get_interface_ip = [self]() noexcept { return self->switcher_->GetInterfaceIP(); };
                host.namespace_query =
                    [self](const void* packet, int packet_length) noexcept { return NamespaceQueryCache(self->switcher_, packet, packet_length); };
                return host;
            }

            udp::StaticUdpRelayHostPorts VirtualEthernetExchanger::BuildStaticUdpRelayHostPorts() noexcept {
                VirtualEthernetExchanger* self = this;

                udp::StaticUdpRelayHostPorts host;
                // create_port binds the current io_context and owning exchanger to a fresh static port,
                // exactly as the inline StaticEchoSendToDestination slow-path did (context null -> no port).
                host.create_port =
                    [self](uint32_t source_ip, int source_port) noexcept -> udp::VirtualEthernetDatagramPortStaticPtr {
                        std::shared_ptr<boost::asio::io_context> context = self->GetContext();
                        if (NULLPTR == context) {
                            return NULLPTR;
                        }

                        auto my = self->shared_from_this();
                        auto exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                        if (NULLPTR == exchanger) {
                            return NULLPTR;
                        }

                        return make_shared_object<VirtualEthernetDatagramPortStatic>(exchanger, context, source_ip, source_port);
                    };
                host.on_port_opened =
                    [self](const udp::VirtualEthernetDatagramPortStaticPtr& port) noexcept {
                        VirtualEthernetLoggerPtr logger = self->switcher_->GetLogger();
                        if (NULLPTR != logger) {
                            logger->Port(self->GetId(), self->GetTransmission(), port->GetSourceEndPoint(), port->GetLocalEndPoint());
                        }

                        ppp::telemetry::Log(Level::kDebug, "exchanger", "static_echo datagram port opened");
                    };
                return host;
            }

            /** @brief Releases exchanger resources. */
            VirtualEthernetExchanger::~VirtualEthernetExchanger() noexcept {
                Finalize();

                ppp::telemetry::Log(Level::kInfo, "exchanger", "destroyed");
                ppp::telemetry::Count("exchanger.destroy", 1);
            }

            /** @brief Gets preferred TUN descriptor hint. */
            int VirtualEthernetExchanger::GetPreferredTunFd() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return preferred_tun_fd_;
            }

            /** @brief Sets preferred TUN descriptor hint. */
            void VirtualEthernetExchanger::SetPreferredTunFd(int fd) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                preferred_tun_fd_ = fd;
            }

            /** @brief Defers finalization onto exchanger io context. */
            void VirtualEthernetExchanger::Dispose() noexcept {
                Dispose(ppp::function<void()>());
            }

            void VirtualEthernetExchanger::Dispose(
                ppp::function<void()> completion) noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, completion = std::move(completion)]() mutable noexcept {
                        Finalize();
                        if (completion) {
                            completion();
                        }
                    });
            }

            /** @brief Finalizes all runtime objects and unregisters session from switcher. */
            void VirtualEthernetExchanger::Finalize() noexcept {
                // BUG-15 + BUG-17: Guard against double-finalization using atomic exchange.
                // If exchange returns true, another thread already entered Finalize; bail out.
                // This must happen BEFORE any map is cleared, so that any concurrent
                // async callback that checks disposed_ first will bail out immediately and will
                // not touch datagrams_, mappings_, or timeouts_ after we release them.
                if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                    return;
                }

                static_echo_source_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);
                for (;;) {
                    datagram_manager_->Release();

                    Dictionary::ReleaseAllObjects(mappings_);
                    mappings_.clear();

                    Timer::ReleaseAllTimeouts(timeouts_);
                    timeouts_.clear();

                    VirtualInternetControlMessageProtocolPtr echo;
                    VirtualInternetControlMessageProtocolPtr replacement_echo;
                    ITransmissionPtr transmission;
                    {
                        std::lock_guard<std::mutex> lock(carrier_mutex_);
                        echo = std::move(echo_);
                        replacement_echo = std::move(resume_replacement_echo_);
                        resume_replacement_statistics_.reset();
                        transmission = std::move(transmission_);
                        retained_root_.Clear();
                        pending_fresh_root_.Clear();
                        OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                            pending_fresh_server_nonce_.size());
                        pending_fresh_transmission_.reset();
                        pending_fresh_deadline_ = 0;
                        recovery_armed_ = false;
                        resume_attempt_.Clear();
                        resume_candidate_.reset();
                    }
                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = std::move(static_echo_);
                    std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Take();

                    if (NULLPTR != echo) {
                        echo->Dispose();
                    }
                    if (NULLPTR != replacement_echo) {
                        replacement_echo->Dispose();
                    }

                    if (NULLPTR != static_echo) {
                        static_echo->Dispose();
                    }

                    if (NULLPTR != transmission) {
                        transmission->Dispose();
                    }

                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }

                    break;
                }

                UploadTrafficToManagedServer();
                static_datagram_manager_->Release();

                static_allocated_context_.reset();

                // BUG-15: Guard every switcher call with a null check — switcher_ may be null
                // if the constructor did not receive a valid switcher reference.
                if (switcher_) {
                    switcher_->DeleteIPv6Exchanger(GetId());
                    switcher_->DeleteP2PPeer(GetId());
                    switcher_->DeletePeerPrefixGateway(GetId());
                    switcher_->DeleteExchanger(this);
                    switcher_->DeleteNatInformation(this, address_);

                    int freed_session_id = static_echo_session_id_.exchange(0);
                    if (freed_session_id != 0) {
                        ppp::telemetry::Log(Level::kInfo, "exchanger", "static_echo freed session_id=%d", freed_session_id);
                        ppp::telemetry::Count("exchanger.static_echo.free", 1);
                    }

                    switcher_->StaticEchoUnallocated(freed_session_id);
                }
            }

            /** @brief Gets firewall assigned to this exchanger. */
            VirtualEthernetExchanger::FirewallPtr VirtualEthernetExchanger::GetFirewall() noexcept {
                return firewall_;
            }

            /** @brief Rejects direct connect requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Rejects direct push requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Rejects direct disconnect requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Handles logical echo acknowledgment from client. */
            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                DoEcho(transmission, ack_id, y);
                return true;
            }

            /** @brief Handles ICMP echo payload forwarded from client. */
            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendEchoToDestination(transmission, owner, packet, packet_length);
                return true;
            }

            /** @brief Handles UDP send request from virtual client endpoint. */
            bool VirtualEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendPacketToDestination(transmission, sourceEP, destinationEP, owner, packet, packet_length, y);
                return true;
            }

            /** @brief Rejects connect-ack packets from client side for safety hardening. */
            bool VirtualEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Handles legacy clients that send a base INFO packet without extensions. */
            bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                if (disposed_ || NULLPTR == switcher_ || NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = switcher_->GetConfiguration();
                if (NULLPTR != configuration && !configuration->server.backend.empty()) {
                    return true;
                }

                InformationEnvelope response;
                response.Base.Clear();
                response.Base.BandwidthQoS = 0;
                response.Base.IncomingTraffic = std::numeric_limits<UInt64>::max();
                response.Base.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                response.Base.ExpiredTime = std::numeric_limits<UInt32>::max();
                response.Extensions.Clear();

                SessionResumeControl offer;
                if (PrepareFreshResumeOffer(transmission, offer)) {
                    response.Extensions.SessionResume = offer;
                    response.ExtendedJson = response.Extensions.ToJson();
                }
                return DoInformation(transmission, response, y);
            }

            /** @brief Processes extended information packets, including IPv4/IPv6 assignment requests. */
            bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                if (disposed_ || NULLPTR == switcher_ || NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                const VirtualEthernetInformationExtensions& request = information.Extensions;
                if (request.TransportAuth.HasAny()) {
                    // Transport authentication is consumed before Establish(). Any later or
                    // repeated control is a protocol violation and cannot be downgraded to INFO.
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return false;
                }

                const SessionResumeControl& resume = request.SessionResume;
                if (resume.HasAny()) {
                    VirtualEthernetInformationExtensions other_extensions = request;
                    other_extensions.SessionResume.Clear();

                    // A retained client can reach a fresh exchanger after server restart.
                    // If an initial offer is already in flight, consume its ResumeRequest and
                    // wait for Accepted. Otherwise reject the stale resume, then send a fresh
                    // offer (or plain INFO when recovery is unavailable) on the same carrier.
                    const bool restart_probe = !other_extensions.HasAny() && resume.Valid() &&
                        resume.version == SessionResumeControl::ProtocolVersion &&
                        resume.action == SessionResumeAction::ResumeRequest &&
                        resume.capabilities == SessionResumeControl::CapabilityV1 &&
                        resume.session_id == EncodeLowerHex(recovery_session_id_) &&
                        resume.reason.empty();
                    if (restart_probe) {
                        const UInt64 now = Executors::GetTickCount();
                        bool pending_offer = false;
                        {
                            std::lock_guard<std::mutex> lock(carrier_mutex_);
                            if (pending_fresh_deadline_ != 0 &&
                                now >= pending_fresh_deadline_) {
                                pending_fresh_root_.Clear();
                                OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                                    pending_fresh_server_nonce_.size());
                                pending_fresh_transmission_.reset();
                                pending_fresh_deadline_ = 0;
                            }
                            pending_offer = !disposed_ && transmission_ == transmission &&
                                pending_fresh_transmission_ == transmission &&
                                pending_fresh_root_.IsSet() && !retained_root_.IsSet() &&
                                !recovery_armed_ && pending_fresh_deadline_ != 0;
                        }
                        /**
                         * A probe that arrives here is always late: this carrier has
                         * already completed a fresh establish, and the configuration
                         * INFO sent there is what the client takes as its fresh
                         * negotiation answer (a frame without SessionResume control
                         * means Fresh on every client negotiation path).  Replying
                         * with Reject + an empty plain INFO would be applied by the
                         * client as a configuration frame and revoke the IPv4/IPv6/
                         * DNS state it just installed, so the probe is consumed
                         * silently instead.
                         */
                        (void)pending_offer;
                        return true;
                    }

                    SessionResumePendingAttempt accepted_attempt;
                    SessionResumeTranscriptFields& accepted_fields = accepted_attempt.fields;
                    SessionResumeProof& accepted_proof = accepted_attempt.proof;
                    accepted_fields.action = SessionResumeAction::Accepted;
                    accepted_fields.capabilities = resume.capabilities;
                    accepted_fields.session_id = recovery_session_id_;
                    accepted_fields.generation = resume.generation;
                    const bool decoded =
                        !other_extensions.HasAny() && resume.Valid() &&
                        resume.version == SessionResumeControl::ProtocolVersion &&
                        resume.action == SessionResumeAction::Accepted &&
                        resume.capabilities == SessionResumeControl::CapabilityV1 &&
                        resume.session_id == EncodeLowerHex(recovery_session_id_) &&
                        resume.generation == 0 && resume.candidate_binding.empty() &&
                        resume.reason.empty() &&
                        DecodeLowerHex(resume.client_nonce, accepted_fields.client_nonce) &&
                        DecodeLowerHex(resume.server_nonce, accepted_fields.server_nonce) &&
                        DecodeLowerHex(resume.proof, accepted_proof) &&
                        !IsZero(accepted_fields.client_nonce) &&
                        !IsZero(accepted_fields.server_nonce);

                    bool accepted = false;
                    {
                        std::lock_guard<std::mutex> lock(carrier_mutex_);
                        if (decoded && !disposed_ && transmission_ == transmission &&
                            pending_fresh_transmission_ == transmission &&
                            pending_fresh_root_.IsSet() && !retained_root_.IsSet() &&
                            !recovery_armed_ && pending_fresh_deadline_ != 0 &&
                            Executors::GetTickCount() < pending_fresh_deadline_ &&
                            accepted_fields.server_nonce == pending_fresh_server_nonce_ &&
                            ppp::app::protocol::VerifySessionResumeProof(
                                pending_fresh_root_, accepted_fields, accepted_proof)) {
                            retained_root_ = std::move(pending_fresh_root_);
                            recovery_armed_ = true;
                            accepted = true;
                        }

                        if (pending_fresh_transmission_ == transmission) {
                            pending_fresh_root_.Clear();
                            OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                                pending_fresh_server_nonce_.size());
                            pending_fresh_transmission_.reset();
                            pending_fresh_deadline_ = 0;
                        }
                    }
                    OPENSSL_cleanse(accepted_proof.data(), accepted_proof.size());
                    if (!accepted) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    }
                    return accepted;
                }

                bool has_ipv6_request = request.RequestedIPv6Address.is_v6();
                bool has_ipv4_request = request.ClientIPv4Req.enabled;
                bool has_p2p_request = request.P2P.HasAny();
                bool has_peer_route_request = request.PeerRouteAnnounce.HasAny();
                bool is_server_response = request.AssignedIPv6Address.is_v6() || request.IPv6StatusCode != VirtualEthernetInformationExtensions::IPv6Status_None;
                if (is_server_response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return false;
                }

                if (!has_ipv6_request && !has_ipv4_request && !has_p2p_request && !has_peer_route_request) {
                    return OnInformation(transmission, information.Base, y);
                }

                VirtualEthernetInformationExtensions response;
                response.Clear();

                // Process IPv6 request if present.
                if (has_ipv6_request) {
                    switcher_->UpdateIPv6Request(GetId(), request, response);
                }

                // Process IPv4 request if present.
                if (has_ipv4_request) {
                    switcher_->UpdateIPv4Request(GetId(), request, response);
                }

                if (has_p2p_request) {
                    auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(shared_from_this());
                    switcher_->UpdateP2PPeer(self, transmission, request, response);
                }

                if (has_peer_route_request) {
                    auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(shared_from_this());
                    switcher_->UpdatePeerRouteAnnounce(self, request, response);
                }

                if (switcher_->IsPeerRoutingEnabled()) {
                    switcher_->BuildPeerRouteTableSnapshot(response.PeerRouteTable);
                }

                // The base info quota/expire fields MUST satisfy the client-side
                // VirtualEthernetInformation::Valid() invariant
                // (IncomingTraffic > 0 && OutgoingTraffic > 0 && ExpiredTime > now);
                // otherwise the client treats this response as "session expired"
                // immediately after IPv4 assignment and tears the link down,
                // producing the silent ~5s reconnect loop observed in the field.
                //
                // For unmanaged sessions (no managed-server backend) we mirror the
                // fallback values that VirtualEthernetSwitcher::Establish() already
                // uses on the *first* INFO push: unbounded quotas and the maximum
                // representable expiration timestamp.
                VirtualEthernetInformation info;
                info.Clear();
                info.BandwidthQoS    = 0;
                info.IncomingTraffic = std::numeric_limits<UInt64>::max();
                info.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                info.ExpiredTime     = std::numeric_limits<UInt32>::max();

                VirtualEthernetSwitcher::InformationEnvelope envelope;
                envelope.Base = info;
                envelope.Extensions = response;
                envelope.ExtendedJson = response.ToJson();
                return DoInformation(transmission, envelope, y);
            }

            /** @brief Allocates static-echo relay session for client. */
            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                StaticEcho(transmission, y);
                return true;
            }

            /** @brief Rejects client-originated static assignment packets for safety hardening. */
            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Applies VMUX enable/disable request and acknowledges resulting state. */
            bool VirtualEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept {
                bool err = true;

                // Negotiated receiver ordering mode (flow v2). agreed == FLOW_V2 only when the
                // peer advertised the capability AND this end uses a non-compat scheduler.
                // Anything else (older peer, caps bit clear, compat mode) falls back to
                // compat global ordering.
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = switcher_->GetConfiguration();
                vmux::vmux_net::mux_mode effective_mux_mode = NULLPTR != configuration
                    ? vmux::vmux_net::parse_mode(configuration->GetEffectiveMuxMode())
                    : vmux::vmux_net::mux_mode_compat;
                // Capability is implementation-level (always true here), not "current mode".
                bool local_supports_flow_v2 = true;
                bool peer_supports_flow_v2 = (ordering_caps & vmux::vmux_net::ordering_caps_flow_v2) != 0;
                // Reliability / FEC capabilities: usage is config-gated locally,
                // and only takes effect when the peer advertises the bits too.
                bool peer_supports_reliability = (ordering_caps & vmux::vmux_net::ordering_caps_reliability) != 0;
                bool peer_supports_fec = (ordering_caps & vmux::vmux_net::ordering_caps_fec) != 0;
                bool local_reliability = NULLPTR != configuration && configuration->mux.reliability.enabled;
                bool local_fec = NULLPTR != configuration && configuration->mux.fec.enabled;
                // Provisional agreed ordering; apply_negotiation is authoritative once mux exists.
                bool turbo = NULLPTR != configuration && configuration->mux.turbo &&
                    effective_mux_mode == vmux::vmux_net::mux_mode_flow;
                bool need_flow_v2 = vmux::vmux_net::mode_requires_flow_v2(effective_mux_mode, turbo);
                vmux::vmux_net::receiver_ordering_mode agreed =
                    (need_flow_v2 && local_supports_flow_v2 && peer_supports_flow_v2)
                        ? vmux::vmux_net::ordering_flow_v2
                        : vmux::vmux_net::ordering_compat;

                for (;;) {
                    if (disposed_) {
                        break;
                    }

                    bool clean = vlan == 0 || max_connections == 0;
                    std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                    if (NULLPTR != mux) {
                        if (clean || mux->Vlan != vlan || mux->get_max_connections() != max_connections || mux->is_disposed()) {
                            mux_coordinator_->ResetIfCurrent(mux);
                            mux->close_exec();
                        }
                        else {
                            break;
                        }
                    }

                    if (clean) {
                        break;
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULLPTR == vmux_context) {
                        break;
                    }
                    if (NULLPTR == vmux_strand) {
                        vmux_strand = make_shared_object<ppp::threading::Executors::Strand>(vmux_context->get_executor());
                        if (NULLPTR == vmux_strand) {
                            break;
                        }
                    }

                    vmux::vmux_net::mux_mode mux_mode = effective_mux_mode;
                    mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, true, acceleration, mux_mode);
                    if (NULLPTR != mux) {
                        mux->Vlan = vlan;
                        mux->Firewall = GetFirewall();
                        mux->Logger = switcher_->GetLogger();
                        mux->AppConfiguration = configuration;
                        mux->BufferAllocator = transmission->BufferAllocator;

                        // turbo dynamic pool: the client may grow its carrier pool past
                        // the negotiated base at runtime. The client's turbo flag is
                        // not on the wire, so the server cannot know it; raise the
                        // ceiling for any flow-mode session (the ceiling is only a
                        // safety cap — accepting the extra ConnectMux links is benign,
                        // and a non-turbo client simply never sends them).
                        if (mux_mode == vmux::vmux_net::mux_mode_flow) {
                            uint32_t hard = (uint32_t)max_connections * (uint32_t)PPP_MUX_TURBO_FACTOR_MAX;
                            if (hard > UINT16_MAX) {
                                hard = UINT16_MAX;
                            }
                            mux->set_pool_hard_max((uint16_t)hard);
                        }

                        // Apply the effective scheduler and receiver ordering before establishment.
                        mux->apply_negotiation(local_supports_flow_v2, peer_supports_flow_v2,
                            local_reliability, peer_supports_reliability, local_fec, peer_supports_fec);
                        agreed = mux->get_ordering_mode();

                        if (mux->update()) {
                            err = false;
                            mux_coordinator_->Replace(mux);
                        }
                        else {
                            mux_coordinator_->ResetIfCurrent(mux);
                            mux->close_exec();
                        }
                    }

                    break;
                }

                if (err) {
                    if (std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Take(); NULLPTR != mux) {
                        mux->close_exec();
                    }

                    DoMux(transmission, 0, 0, false, 0, y);
                }
                else {
                    // Echo the agreed capabilities back so the client learns the result.
                    Byte agreed_caps = (agreed == vmux::vmux_net::ordering_flow_v2) ? (Byte)vmux::vmux_net::ordering_caps_flow_v2 : (Byte)0;
                    if (mux_coordinator_->Session() != NULLPTR && mux_coordinator_->Session()->reliability_agreed()) {
                        agreed_caps |= (Byte)vmux::vmux_net::ordering_caps_reliability;
                    }
                    if (mux_coordinator_->Session() != NULLPTR && mux_coordinator_->Session()->fec_agreed()) {
                        agreed_caps |= (Byte)vmux::vmux_net::ordering_caps_fec;
                    }
                    DoMux(transmission, vlan, max_connections, acceleration, agreed_caps, y);
                }

                return true;
            }

            /** @brief Handles client NAT packet and forwards via IPv4 or IPv6 routing path. */
            bool VirtualEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULLPTR == switcher_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (NULLPTR != logger) {
                    logger->Packet(GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ClientToServer);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                bool forwarded = false;
                if (configuration->server.subnet) {
                    forwarded = ForwardNatPacketToDestination(packet, packet_length, y);
                }

                if (!forwarded && switcher_->IsIPv6ServerEnabled()) {
                    ForwardIPv6PacketToDestination(packet, packet_length, y);
                }

                return true;
            }

            /** @brief Forwards IPv6 packet toward local exchanger or transit gateway. */
            bool VirtualEthernetExchanger::ForwardIPv6PacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();

                if (!switcher_->IsIPv6ServerEnabled()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                Byte next_header = 0;
                int payload_length = 0;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination, &next_header, &payload_length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                VirtualEthernetInformationExtensions approved;
                if (!switcher_->TryGetAssignedIPv6Extensions(GetId(), approved) || !approved.AssignedIPv6Address.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseUnavailable);
                    return false;
                }

                if (source != approved.AssignedIPv6Address.to_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                boost::asio::ip::address gateway = switcher_->GetIPv6TransitGateway();
                if (gateway.is_v6()) {
                    if (HandleIPv6GatewayEchoReply(packet, packet_length, gateway.to_v6())) {
                        ppp::telemetry::Log(Level::kDebug, "exchanger", "IPv6 gateway echo reply handled");
                        return DoNat(GetTransmission(), packet, packet_length, y);
                    }
                }

                // Reject packets destined for loopback or multicast addresses; these
                // must never be forwarded into the virtual network fabric.
                if (destination.is_loopback() || destination.is_multicast()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                FirewallPtr firewall = firewall_;
                if (NULLPTR != firewall) {
                    if (firewall->IsDropNetworkSegment(boost::asio::ip::address(destination))) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                        return false;
                    }

                    int destination_port = IPEndPoint::MinPort;
                    Byte transport_protocol = 0;
                    bool reject = false;
                    if (TryGetIPv6TransportDestinationPort(packet, packet_length, next_header, payload_length, destination_port, transport_protocol, reject) &&
                        firewall->IsDropNetworkPort(destination_port, transport_protocol == IPPROTO_TCP)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                        return false;
                    }

                    if (reject) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                        return false;
                    }
                }

                VirtualEthernetSwitcher::VirtualEthernetExchangerPtr exchanger = switcher_->FindIPv6Exchanger(destination);
                if (NULLPTR == exchanger) {
                    return switcher_->SendIPv6TransitPacket(packet, packet_length);
                }

                if (!configuration->server.subnet &&
                    configuration->server.ipv6.mode != AppConfiguration::IPv6Mode_Gua &&
                    configuration->server.ipv6.mode != AppConfiguration::IPv6Mode_Nat66) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (exchanger->DoNat(transmission, packet, packet_length, y)) {
                    VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                    if (NULLPTR != logger) {
                        logger->Packet(exchanger->GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToClient);
                    }
                    return true;
                }

                transmission->Dispose();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                return false;
            }

            /** @brief Registers NAT mapping after LAN information announcement. */
            bool VirtualEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.subnet) {
                    Arp(transmission, ip, mask);
                }

                return true;
            }

            /** @brief Allocates static echo context and responds with assigned session values. */
            bool VirtualEthernetExchanger::StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                ppp::string session_guid = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(GetId());
                ppp::telemetry::SpanScope span("exchanger.static_echo.alloc", session_guid.c_str());

                if (disposed_) {
                    return false;
                }

                int remote_port = IPEndPoint::MinPort;
                int allocated_id = 0;

                Int128 guid = GetId();
                auto allocated_context = switcher_->StaticEchoAllocated(guid, allocated_id, remote_port);

                if (NULLPTR != allocated_context) {
                    static_echo_session_id_.exchange(allocated_id);
                    static_allocated_context_ = allocated_context;

                    ppp::telemetry::Log(Level::kInfo, "exchanger", "static_echo allocated session_id=%d", allocated_id);
                    ppp::telemetry::Count("exchanger.static_echo.alloc", 1);

                    return DoStatic(transmission, allocated_context->fsid, allocated_id, remote_port, y);
                }
                else {
                    return DoStatic(transmission, 0, 0, IPEndPoint::MinPort, y);
                }
            }

            /** @brief Registers this exchanger in switcher NAT table using announced IP/mask. */
            bool VirtualEthernetExchanger::Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept {
                using VES = VirtualEthernetSwitcher;

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(mask, IPEndPoint::MinPort))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                    return false;
                }

                VES::NatInformationPtr nat = switcher_->AddNatInformation(exchanger, ip, mask);
                if (NULLPTR == nat) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingCreateFailed);
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (NULLPTR != logger) {
                    logger->Arp(GetId(), transmission, ip, mask);
                }

                // Mirror the legacy address into the IPv4 lease pool so a later
                // AcquireAuto() for a new-protocol client cannot hand the same
                // IP out a second time.  Best-effort: if the pool is not
                // configured or the IP is already leased to a different
                // session, the call is a silent no-op and the legacy NAT entry
                // remains the source of truth.  The pool entry is released
                // automatically alongside the session via DeleteIPv4Lease().
                switcher_->ReserveIPv4Lease(GetId(), ip);

                address_ = ip;
                return true;
            }

            /** @brief Removes timeout callback entry by native key pointer. */
            bool VirtualEthernetExchanger::DeleteTimeout(void* k) noexcept {
                if (NULLPTR == k) {
                    return false;
                }
                else {
                    return Dictionary::RemoveValueByKey(timeouts_, k);
                }
            }

            /** @brief Forwards one UDP payload to destination through cached/new datagram port. */
            bool VirtualEthernetExchanger::NamespaceQueryCache(
                const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                const void*                                         packet,
                int                                                 packet_length) noexcept {

                auto cache = switcher->GetNamespaceCache();
                if (NULLPTR == cache) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                    return false;
                }

                uint16_t queries_type = 0;
                uint16_t queries_clazz = 0;
                ppp::string domain = ppp::net::native::dns::ExtractHostY((Byte*)packet, packet_length,
                    [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                        queries_type = type;
                        queries_clazz = clazz;
                        return true;
                    });

                if (domain.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                std::shared_ptr<Byte> response = make_shared_alloc<Byte>(packet_length);
                if (NULLPTR == response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                memcpy(response.get(), packet, packet_length);

                return cache->Add(queries_key, response, packet_length);
            }

            int VirtualEthernetExchanger::NamespaceQueryReply(
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const ppp::string&                                  domain,
                const void*                                         packet,
                int                                                 packet_length,
                uint16_t                                            queries_type,
                uint16_t                                            queries_clazz,
                bool                                                static_transit) noexcept {

                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (NULLPTR != packet && packet_length >= sizeof(dns_hdr)) {
                    if (domain.size() > 0) {
                        auto cache = switcher_->GetNamespaceCache();
                        if (NULLPTR != cache) {
                            std::shared_ptr<Byte> response;
                            int response_length;

                            ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                            if (cache->Get(queries_key, response, response_length, ((dns_hdr*)packet)->usTransID)) {
                                ITransmissionPtr transmission = GetTransmission();
                                if (NULLPTR != transmission) {
                                    boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                                    if (static_transit) {
                                        bool outputed = VirtualEthernetDatagramPortStatic::Output(switcher_.get(),
                                            this, response.get(), response_length, sourceEP, remoteEP);
                                        if (outputed) {
                                            return 1;
                                        }
                                        else {
                                            return -1;
                                        }
                                    }
                                    elif(DoSendTo(transmission, sourceEP, remoteEP, response.get(), response_length, nullof<YieldContext>())) {
                                        return 1;
                                    }
                                    else {
                                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                                        transmission->Dispose();
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
                }

                return 0;
            }

            bool VirtualEthernetExchanger::SendPacketToDestination(const ITransmissionPtr& transmission,
                const boost::asio::ip::udp::endpoint&   sourceEP,
                const boost::asio::ip::udp::endpoint&   destinationEP,
                const std::shared_ptr<Byte>&            owner,
                Byte*                                   packet,
                int                                     packet_length,
                YieldContext&                           y) noexcept {

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool fin = false;
                if (NULLPTR == packet && packet_length != 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }
                elif(NULLPTR == packet || packet_length < 1) {
                    fin = true;
                }

                FirewallPtr firewall = firewall_;
                int destinationPort = destinationEP.port();

                if (NULLPTR != firewall) {
                    if (firewall->IsDropNetworkPort(destinationPort, false)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
                    if (firewall->IsDropNetworkSegment(destinationIP)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                        return false;
                    }
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (destinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::telemetry::Log(Level::kDebug, "exchanger", "dns packet received length=%d", packet_length);
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(packet, packet_length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        ppp::telemetry::Log(Level::kDebug, "exchanger", "dns query host=%s type=%u class=%u length=%d", hostDomain.c_str(), static_cast<unsigned int>(queries_type), static_cast<unsigned int>(queries_clazz), packet_length);
                        if (NULLPTR != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        if (NULL != firewall) {
                            if (firewall->IsDropNetworkDomains(hostDomain)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                                return false;
                            }
                        }
                    }
                    else {
                        ppp::diagnostics::ErrorCode dns_error = ppp::diagnostics::GetLastErrorCode();
                        ppp::telemetry::Log(Level::kDebug, "exchanger", "dns query host empty error=%d length=%d", static_cast<int>(dns_error), packet_length);
                    }

                    int status = NamespaceQueryReply(sourceEP, destinationEP, hostDomain,
                        packet, packet_length, queries_type, queries_clazz, false);
                    if (status < 0) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, owner, packet, packet_length, false);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                return datagram_manager_->SendToDestination(transmission, sourceEP, destinationEP, packet, packet_length, fin);
            }

            /**
             * @brief Sends DNS query to redirect endpoint and relays async response.
             */
            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                ITransmissionPtr                                    transmission,
                boost::asio::ip::udp::endpoint                      redirectEP,
                boost::asio::ip::udp::endpoint                      sourceEP,
                boost::asio::ip::udp::endpoint                      destinationEP,
                std::shared_ptr<Byte>                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    return false;
                }

                const auto context = transmission->GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    return false;
                }

                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                boost::system::error_code ec;
                socket->open(destinationEP.protocol(), ec);
                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                int handle = socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, destinationEP.protocol() == boost::asio::ip::udp::v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

socket->send_to(boost::asio::buffer(packet.get(), packet_length), redirectEP,
                    boost::asio::socket_base::message_end_of_record, ec);
                if (ec) {
                    Socket::Closesocket(socket);  // Clean up socket on send failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    return false;
                }

                /** @brief Timer callback closes socket if redirect query times out. */
                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [socket_weak](Timer*) noexcept {
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            Socket::Closesocket(socket);
                        }
                    });
                if (NULLPTR == cb) {
                    Socket::Closesocket(socket);  // Clean up socket on callback alloc failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                std::shared_ptr<ppp::threading::Timer> timeout;  // Non-const to allow disposal
                {
                    std::shared_ptr<ppp::threading::Timer> created_timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                    timeout = created_timeout;
                }
                if (NULLPTR == timeout) {
                    Socket::Closesocket(socket);  // Clean up socket on timeout alloc failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    return false;
                }

                if (!timeouts_.emplace(socket.get(), cb).second) {
                    timeout->Dispose();  // Clean up timeout on insert failure
                    Socket::Closesocket(socket);  // Clean up socket on timeout entry conflict
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetExchangerTimeoutEntryConflict);
                    return false;
                }

                const auto max_buffer_size = PPP_BUFFER_SIZE;
                const auto self = shared_from_this();

                // BUG-16: buffer_ is a shared scratch buffer owned by this exchanger.
                // Multiple concurrent INTERNAL_RedirectDnsQuery calls are possible when
                // the client sends several DNS queries in quick succession before any
                // reply arrives.  Each outstanding async_receive_from must have its own
                // dedicated receive buffer; sharing buffer_ across concurrent receives
                // would cause later arriving data to corrupt an earlier in-flight read.
                // Allocate a per-call heap buffer so every outstanding receive is
                // independently owned and there is no aliasing between concurrent calls.
                const std::shared_ptr<ppp::threading::BufferswapAllocator> recv_allocator = transmission->BufferAllocator;
                const std::shared_ptr<Byte> recv_buffer = ppp::threading::BufferswapAllocator::MakeByteArray(recv_allocator, max_buffer_size);
                if (NULLPTR == recv_buffer) {
                    DeleteTimeout(socket.get());  // Clean up timeout entry
                    Socket::Closesocket(socket);  // Clean up socket on buffer alloc failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                const auto responseEP = make_shared_object<boost::asio::ip::udp::endpoint>();
                if (NULLPTR == responseEP) {
                    DeleteTimeout(socket.get());  // Clean up timeout entry
                    Socket::Closesocket(socket);  // Clean up socket on endpoint alloc failure
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                /** @brief Receives redirect DNS response and forwards to static/dynamic path. */
                socket->async_receive_from(boost::asio::buffer(recv_buffer.get(), max_buffer_size),
                    *responseEP,
                    [self, this, socket, sourceEP, timeout, static_transit, transmission, destinationEP, responseEP, recv_buffer](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred > 0) {
                                if (static_transit) {
                                    VirtualEthernetDatagramPortStatic::Output(switcher_.get(), this, recv_buffer.get(), bytes_transferred, sourceEP, destinationEP);
                                }
                                elif(!DoSendTo(transmission, sourceEP, destinationEP, recv_buffer.get(), bytes_transferred, nullof<YieldContext>())) {
                                    transmission->Dispose();
                                }

                                AppConfigurationPtr configuration = GetConfiguration();
                                if (NULLPTR != configuration && configuration->udp.dns.cache) {
                                    NamespaceQueryCache(switcher_, recv_buffer.get(), bytes_transferred);
                                }
                            }
                        }

                        Socket::Closesocket(socket);
                        if (timeout) {
                            timeout->Stop();
                            timeout->Dispose();
                        }
                    });
                return true;
            }

            /**
             * @brief Resolves configured DNS redirect host and dispatches redirect send.
             */
            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                const ITransmissionPtr&                             transmission,
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const std::shared_ptr<Byte>&                        owner,
                Byte*                                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (!packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                if (!transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                // Zero-copy slice when owner is available; otherwise fall back to alloc+memcpy.
                std::shared_ptr<Byte> buffer = ppp::wrap_shared_pointer(packet, owner);
                if (!buffer) {
                    const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                    buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_length);
                    if (NULLPTR == buffer) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }
                    memcpy(buffer.get(), packet, packet_length);
                }

                const boost::asio::ip::udp::endpoint destination = destinationEP;
                const boost::asio::ip::udp::endpoint source = sourceEP;
                const ITransmissionPtr in = transmission;

                const auto configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    return false;
                }

                const auto self = shared_from_this();
                const std::shared_ptr<boost::asio::io_context> context = in->GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    return false;
                }

                const Ipep::GetAddressByHostNameCallback cb =
                    [self, this, buffer, packet_length, static_transit, source, in, destination, context](const std::shared_ptr<IPEndPoint>& redirectEP) noexcept {
                        if (!redirectEP) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                            return false;
                        }

                        boost::asio::ip::udp::endpoint redirect = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(*redirectEP);
                        boost::asio::post(*context,
                            [self, this, buffer, packet_length, static_transit, source, in, destination, redirect]() noexcept {
                                return INTERNAL_RedirectDnsQuery(in, redirect, source, destination, buffer, packet_length, static_transit);
                            });
                        return true;
                    };

                if (!Ipep::GetAddressByHostName(*context, configuration->udp.dns.redirect, PPP_DNS_SYS_PORT, cb)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                    return false;
                }

                return true;
            }

            /**
             * @brief Applies DNS redirect policy for one outgoing DNS query packet.
             */
            int VirtualEthernetExchanger::RedirectDnsQuery(
                const ITransmissionPtr&                             transmission,
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const std::shared_ptr<Byte>&                        owner,
                Byte*                                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
                if (configuration->udp.dns.redirect.empty()) {
                    return -1;
                }

                if (disposed_) {
                    return 0;
                }

                boost::asio::ip::udp::endpoint redirect_server = switcher_->GetDnsserverEndPoint();
                boost::asio::ip::address dnsserverIP = redirect_server.address();
                if (dnsserverIP.is_unspecified()) {
                    return INTERNAL_RedirectDnsQuery(transmission, sourceEP, destinationEP, owner, packet, packet_length, static_transit);
                }

                boost::asio::ip::udp::endpoint dnsserverEP(dnsserverIP, PPP_DNS_SYS_PORT);
                return INTERNAL_RedirectDnsQuery(transmission,
                    dnsserverEP,
                    sourceEP,
                    destinationEP,
                    ppp::wrap_shared_pointer(packet, owner), packet_length, static_transit);
            }

            /** @brief Schedules periodic maintenance for all exchanger-owned runtime objects. */
            bool VirtualEthernetExchanger::Update(UInt64 now) noexcept {
                if (disposed_ || IsRecoveryExpired(now)) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, now]() noexcept {
                        {
                            std::lock_guard<std::mutex> lock(carrier_mutex_);
                            if (pending_fresh_deadline_ != 0 &&
                                now >= pending_fresh_deadline_) {
                                pending_fresh_root_.Clear();
                                OPENSSL_cleanse(pending_fresh_server_nonce_.data(),
                                    pending_fresh_server_nonce_.size());
                                pending_fresh_transmission_.reset();
                                pending_fresh_deadline_ = 0;
                            }
                        }

                        int session_id = static_echo_session_id_.load();
                        if (session_id != 0) {
                            static_datagram_manager_->Tick(now);
                        }

                        datagram_manager_->Tick(now);
                        if (IsSuspended(now)) {
                            return;
                        }

                        UploadTrafficToManagedServer();
                        DoMuxEvents();
                        ITransmissionPtr transmission = GetTransmission();
                        if (NULLPTR != transmission && !DoKeepAlived(transmission, now)) {
                            bool current = false;
                            {
                                std::lock_guard<std::mutex> lock(carrier_mutex_);
                                current = transmission_ == transmission;
                            }
                            if (current) {
                                transmission->Dispose();
                            }
                        }
                        Dictionary::UpdateAllObjects2(mappings_, now);
                    });
                return true;
            }

            /** @brief Polls VMUX and tears it down when update fails. */
            bool VirtualEthernetExchanger::DoMuxEvents() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                if (NULLPTR != mux) {
                    if (mux->update()) {
                        return true;
                    }

                    mux_coordinator_->ResetIfCurrent(mux);
                    mux->close_exec();
                }

                return false;
            }

            /** @brief Uploads traffic delta counters to managed server when link is available. */
            bool VirtualEthernetExchanger::UploadTrafficToManagedServer() noexcept {
                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULLPTR == server) {
                    return false;
                }

                bool link_is_available = server->LinkIsAvailable();
                if (!link_is_available) {
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                ITransmissionStatisticsPtr statistics = transmission->Statistics;
                if (NULLPTR == statistics) {
                    return false;
                }

                statistics = statistics->Clone();
                if (NULLPTR == statistics) {
                    return false;
                }

                int64_t rx = 0;
                int64_t tx = 0;

                ITransmissionStatisticsPtr statistics_last = statistics_last_;
                if (NULLPTR != statistics_last) {
                    rx = statistics->IncomingTraffic - statistics_last->IncomingTraffic;
                    tx = statistics->OutgoingTraffic - statistics_last->OutgoingTraffic;
                }
                else {
                    rx = statistics->IncomingTraffic;
                    tx = statistics->OutgoingTraffic;
                }

                statistics_last_ = statistics;
                server->UploadTrafficToManagedServer(GetId(), rx, tx);
                return true;
            }

            /** @brief Creates ICMP and static-ICMP helper components for this exchanger. */
            bool VirtualEthernetExchanger::Open() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo = NewEchoTransmissions(transmission);
                if (NULLPTR == echo) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = make_shared_object<VirtualInternetControlMessageProtocolStatic>(exchanger, configuration, context);
                if (NULLPTR == static_echo) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                echo_ = std::move(echo);
                static_echo_ = std::move(static_echo);
                return true;
            }

            /** @brief Constructs echo forwarding helper bound to current session. */
            VirtualEthernetExchanger::VirtualInternetControlMessageProtocolPtr VirtualEthernetExchanger::NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualInternetControlMessageProtocol>(exchanger, transmission);
            }

            /** @brief Constructs UDP datagram port proxy for one source endpoint. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualEthernetDatagramPort>(self, BuildServerUdpRelayHostPorts(), transmission, sourceEP);
            }

            /** @brief Finds a cached datagram port by source endpoint key. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->GetDatagramPort(sourceEP);
            }

            /** @brief Removes and returns cached datagram port by source endpoint key. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->ReleaseDatagramPort(sourceEP);
            }

            /** @brief Parses and forwards ICMP packet to echo subsystem after firewall checks. */
            bool VirtualEthernetExchanger::SendEchoToDestination(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo;
                {
                    std::lock_guard<std::mutex> lock(carrier_mutex_);
                    if (transmission_ != transmission) {
                        return false;
                    }
                    echo = echo_;
                }
                if (NULLPTR == echo) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = echo->BufferAllocator;
                std::shared_ptr<IPFrame> ip = IPFrame::Parse(allocator, owner, packet, packet_length);
                if (NULLPTR == ip) {
                    return false;
                }

                if (ip->ProtocolType != ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                FirewallPtr firewall = firewall_;
                if (NULLPTR != firewall) {
                    boost::asio::ip::address destinationIP = Ipep::ToAddress(ip->Destination);
                    if (firewall->IsDropNetworkSegment(destinationIP)) {
                        return false;
                    }
                }

                std::shared_ptr<IcmpFrame> icmp = IcmpFrame::Parse(ip.get());
                if (NULLPTR == icmp) {
                    return false;
                }

                return echo->Echo(ip, icmp, IPEndPoint(icmp->Destination, IPEndPoint::MinPort));
            }

            /** @brief Forwards IPv4 NAT packet to matching peer exchangers in same subnet. */
            bool VirtualEthernetExchanger::ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept {
                using VES = VirtualEthernetSwitcher;

                if (disposed_) {
                    return false;
                }

                ppp::net::native::ip_hdr* ip = ppp::net::native::ip_hdr::Parse(packet, packet_length);
                if (NULLPTR == ip) {
                    return false;
                }

                app::protocol::IcmpPathMtuError control_error;
                const bool is_control_error = app::protocol::TryParseIcmpPathMtuError(
                    packet, packet_length, control_error);
                if (ip->proto == ppp::net::native::ip_hdr::IP_PROTO_ICMP && !is_control_error) {
                    return false;
                }

                VES::NatInformationPtr source = switcher_->FindNatInformation(ip->src);
                if (is_control_error) {
                    // This packet entered through a client session, so both RFC 792
                    // address relationships must hold: the client originated the
                    // error for the quoted destination and the outer destination owns
                    // the quoted source. This prevents a client from forging a PMTU
                    // update for an unrelated peer flow.
                    const bool related_to_outer_packet =
                        control_error.QuotedDestination == control_error.OuterSource &&
                        control_error.QuotedSource == control_error.OuterDestination;
                    if (!related_to_outer_packet) {
                        ppp::telemetry::Count("pmtu.error_rejected", 1);
                        return false;
                    }
                }
                if (NULLPTR == source) {
                    return false;
                }

                /** @brief Delivers a packet to the exchanger that owns destination address. */
                static const auto forward =
                    [](VirtualEthernetSwitcher* switcher, uint32_t source, uint32_t destination, Byte* packet, int packet_length, YieldContext& y) noexcept -> int {
                        bool via_gateway = false;
                        VES::NatInformationPtr nat = switcher->FindNatInformation(destination);
                        if (NULLPTR == nat && switcher->IsPeerRoutingEnabled()) {
                            uint32_t via = switcher->FindGatewayVirtualIPForDestination(destination);
                            if (via != 0) {
                                nat = switcher->FindNatInformation(via);
                                via_gateway = (NULLPTR != nat);
                            }
                        }
                        if (NULLPTR == nat) {
                            return 0;
                        }

                        if (!via_gateway) {
                            uint32_t mask = nat->SubmaskAddress;
                            if ((destination & mask) != (nat->IPAddress & mask)) {
                                return 0;
                            }
                        }

                        std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;

                        ITransmissionPtr transmission = exchanger->GetTransmission();
                        if (NULLPTR != transmission) {
                            // Keep the static tunnel-safe clamp as a fallback. Learned PMTU is
                            // applied by the destination client before its next outbound SYN.
                            app::protocol::ClampTcpMssIPv4(packet, packet_length,
                                app::protocol::ComputeDynamicTcpMss(true, app::protocol::kVEthernetTunnelOverhead));

                            // Fix #2: NAT relay MUST execute first. P2P offer is best-effort and
                            // must never block or affect the relay forward status.
                            if (exchanger->DoNat(transmission, packet, packet_length, y)) {
                                VirtualEthernetLoggerPtr logger = switcher->GetLogger();
                                if (NULLPTR != logger) {
                                    logger->Packet(exchanger->GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToClient);
                                }

                                // Best-effort P2P hint — failure does not affect relay.
                                switcher->OfferP2PPeerHints(source, destination, y);
                                return 1;
                            }

                            transmission->Dispose();
                        }

                        return -1;
                    };

                if (uint32_t destination = ip->dest; destination != IPEndPoint::BroadcastAddress) {
                    int status = forward(switcher_.get(), source->IPAddress, destination, packet, packet_length, y);
                    // NOTE: NAT classification observations must come from actual UDP
                    // relay traffic (e.g., static-echo or UDP sendto paths), NOT from
                    // TCP control channel endpoints.  TCP endpoints reflect TCP NAT
                    // behavior and do not predict UDP NAT mapping patterns (#14).
                    // Observations should be recorded in the UDP datagram port paths
                    // when UDP relay traffic is processed.
                    return status > 0;
                }
                else {
                    // BUG-19: The original loop iterated every host address in the subnet,
                    // which is up to 16 million iterations for a /8 — blocking the IO thread
                    // for an unbounded time.  Cap the broadcast walk at 256 host addresses to
                    // bound worst-case latency while still covering practical subnet sizes
                    // (/24 and smaller, which are the common deployment configurations).
                    // Subnets larger than /24 will only have their first 256 hosts forwarded;
                    // this is an intentional safety limit, not a correctness regression, because
                    // iterating millions of addresses synchronously would stall every other
                    // session on the same IO thread.
                    static constexpr uint32_t kMaxBroadcastHosts = 256;

                    bool any = false;
                    uint32_t current = htonl(ip->src);
                    uint32_t mask = ntohl(source->SubmaskAddress);
                    uint32_t first = current & mask;
                    uint32_t boardcast = first | (~mask); // first | (~first & 0xff);
                    uint32_t walked = 0;

                    for (uint32_t address = first; address < boardcast && walked < kMaxBroadcastHosts; address++) {
                        if (current == address) {
                            continue;
                        }

                        walked++;
                        int status = forward(switcher_.get(), ip->src, htonl(address), packet, packet_length, y);
                        if (status < 0) {
                            break;
                        }

                        any |= status > 0;
                    }

                    return any;
                }
            }

            /** @brief Handles FRP mapping entry registration notification. */
            bool VirtualEthernetExchanger::OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.mapping) {
                    RegisterMappingPort(in, tcp, remote_port);
                }

                return true;
            }

            /** @brief Forwards FRP UDP payload to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpSendTo(packet, packet_length, sourceEP);
                }

                return true;
            }

            /** @brief Forwards FRP connect result to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpConnectOK(connection_id, error_code);
                }

                return true;
            }

            /** @brief Forwards FRP disconnect event to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            /** @brief Forwards FRP TCP stream payload to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpPush(connection_id, owner, packet, packet_length);
                }

                return true;
            }

            /** @brief Creates, opens and registers FRP mapping port if absent. */
            bool VirtualEthernetExchanger::RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept {
                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, tcp, remote_port);
                if (NULLPTR != mapping_port) {
                    return false;
                }

                mapping_port = NewMappingPort(in, tcp, remote_port);
                if (NULLPTR == mapping_port) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                bool ok = mapping_port->OpenFrpServer(logger);
                if (ok) {
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, tcp, remote_port, mapping_port);
                }

                if (ok) {
                    if (NULLPTR != logger) {
                        logger->MPEntry(GetId(), transmission, mapping_port->BoundEndPointOfFrpServer(), tcp);
                    }

                    ppp::telemetry::Log(Level::kDebug, "exchanger", "mapping added remote_port=%d", remote_port);
                    ppp::telemetry::Count("exchanger.mapping.add", 1);
                }
                else {
                    mapping_port->Dispose();
                }
                return ok;
            }

            /** @brief Builds FRP mapping port object with disposal hook. */
            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class MappingPort : public VirtualEthernetMappingPort {
                public:
                    MappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    /** @brief Unregisters mapping key asynchronously, then disposes base resources. */
                    virtual void Dispose() noexcept override {
                        // Remove the mapping entry after leaving the current call stack so
                        // disposal cannot re-enter the exchanger while its lock is held.
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer(); NULLPTR != linklayer) {
                            if (std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(linklayer); NULLPTR != exchanger) {
                                auto self = shared_from_this();
                                std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                                auto remove_mapping = [exchanger, self]() noexcept {
                                    SynchronizedObjectScope scope(exchanger->syncobj_);
                                    VirtualEthernetMappingPort::DeleteMappingPort(
                                        exchanger->mappings_, self->ProtocolIsNetworkV4(), self->ProtocolIsTcpNetwork(), self->GetRemotePort());
                                    ppp::telemetry::Log(Level::kDebug, "exchanger", "mapping removed remote_port=%d", self->GetRemotePort());
                                    ppp::telemetry::Count("exchanger.mapping.remove", 1);
                                };

                                if (NULLPTR != context) {
                                    boost::asio::post(*context, std::move(remove_mapping));
                                }
                                else {
                                    remove_mapping();
                                }
                            }
                        }

                        VirtualEthernetMappingPort::Dispose();
                    }
                };

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto self = shared_from_this();
                return make_shared_object<MappingPort>(self, transmission, tcp, in, remote_port);
            }

            /** @brief Finds FRP mapping port by direction/protocol/remote-port key. */
            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            /** @brief Runs keepalive without finalizing recoverable session state. */
            bool VirtualEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_) {
                    return false;
                }

                return VirtualEthernetLinklayer::DoKeepAlived(transmission, now);
            }

            /** @brief Handles static-echo ICMP packet and relays via static echo engine. */
            bool VirtualEthernetExchanger::StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULLPTR == packet) {
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                std::shared_ptr<ppp::net::packet::IPFrame> ip = packet->GetIPPacket(allocator);
                if (NULLPTR == ip) {
                    return false;
                }
                elif(ip->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }
                elif(ip->Source == IPEndPoint::LoopbackAddress) {
                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                    if (NULLPTR == echo) {
                        return false;
                    }

                    ppp::app::protocol::VirtualEthernetPacket::FillBytesToPayload(ip.get());
                    return echo->Output(ip.get(), IPEndPoint::ToEndPoint(sourceEP));
                }

                std::shared_ptr<ppp::net::packet::IcmpFrame> frame = ppp::net::packet::IcmpFrame::Parse(ip.get());
                if (NULLPTR == ip || NULLPTR == frame) {
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                if (NULLPTR == echo) {
                    return false;
                }

                return echo->Echo(ip, frame, IPEndPoint::ToEndPoint(sourceEP));
            }

            /** @brief Releases static-echo datagram port by source address and port. */
            bool VirtualEthernetExchanger::StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept {
                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }

                uint64_t key = MAKE_QWORD(source_ip, source_port);
                if (!key) {
                    return false;
                }

                return NULLPTR != static_datagram_manager_->ReleaseDatagramPort(key);
            }

            /** @brief Forwards static-echo UDP packet to destination through cached/static port. */
            bool VirtualEthernetExchanger::StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULLPTR == packet) {
                    return false;
                }

                std::shared_ptr<Byte> messages = packet->Payload;
                if (NULLPTR == messages) {
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetDatagramPortStatic> datagram_port;
                int source_port = packet->SourcePort;
                uint32_t source_ip = packet->SourceIP;

                boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->DestinationIP);
                boost::asio::ip::udp::endpoint destinationEP = boost::asio::ip::udp::endpoint(destinationIP, packet->DestinationPort);

                if (source_ip == IPEndPoint::AnyAddress || source_ip == IPEndPoint::NoneAddress) {
                    return false;
                }
                elif(source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationPort <= IPEndPoint::MinPort || packet->DestinationPort > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationIP == IPEndPoint::AnyAddress || packet->DestinationIP == IPEndPoint::NoneAddress) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (packet->DestinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(messages.get(), packet->Length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        if (NULLPTR != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        FirewallPtr firewall = firewall_;
                        if (NULL != firewall && firewall->IsDropNetworkDomains(hostDomain)) {
                            return false;
                        }
                    }

                    boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(IPEndPoint(source_ip, source_port));

                    int status = NamespaceQueryReply(sourceEP, destinationEP, hostDomain,
                        messages.get(), packet->Length, queries_type, queries_clazz, true);
                    if (status < 0) {
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, messages, messages.get(), packet->Length, true);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                uint64_t key = MAKE_QWORD(source_ip, source_port);
                datagram_port = static_datagram_manager_->GetOrAddDatagramPort(key, source_ip, source_port);

                if (NULLPTR == datagram_port) {
                    return false;
                }

                return datagram_port->SendTo(messages.get(), packet->Length, destinationEP);
            }
        }
    }
}
