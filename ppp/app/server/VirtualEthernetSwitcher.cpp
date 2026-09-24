#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/IPv6TransitPolicy.h>
#include <ppp/app/server/PeerRouteAnnouncePolicy.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/IDisposable.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/cryptography/digest.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/proxies/sniproxy.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/io/File.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/protocol/TransportAuthNegotiation.h>
#include <ppp/app/server/SessionResumeEstablishTransaction.h>
#include <ppp/app/server/SessionResumeFallbackDecision.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h> /* SpanScope RAII */
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/p2p/P2PDefs.h>
#include <ppp/p2p/P2PRelayOfferCoordinator.h>
#include <ppp/app/P2PCandidateAdapter.h>

#include <chrono>

#if defined(_LINUX)
#include <common/unix/UnixAfx.h>
#include <linux/ppp/tap/TapLinux.h>
#endif

#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

/**
 * @file VirtualEthernetSwitcher.cpp
 * @brief Implements virtual ethernet switching, session lifecycle, and IPv6 dataplane plumbing.
 */

using ppp::app::protocol::VirtualEthernetPacket;
using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::threading::Executors;
using ppp::coroutines::YieldContext;
using ppp::collections::Dictionary;
using ppp::telemetry::Level;

static bool BuildSessionResumeId(const ppp::Int128& id,
    ppp::app::protocol::SessionResumeId& output) noexcept {
    ppp::string guid = ppp::auxiliary::StringAuxiliary::Int128ToGuidString(id);
    ppp::string canonical;
    canonical.reserve(ppp::app::protocol::SessionResumeIdSize * 2);
    for (char value : guid) {
        if (value != '-') {
            canonical.push_back(value);
        }
    }
    if (canonical.size() != output.size() * 2) {
        output.fill(0);
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

    for (std::size_t i = 0; i < output.size(); ++i) {
        std::uint8_t high = 0;
        std::uint8_t low = 0;
        if (!nibble(canonical[i * 2], high) || !nibble(canonical[i * 2 + 1], low)) {
            output.fill(0);
            return false;
        }
        output[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

static bool IsEligibleAuthenticatedRecoveryCarrier(
    const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept {
    if (!transmission || transmission->IsServerLoopbackIngress() ||
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

static bool DeriveSessionResumeCandidateBinding(
    const std::shared_ptr<ppp::transmissions::ITransmission>& transmission,
    const ppp::Int128& session_id,
    ppp::app::protocol::SessionResumeCandidateBinding& candidate) noexcept {
    if (!IsEligibleAuthenticatedRecoveryCarrier(transmission)) {
        candidate.fill(0);
        return false;
    }

    ppp::app::protocol::SessionResumeId binary_session_id{};
    if (!BuildSessionResumeId(session_id, binary_session_id)) {
        candidate.fill(0);
        return false;
    }

    ppp::app::protocol::SessionResumeExporter exporter =
        [transmission](const char* label, const std::uint8_t* context,
            std::size_t context_length, std::uint8_t* output,
            std::size_t output_length) noexcept {
                return transmission->ExportAuthenticatedSessionKey(
                    label, context, context_length, output, output_length);
            };
    return ppp::app::protocol::DeriveSessionResumeCandidateBinding(
        exporter, binary_session_id, candidate);
}

/**
 * @brief Tests whether an IPv6 address is in the global unicast range.
 * @param address IPv6 address to evaluate.
 * @return true for 2000::/3 addresses; otherwise false.
 */
static bool IsGlobalUnicastIPv6Address(const boost::asio::ip::address_v6& address) noexcept {
    boost::asio::ip::address_v6::bytes_type bytes = address.to_bytes();
    return (bytes[0] & 0xe0) == 0x20;
}

/**
 * @brief Derives the first host address from an IPv6 network/prefix.
 * @param network Network base address.
 * @param prefix_length Prefix length used to compute the network.
 * @param host Receives the derived first host address.
 * @return true if a host address can be generated; otherwise false.
 */
static bool TryGetFirstHostIPv6(const boost::asio::ip::address_v6& network, int prefix_length, boost::asio::ip::address_v6& host) noexcept {
    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
    if (prefix_length >= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
        return false;
    }

    boost::asio::ip::address_v6::bytes_type bytes = ppp::ipv6::ComputeNetworkAddress(network, prefix_length).to_bytes();
    for (int i = 15; i >= 0; --i) {
        if (bytes[i] != 0xff) {
            ++bytes[i];
            for (int j = i + 1; j < 16; ++j) {
                bytes[j] = 0;
            }
            host = boost::asio::ip::address_v6(bytes);
            return true;
        }
    }
    return false;
}

/**
 * @brief Validates whether an IPv6 address can be leased to a client.
 * @param address Candidate client address.
 * @param prefix_length Prefix length used for network/broadcast checks.
 * @param gateway Optional gateway address to exclude.
 * @return true if the candidate is assignable; otherwise false.
 */
static bool IsAssignableClientIPv6Address(const boost::asio::ip::address_v6& address, int prefix_length, const boost::asio::ip::address_v6* gateway = NULLPTR) noexcept {
    // Reject well-known non-routable or reserved address categories.
    // Link-local (fe80::/10) must be excluded: they are interface-scoped and
    // cannot be used as globally routable client addresses across the VPN.
    if (address.is_unspecified() || address.is_multicast() || address.is_loopback() || address.is_link_local()) {
        return false;
    }

    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
    if (prefix_length < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH && address == ppp::ipv6::ComputeNetworkAddress(address, prefix_length)) {
        return false;
    }

    if (NULLPTR != gateway && !gateway->is_unspecified() && address == *gateway) {
        return false;
    }

    return true;
}

/**
 * @brief Reads and normalizes configured IPv6 CIDR information.
 * @param configuration Application configuration source.
 * @param network Receives normalized network address.
 * @param prefix_length Receives clamped prefix length.
 * @return true when configuration resolves to a valid IPv6 network; otherwise false.
 */
static bool GetConfiguredIPv6Network(const ppp::configurations::AppConfiguration& configuration, boost::asio::ip::address_v6& network, int& prefix_length) noexcept {
    const auto& ipv6 = configuration.server.ipv6;
    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, ipv6.prefix_length));
    if (prefix_length <= ppp::ipv6::IPv6_MIN_PREFIX_LENGTH || prefix_length > ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
        return false;
    }

    ppp::string prefix_string = ipv6.cidr;
    std::size_t slash = prefix_string.find('/');
    if (slash != ppp::string::npos) {
        prefix_string = prefix_string.substr(0, slash);
    }

    boost::system::error_code ec;
    boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
    if (ec || !prefix.is_v6()) {
        return false;
    }

    network = ppp::ipv6::ComputeNetworkAddress(prefix.to_v6(), prefix_length);
    return true;
}

#if defined(_LINUX)
/**
 * @brief Chooses the uplink interface used for IPv6 neighbor proxy.
 * @param preferred_nic Configured preferred interface name.
 * @return Preferred interface, or detected default-route interface, or empty string.
 */
static ppp::string ResolvePreferredIPv6UplinkInterface(const ppp::string& preferred_nic) noexcept {
    if (!preferred_nic.empty()) {
        return preferred_nic;
    }

    auto lines = ppp::unix__::UnixAfx::ExecuteShellCommandLines("ip -6 route show default");
    for (const ppp::string& route : lines) {
        std::size_t pos = route.find(" dev ");
        if (pos == ppp::string::npos) {
            continue;
        }

        pos += 5;
        std::size_t end = route.find(' ', pos);
        ppp::string ifname = end == ppp::string::npos ? route.substr(pos) : route.substr(pos, end - pos);
        if (!ifname.empty()) {
            return ifname;
        }
    }

    return ppp::string();
}

/**
 * @brief Checks if the host currently has an IPv6 default route.
 * @return true when a default IPv6 route is present; otherwise false.
 */
static bool HasIPv6DefaultRoute() noexcept {
    auto lines = ppp::unix__::UnixAfx::ExecuteShellCommandLines("ip -6 route show default");
    for (const ppp::string& route : lines) {
        if (route.empty()) {
            continue;
        }

        if (route.find("default") == 0) {
            return true;
        }
    }

    return false;
}
#endif

namespace ppp {
    namespace transmissions {
        typedef ITransmission::AppConfigurationPtr      AppConfigurationPtr;

        bool                                            Transmission_Handshake_Nop(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept;
    }

    namespace app {
        namespace server {
#if defined(_LINUX)
            static bool AddIPv6TransitRouteOnTap(
                const std::shared_ptr<ppp::tap::ITap>& tap,
                const boost::asio::ip::address& ip,
                int prefix_length) noexcept {
                if (NULLPTR == tap || !ip.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteAddFailed);
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH,
                    std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                auto started_at = std::chrono::steady_clock::now();
                bool ok = ppp::tap::TapLinux::AddRoute6(tap->GetId(), ip_str, prefix_length, ppp::string());
                if (ok) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - started_at).count();
                    ppp::telemetry::Count("server.route.added", 1);
                    ppp::telemetry::Histogram("server.route.add.us", elapsed);
                    ppp::telemetry::Log(Level::kDebug, "server", "route added");
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteAddFailed);
                }
                return ok;
            }

            static bool DeleteIPv6TransitRouteOnTap(
                const std::shared_ptr<ppp::tap::ITap>& tap,
                const boost::asio::ip::address& ip,
                int prefix_length) noexcept {
                if (NULLPTR == tap || !ip.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteDeleteFailed);
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH,
                    std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                auto started_at = std::chrono::steady_clock::now();
                bool ok = ppp::tap::TapLinux::DeleteRoute6(tap->GetId(), ip_str, prefix_length, ppp::string());
                if (ok) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - started_at).count();
                    ppp::telemetry::Count("server.route.deleted", 1);
                    ppp::telemetry::Histogram("server.route.delete.us", elapsed);
                    ppp::telemetry::Log(Level::kDebug, "server", "route deleted");
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteDeleteFailed);
                }
                return ok;
            }
#endif

            /**
             * @brief Constructs the virtual ethernet switch core.
             * @param configuration Shared server/application configuration.
             * @param tun_name Optional TUN interface name.
             * @param tun_ssmt Number of SSMT worker contexts for transit TAP.
             * @param tun_ssmt_mq Enables multiqueue SSMT mode when true.
             */
            VirtualEthernetSwitcher::VirtualEthernetSwitcher(const AppConfigurationPtr& configuration, const ppp::string& tun_name, int tun_ssmt, bool tun_ssmt_mq) noexcept
                : disposed_(false)
                , configuration_(configuration)
                , context_(Executors::GetDefault())
                , tun_name_(tun_name)
                , tun_ssmt_(std::max<int>(0, tun_ssmt))
                , tun_ssmt_mq_(tun_ssmt_mq)
                , static_echo_socket_(*context_)
                , static_echo_bind_port_(IPEndPoint::MinPort) {

                boost::asio::ip::udp::endpoint dnsserverEP = ParseDNSEndPoint(configuration_->udp.dns.redirect);
                dnsserverEP_ = dnsserverEP;

                interfaceIP_ = Ipep::ToAddress(configuration_->ip.interface_, true);
                statistics_ = make_shared_object<ppp::transmissions::ITransmissionStatistics>();

                static_echo_buffers_ = ppp::threading::Executors::GetCachedBuffer(context_);
            }

            /** @brief Releases all switch-owned resources and active sessions. */
            VirtualEthernetSwitcher::~VirtualEthernetSwitcher() noexcept {
                Finalize();
            }

            int VirtualEthernetSwitcher::GetNode() noexcept {
                return configuration_->server.node;
            }

            /**
             * @brief Builds information payload plus IPv6 extension fields.
             * @param session_id Session identifier.
             * @param info Base information payload.
             * @return Envelope containing base info and extension JSON.
             */
            VirtualEthernetSwitcher::InformationEnvelope VirtualEthernetSwitcher::BuildInformationEnvelope(const Int128& session_id, const VirtualEthernetInformation& info) noexcept {
                InformationEnvelope envelope;
                envelope.Base = info;
                BuildInformationIPv6Extensions(session_id, envelope.Extensions);

                // Auto-assign IPv4 from the lease pool when configured.
                // This mirrors the IPv6 auto-assignment above: the pool
                // hands out an address for every session that reaches
                // this point (initial handshake or managed-server info).
                if (configuration_->server.ipv4_pool.configured) {
                    IPv4LeasePool::Result r = ipv4_pool_.AcquireAuto(session_id);
                    if (r.ok) {
                        envelope.Extensions.ClientIPv4Assign.enabled  = true;
                        envelope.Extensions.ClientIPv4Assign.accepted = r.accepted;
                        envelope.Extensions.ClientIPv4Assign.conflict = r.conflict;
                        envelope.Extensions.ClientIPv4Assign.mode     = "auto";
                        if (!r.reason.empty()) {
                            envelope.Extensions.ClientIPv4Assign.reason = r.reason;
                        }

                        std::string addr_str = r.address.to_string();
                        envelope.Extensions.ClientIPv4Assign.address = ppp::string(addr_str.data(), addr_str.size());

                        std::string gw_str = r.gateway.to_string();
                        envelope.Extensions.ClientIPv4Assign.gateway = ppp::string(gw_str.data(), gw_str.size());

                        std::string mask_str = r.mask.to_string();
                        envelope.Extensions.ClientIPv4Assign.mask = ppp::string(mask_str.data(), mask_str.size());
                    }
                }

                if (IsPeerRoutingEnabled()) {
                    BuildPeerRouteTableSnapshot(envelope.Extensions.PeerRouteTable, &session_id);
                }

                envelope.ExtendedJson = envelope.Extensions.ToJson();
                return envelope;
            }

            /**
             * @brief Reports whether the current platform supports IPv6 dataplane integration.
             * @return true on supported platforms; otherwise false.
             */
            bool VirtualEthernetSwitcher::SupportsIPv6DataPlane() noexcept {
#if defined(_LINUX)
                return true;
#else
                return false;
#endif
            }

            /**
             * @brief Checks whether IPv6 server mode is enabled and supported.
             * @return true when IPv6 mode is NAT66 or GUA and dataplane exists.
             */
            bool VirtualEthernetSwitcher::IsIPv6ServerEnabled() noexcept {
                AppConfiguration::IPv6Mode mode = configuration_->server.ipv6.mode;
                return SupportsIPv6DataPlane() && (mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua);
            }

            /**
             * @brief Resolves the IPv6 transit gateway used for client routing.
             * @return Configured or derived gateway address, or empty on failure.
             */
            boost::asio::ip::address VirtualEthernetSwitcher::GetIPv6TransitGateway() noexcept {
                const auto& ipv6 = configuration_->server.ipv6;

#if defined(_LINUX)
                if (ipv6.mode == AppConfiguration::IPv6Mode_Gua && !HasIPv6DefaultRoute()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6GatewayNotReachable);
                    return boost::asio::ip::address();
                }
#endif

                boost::system::error_code ec;
                boost::asio::ip::address configured_gateway = StringToAddress(ipv6.gateway, ec);
                if (!ec && configured_gateway.is_v6()) {
                    return configured_gateway;
                }

                boost::asio::ip::address_v6 network;
                int prefix_length = 0;
                if (!GetConfiguredIPv6Network(*configuration_, network, prefix_length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6GatewayNotReachable);
                    return boost::asio::ip::address();
                }

                boost::asio::ip::address_v6 gateway;
                if (!TryGetFirstHostIPv6(network, prefix_length, gateway)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6GatewayNotReachable);
                    return boost::asio::ip::address();
                }

                return boost::asio::ip::address(gateway);
            }

            /**
             * @brief Computes IPv6 lease/route metadata for a session handshake.
             * @param session_id Session identifier.
             * @param extensions Receives generated IPv6 extension fields.
             * @return true when extensions contain a usable assignment; otherwise false.
             */
            bool VirtualEthernetSwitcher::BuildInformationIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept {
                struct ScopedIPv6AssignHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();
                    VirtualEthernetInformationExtensions& extensions;

                    explicit ScopedIPv6AssignHistogram(VirtualEthernetInformationExtensions& value) noexcept
                        : extensions(value) {}

                    ~ScopedIPv6AssignHistogram() noexcept {
                        if (extensions.AssignedIPv6Address.is_v6()) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                            ppp::telemetry::Histogram("server.ipv6.assign.us", elapsed);
                        }
                    }
                } ipv6_assign_histogram(extensions);

                extensions.Clear();

                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled()) {
                    extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                    extensions.IPv6StatusMessage = "server-ipv6-disabled";
                    return false;
                }

                IPv6RequestEntry request_entry;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto request_it = ipv6_requests_.find(session_id);
                    if (request_it != ipv6_requests_.end()) {
                        request_entry = request_it->second;
                    }
                }

                extensions.RequestedIPv6Address = request_entry.RequestedAddress;
                extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned;
                extensions.IPv6StatusMessage = "server-auto-assigned";

                /**
                 * @brief Validates whether a client-requested IPv6 can be honored.
                 */
                auto is_request_usable = [&](const boost::asio::ip::address_v6& requested, const boost::asio::ip::address_v6& prefix, int prefix_length) noexcept -> bool {
                    return request_entry.RequestedAddress.is_v6() &&
                        requested == request_entry.RequestedAddress.to_v6() &&
                        ppp::ipv6::PrefixMatch(requested, prefix, prefix_length);
                };

                /**
                 * @brief Builds a deterministic per-session IPv6 candidate from session digest.
                 */
                auto build_stable_ipv6 = [&](boost::asio::ip::address_v6::bytes_type bytes, int prefix_length) noexcept -> bool {
                    ppp::string seed = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);

                    ppp::string digest = ppp::cryptography::hash_hmac(seed.data(), static_cast<int>(seed.size()), ppp::cryptography::DigestAlgorithmic_sha256, false, false);
                    if (digest.size() < 8) {
                        return false;
                    }

                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                    boost::asio::ip::address_v6::bytes_type digest_bytes = {};
                    memcpy(digest_bytes.data(), digest.data(), std::min<std::size_t>(digest.size(), digest_bytes.size()));

                    boost::asio::ip::address_v6::bytes_type network_bytes = ppp::ipv6::ComputeNetworkAddress(boost::asio::ip::address_v6(bytes), prefix_length).to_bytes();
                    int full_bytes = prefix_length / 8;
                    int remainder_bits = prefix_length % 8;
                    for (int i = full_bytes; i < 16; ++i) {
                        network_bytes[i] = digest_bytes[i];
                    }

                    if (remainder_bits != 0 && full_bytes < 16) {
                        unsigned char host_mask = static_cast<unsigned char>(0xff >> remainder_bits);
                        network_bytes[full_bytes] = static_cast<unsigned char>((network_bytes[full_bytes] & static_cast<unsigned char>(~host_mask)) | (digest_bytes[full_bytes] & host_mask));
                    }

                    boost::asio::ip::address_v6 candidate = boost::asio::ip::address_v6(network_bytes);

                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    boost::asio::ip::address_v6 gateway_v6;
                    if (transit_gateway.is_v6()) {
                        gateway_v6 = transit_gateway.to_v6();
                    }
                    if (!IsAssignableClientIPv6Address(candidate, prefix_length, transit_gateway.is_v6() ? &gateway_v6 : NULLPTR)) {
                        boost::asio::ip::address_v6::bytes_type candidate_bytes = candidate.to_bytes();
                        candidate_bytes[15] ^= 0x01;
                        candidate = boost::asio::ip::address_v6(candidate_bytes);
                    }

                    if (!IsAssignableClientIPv6Address(candidate, prefix_length, transit_gateway.is_v6() ? &gateway_v6 : NULLPTR)) {
                        return false;
                    }

                    extensions.AssignedIPv6Address = candidate;
                    return true;
                };

                /**
                 * @brief Attempts to reserve and record an IPv6 lease for the session.
                 */
                auto try_commit_ipv6_lease = [&](const boost::asio::ip::address_v6& candidate, bool static_binding, Byte status_code, const ppp::string& status_message) noexcept -> bool {
                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    boost::asio::ip::address_v6 transit_gateway_v6;
                    const boost::asio::ip::address_v6* transit_gateway_ptr = NULLPTR;
                    if (transit_gateway.is_v6()) {
                        transit_gateway_v6 = transit_gateway.to_v6();
                        transit_gateway_ptr = &transit_gateway_v6;
                    }

                    if (!IsAssignableClientIPv6Address(candidate, ipv6.prefix_length, transit_gateway_ptr)) {
                        return false;
                    }

                    std::string candidate_std = candidate.to_string();
                    ppp::string candidate_key(candidate_std.data(), candidate_std.size());

                    boost::asio::ip::address_v6 configured_network;
                    int allowed_prefix_length = 0;
                    if (GetConfiguredIPv6Network(*configuration_, configured_network, allowed_prefix_length)) {
                        if (!ppp::ipv6::PrefixMatch(candidate, configured_network, allowed_prefix_length)) {
                            return false;
                        }
                    }

                    UInt64 now = Executors::GetTickCount();
                    UInt64 expires_at = ipv6.lease_time > 0 ? now + static_cast<UInt64>(ipv6.lease_time) * 1000ULL : UINT64_MAX;

                    SynchronizedObjectScope scope(syncobj_);
                    auto existing_lease_it = ipv6_leases_.find(session_id);
                    if (existing_lease_it != ipv6_leases_.end() && existing_lease_it->second.Address.is_v6() && candidate != existing_lease_it->second.Address.to_v6()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                        return false;
                    }

                    auto mapping_it = ipv6s_.find(candidate_key);
                    if (mapping_it != ipv6s_.end() && mapping_it->second && mapping_it->second->GetId() != session_id) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                        return false;
                    }

                    for (const auto& kv : ipv6_leases_) {
                        if (kv.first == session_id) {
                            continue;
                        }

                        const IPv6LeaseEntry& lease = kv.second;
                        if (!lease.Address.is_v6() || lease.Address.to_v6() != candidate) {
                            continue;
                        }

                        if (lease.StaticBinding || lease.ExpiresAt == UINT64_MAX || lease.ExpiresAt > now) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                            return false;
                        }
                    }

                    IPv6LeaseEntry& lease = ipv6_leases_[session_id];
                    lease.SessionId = session_id;
                    lease.ExpiresAt = static_binding ? UINT64_MAX : expires_at;
                    lease.Address = boost::asio::ip::address(candidate);
                    lease.AddressPrefixLength = extensions.AssignedIPv6AddressPrefixLength;
                    lease.StaticBinding = static_binding;

                    extensions.AssignedIPv6Address = boost::asio::ip::address(candidate);
                    extensions.IPv6StatusCode = status_code;
                    extensions.IPv6StatusMessage = status_message;
                    return true;
                };

                boost::system::error_code ec;

                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (mode == AppConfiguration::IPv6Mode_Nat66) {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                    extensions.AssignedIPv6AddressPrefixLength = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;

                    if (configuration_->server.subnet && ipv6.prefix_length > ppp::ipv6::IPv6_MIN_PREFIX_LENGTH && ipv6.prefix_length < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                        boost::system::error_code route_ec;
                        ppp::string route_prefix_string = ipv6.cidr;
                        std::size_t route_slash = route_prefix_string.find('/');
                        if (route_slash != ppp::string::npos) {
                            route_prefix_string = route_prefix_string.substr(0, route_slash);
                        }

                        boost::asio::ip::address route_prefix = StringToAddress(route_prefix_string, route_ec);
                        if (!route_ec && route_prefix.is_v6()) {
                            extensions.AssignedIPv6RoutePrefix = route_prefix;
                            extensions.AssignedIPv6RoutePrefixLength = static_cast<Byte>(ipv6.prefix_length);
                        }
                    }

                    boost::asio::ip::address_v6::bytes_type ula_bytes = {};
                    ec.clear();
                    ppp::string configured_prefix_string = ipv6.cidr;
                    std::size_t slash = configured_prefix_string.find('/');
                    if (slash != ppp::string::npos) {
                        configured_prefix_string = configured_prefix_string.substr(0, slash);
                    }
                    boost::asio::ip::address configured_prefix = StringToAddress(configured_prefix_string, ec);
                    if (!ec && configured_prefix.is_v6()) {
                        ula_bytes = configured_prefix.to_v6().to_bytes();
                    }
                    else {
                        ula_bytes[0] = 0xfd;
                    }

                    if (!build_stable_ipv6(ula_bytes, ipv6.prefix_length)) {
                        extensions.Clear();
                        return false;
                    }

                    boost::asio::ip::address_v6 stable_candidate = extensions.AssignedIPv6Address.to_v6();
                    extensions.AssignedIPv6Address = boost::asio::ip::address();

                    ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                    auto static_it = ipv6.static_addresses.find(session_guid);
                    if (static_it != ipv6.static_addresses.end()) {
                        ec.clear();
                        boost::asio::ip::address static_address = StringToAddress(static_it->second, ec);
                        if (!ec && static_address.is_v6()) {
                            if (!try_commit_ipv6_lease(static_address.to_v6(), true, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "static-binding")) {
                                extensions.Clear();
                                extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                                extensions.IPv6StatusMessage = "server-ipv6-static-binding-invalid";
                                return false;
                            }
                        }
                    }

                    boost::asio::ip::address_v6 requested_address = request_entry.RequestedAddress.is_v6() ? request_entry.RequestedAddress.to_v6() : boost::asio::ip::address_v6();
                    bool use_requested_first = is_request_usable(requested_address, boost::asio::ip::address_v6(ula_bytes), ipv6.prefix_length);

                    if (!extensions.AssignedIPv6Address.is_v6() && use_requested_first && request_entry.RequestedAddress.is_v6()) {
                        boost::asio::ip::address_v6 requested = request_entry.RequestedAddress.to_v6();
                        if (ppp::ipv6::PrefixMatch(requested, boost::asio::ip::address_v6(ula_bytes), ipv6.prefix_length)) {
                            try_commit_ipv6_lease(requested, false, VirtualEthernetInformationExtensions::IPv6Status_ClientRequested, "client-request-accepted");
                        }
                    }

                    if (!extensions.AssignedIPv6Address.is_v6()) {
                        boost::asio::ip::address_v6 leased;
                        {
                            SynchronizedObjectScope scope(syncobj_);
                            auto lease_it = ipv6_leases_.find(session_id);
                            if (lease_it != ipv6_leases_.end() && lease_it->second.Address.is_v6()) {
                                leased = lease_it->second.Address.to_v6();
                            }
                        }
                        if (!leased.is_unspecified()) {
                            try_commit_ipv6_lease(leased, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "lease-reused");
                        }
                    }

                    if (!extensions.AssignedIPv6Address.is_v6()) {
                        boost::asio::ip::address_v6::bytes_type candidate_bytes = stable_candidate.to_bytes();
                        bool committed = false;
                        static constexpr unsigned char retry_masks[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
                        for (unsigned char retry_mask : retry_masks) {
                            boost::asio::ip::address_v6 candidate = boost::asio::ip::address_v6(candidate_bytes);
                            if (try_commit_ipv6_lease(candidate, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, request_entry.RequestedAddress.is_v6() ? "client-request-replaced" : "server-auto-assigned")) {
                                committed = true;
                                break;
                            }
                            candidate_bytes[15] ^= retry_mask;
                        }

                        if (!committed) {
                            extensions.Clear();
                            extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                            extensions.IPv6StatusMessage = "ipv6-address-unavailable";
                            return false;
                        }
                    }

                    boost::asio::ip::address gateway = GetIPv6TransitGateway();
                    if (gateway.is_v6()) {
                        extensions.AssignedIPv6Gateway = gateway;
                    }
                    elif (mode == AppConfiguration::IPv6Mode_Gua) {
                        extensions.Clear();
                        extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                        extensions.IPv6StatusMessage = "server-gua-requires-gateway";
                        return false;
                    }

                    // NAT mode still carries an explicit virtual gateway so clients can prefer
                    // `default via <gateway> dev tun0` over direct-device routing.

                    ec.clear();
                    boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                    if (!ec && dns1.is_v6()) {
                        extensions.AssignedIPv6Dns1 = dns1;
                    }

                    ec.clear();
                    boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                    if (!ec && dns2.is_v6()) {
                        extensions.AssignedIPv6Dns2 = dns2;
                    }

                    return extensions.HasAny();
                }
                elif (mode == AppConfiguration::IPv6Mode_Gua) {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                    extensions.AssignedIPv6AddressPrefixLength = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
                    extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_NeighborProxy;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6CidrInvalid);
                    extensions.Clear();
                    return false;
                }

                if (mode == AppConfiguration::IPv6Mode_Gua && !IsGlobalUnicastIPv6Address(prefix.to_v6())) {
                    extensions.Clear();
                    extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                    extensions.IPv6StatusMessage = "server-gua-requires-global-unicast-cidr";
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type bytes = prefix.to_v6().to_bytes();
                if (!build_stable_ipv6(bytes, ipv6.prefix_length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6CidrInvalid);
                    extensions.Clear();
                    return false;
                }
                boost::asio::ip::address_v6 stable_candidate = extensions.AssignedIPv6Address.to_v6();

                extensions.AssignedIPv6Address = boost::asio::ip::address();

                ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                auto static_it = ipv6.static_addresses.find(session_guid);
                    if (static_it != ipv6.static_addresses.end()) {
                        ec.clear();
                        boost::asio::ip::address static_address = StringToAddress(static_it->second, ec);
                        if (!ec && static_address.is_v6()) {
                            if (!try_commit_ipv6_lease(static_address.to_v6(), true, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "static-binding")) {
                                // Populate extensions error fields so the caller / client can
                                // distinguish a static-binding conflict from other failure modes.
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                                extensions.IPv6StatusCode    = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                                extensions.IPv6StatusMessage = "gua-static-binding-conflict";
                                return false;
                            }
                        }
                    }

                boost::asio::ip::address_v6 requested_address = request_entry.RequestedAddress.is_v6() ? request_entry.RequestedAddress.to_v6() : boost::asio::ip::address_v6();
                bool use_requested_first = is_request_usable(requested_address, prefix.to_v6(), ipv6.prefix_length);

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    boost::asio::ip::address leased_address;
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        auto lease_it = ipv6_leases_.find(session_id);
                        if (lease_it != ipv6_leases_.end() && lease_it->second.Address.is_v6()) {
                            leased_address = lease_it->second.Address;
                        }
                    }
                    if (leased_address.is_v6()) {
                        try_commit_ipv6_lease(leased_address.to_v6(), false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "lease-reused");
                    }
                }

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    if (!extensions.AssignedIPv6Address.is_v6() && use_requested_first && request_entry.RequestedAddress.is_v6()) {
                        boost::asio::ip::address_v6 requested = request_entry.RequestedAddress.to_v6();
                        if (ppp::ipv6::PrefixMatch(requested, prefix.to_v6(), ipv6.prefix_length)) {
                            try_commit_ipv6_lease(requested, false, VirtualEthernetInformationExtensions::IPv6Status_ClientRequested, "client-request-accepted");
                        }
                    }

                    if (!extensions.AssignedIPv6Address.is_v6()) {
                        boost::asio::ip::address_v6::bytes_type candidate_bytes = stable_candidate.to_bytes();
                        bool committed = false;

                        static constexpr unsigned char retry_masks[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

                        for (unsigned char retry_mask : retry_masks) {
                            boost::asio::ip::address_v6 candidate = boost::asio::ip::address_v6(candidate_bytes);
                            if (try_commit_ipv6_lease(candidate, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, request_entry.RequestedAddress.is_v6() ? "client-request-replaced" : "server-auto-assigned")) {
                                committed = true;
                                break;
                            }

                            candidate_bytes[15] ^= retry_mask;
                        }

                        if (!committed) {
                            extensions.Clear();
                            extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                            extensions.IPv6StatusMessage = "ipv6-address-unavailable";
                            return false;
                        }
                    }

                }

                boost::asio::ip::address gateway = GetIPv6TransitGateway();
                if (gateway.is_v6()) {
                    extensions.AssignedIPv6Gateway = gateway;
                }

                ec.clear();
                boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                if (!ec && dns1.is_v6()) {
                    extensions.AssignedIPv6Dns1 = dns1;
                }

                ec.clear();
                boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                if (!ec && dns2.is_v6()) {
                    extensions.AssignedIPv6Dns2 = dns2;
                }

                if (extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Nat66 &&
                    extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Gua) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    extensions.Clear();
                    return false;
                }

                return extensions.HasAny();
            }

            /**
             * @brief Retrieves the currently leased IPv6 extension set for a session.
             * @param session_id Session identifier.
             * @param extensions Receives extension values when lease is valid.
             * @return true if a valid assigned IPv6 lease exists; otherwise false.
             */
            bool VirtualEthernetSwitcher::TryGetAssignedIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept {
                extensions.Clear();
                if (!IsIPv6ServerEnabled()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (mode != AppConfiguration::IPv6Mode_Nat66 && mode != AppConfiguration::IPv6Mode_Gua) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                IPv6LeaseEntry lease;
                std::string lease_ip_std;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto lease_it = ipv6_leases_.find(session_id);
                    if (lease_it == ipv6_leases_.end() || !lease_it->second.Address.is_v6()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseUnavailable);
                        return false;
                    }
                    lease = lease_it->second;

                    lease_ip_std = lease.Address.to_string();
                    ppp::string lease_ip_key(lease_ip_std.data(), lease_ip_std.size());
                    auto owner_it = ipv6s_.find(lease_ip_key);
                    if (owner_it == ipv6s_.end() || !owner_it->second || owner_it->second->GetId() != session_id) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseUnavailable);
                        return false;
                    }
                }

                boost::system::error_code ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6CidrInvalid);
                    return false;
                }

                if (!ppp::ipv6::PrefixMatch(lease.Address.to_v6(), prefix.to_v6(), ipv6.prefix_length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetMaskInvalid);
                    return false;
                }

                extensions.AssignedIPv6Mode = mode == AppConfiguration::IPv6Mode_Nat66 ?
                    VirtualEthernetInformationExtensions::IPv6Mode_Nat66 :
                    VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                extensions.AssignedIPv6AddressPrefixLength = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
                extensions.AssignedIPv6Address = lease.Address;
                extensions.AssignedIPv6Gateway = GetIPv6TransitGateway();
                if (mode == AppConfiguration::IPv6Mode_Gua && !extensions.AssignedIPv6Gateway.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6GatewayInvalid);
                    return false;
                }
                if (mode == AppConfiguration::IPv6Mode_Gua) {
                    extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_NeighborProxy;
                }
                if (mode == AppConfiguration::IPv6Mode_Nat66 && configuration_->server.subnet && ipv6.prefix_length > ppp::ipv6::IPv6_MIN_PREFIX_LENGTH && ipv6.prefix_length < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    extensions.AssignedIPv6RoutePrefix = prefix;
                    extensions.AssignedIPv6RoutePrefixLength = static_cast<Byte>(ipv6.prefix_length);
                }

                ec.clear();
                boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                if (!ec && dns1.is_v6()) {
                    extensions.AssignedIPv6Dns1 = dns1;
                }

                ec.clear();
                boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                if (!ec && dns2.is_v6()) {
                    extensions.AssignedIPv6Dns2 = dns2;
                }

                return extensions.AssignedIPv6Address.is_v6();
            }

            /**
             * @brief Binds a session exchanger to its assigned IPv6 dataplane state.
             * @param session_id Session identifier.
             * @param extensions Assigned IPv6 settings.
             * @return true when route, permanent-neighbor/proxy, and table mappings are installed.
             */
            bool VirtualEthernetSwitcher::AddIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (!extensions.AssignedIPv6Address.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                    return false;
                }

#if defined(_LINUX)
                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
#endif
                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                const boost::asio::ip::address& ip = extensions.AssignedIPv6Address;
                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

#if defined(_LINUX)
                ITapPtr transit_tap;
#endif
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    auto active = exchangers_.find(session_id);
                    if (active == exchangers_.end() || active->second != exchanger) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                        return false;
                    }

                    // O(1) check: if this session already has a lease for a different address,
                    // reject the binding to avoid a session owning multiple IPv6 entries in ipv6s_.
                    auto lease_it = ipv6_leases_.find(session_id);
                    if (lease_it != ipv6_leases_.end() && lease_it->second.Address.is_v6()) {
                        std::string existing_std = lease_it->second.Address.to_string();
                        ppp::string existing_key(existing_std.data(), existing_std.size());
                        if (existing_key != ip_key) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                            return false;
                        }
                    }

                    auto existing = ipv6s_.find(ip_key);
                    if (existing != ipv6s_.end() && existing->second && session_id != existing->second->GetId()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                        return false;
                    }
#if defined(_LINUX)
                    transit_tap = ipv6_transit_tap_;
#endif
                }

#if defined(_LINUX)
                if (NULLPTR == transit_tap) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    return false;
                }
                bool route_ok = AddIPv6TransitRouteOnTap(transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#else
                bool route_ok = AddIPv6TransitRoute(ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#endif
                if (!route_ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteAddFailed);
                    return false;
                }

#if defined(_LINUX)
                ppp::tap::TapLinux::NeighborMutationResult neighbor_result =
                    ppp::tap::TapLinux::AddIPv6PermanentNeighbor(transit_tap->GetId(), ip_key);
                if (neighbor_result == ppp::tap::TapLinux::NeighborMutationResult::Failed) {
                    DeleteIPv6TransitRouteOnTap(transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
                    return false;
                }
                bool permanent_neighbor_created = neighbor_result == ppp::tap::TapLinux::NeighborMutationResult::Changed;
#endif

                bool proxy_required = AppConfiguration::IPv6Mode_Gua == mode;
                bool proxy_ok = !proxy_required || AddIPv6NeighborProxy(ip);
                if (!proxy_ok) {
                    ppp::diagnostics::ErrorCode failure_code = ppp::diagnostics::GetLastErrorCode();
#if defined(_LINUX)
                    if (permanent_neighbor_created &&
                        !ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(transit_tap->GetId(), ip_key)) {
                        SynchronizedObjectScope scope(syncobj_);
                        if (ipv6_transit_tap_ == transit_tap) {
                            ipv6_transit_neighbor_owned_.insert(ip_key);
                        }
                    }
                    DeleteIPv6TransitRouteOnTap(transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#else
                    DeleteIPv6TransitRoute(ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#endif
                    ppp::diagnostics::SetLastErrorCode(
                        failure_code == ppp::diagnostics::ErrorCode::Success
                            ? ppp::diagnostics::ErrorCode::IPv6NeighborProxyAddFailed
                            : failure_code);
                    return false;
                }

                bool can_publish = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto active = exchangers_.find(session_id);
                    auto existing = ipv6s_.find(ip_key);
                    bool destination_available = existing == ipv6s_.end() ||
                        !existing->second || existing->second == exchanger;
                    can_publish = !disposed_.load(std::memory_order_acquire) &&
                        active != exchangers_.end() && active->second == exchanger &&
                        destination_available;
#if defined(_LINUX)
                    can_publish = can_publish && ipv6_transit_tap_ == transit_tap;
#endif
                    if (can_publish) {
                        ipv6s_[ip_key] = exchanger;
#if defined(_LINUX)
                        if (permanent_neighbor_created) {
                            ipv6_transit_neighbor_owned_.insert(ip_key);
                        }
#endif
                    }
                }

                if (!can_publish) {
                    if (proxy_required) {
                        DeleteIPv6NeighborProxy(ip);
                    }
#if defined(_LINUX)
                    if (permanent_neighbor_created &&
                        !ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(transit_tap->GetId(), ip_key)) {
                        SynchronizedObjectScope scope(syncobj_);
                        if (ipv6_transit_tap_ == transit_tap) {
                            ipv6_transit_neighbor_owned_.insert(ip_key);
                        }
                    }
                    DeleteIPv6TransitRouteOnTap(transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#else
                    DeleteIPv6TransitRoute(ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#endif
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                ppp::telemetry::Count("server.ipv6.assigned", 1);
                ppp::telemetry::Log(Level::kDebug, "server", "ipv6 assigned");
                return true;
            }

            /**
             * @brief Removes one IPv6 exchanger binding using explicit extension data.
             * @param session_id Session identifier.
             * @param extensions Extension object containing assigned IPv6 address.
             * @return true when route, owned permanent neighbor, and proxy teardown succeeds.
             *
             * @note Two-phase locking: the map entry is erased under syncobj_ to guarantee
             *       atomic removal visibility, then the OS-level route/neighbor/proxy teardown
             *       runs outside the lock to avoid blocking peers during kernel operations.
             */
            bool VirtualEthernetSwitcher::DeleteIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept {
                ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                ppp::telemetry::SpanScope span("server.ipv6.withdraw", session_guid.c_str());
                if (!extensions.AssignedIPv6Address.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                    return false;
                }

#if defined(_LINUX)
                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
#endif
                const boost::asio::ip::address& ip = extensions.AssignedIPv6Address;
                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

#if defined(_LINUX)
                bool permanent_neighbor_owned = false;
                ITapPtr transit_tap;
#endif
                {
                    /** @brief Hold the lock only long enough to validate and erase the map entry. */
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    auto tail = ipv6s_.find(ip_key);
                    if (tail == ipv6s_.end()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                        return false;
                    }

                    if (tail->second && tail->second->GetId() != session_id) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseConflict);
                        return false;
                    }

                    ipv6s_.erase(tail);
#if defined(_LINUX)
                    permanent_neighbor_owned = ipv6_transit_neighbor_owned_.count(ip_key) > 0;
                    transit_tap = ipv6_transit_tap_;
#endif
                }

                /**
                 * @brief OS-level teardown runs outside syncobj_ to avoid prolonged lock hold.
                 *
                 * The lifecycle mutex keeps Finalize() from replacing or disposing the TAP while
                 * route and neighbor deletion runs against the snapshotted identity.
                 */
#if defined(_LINUX)
                bool route_removed = DeleteIPv6TransitRouteOnTap(
                    transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#else
                bool route_removed = DeleteIPv6TransitRoute(ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#endif
                bool proxy_removed = DeleteIPv6NeighborProxy(ip);
                bool permanent_neighbor_removed = true;
#if defined(_LINUX)
                if (permanent_neighbor_owned) {
                    permanent_neighbor_removed = NULLPTR != transit_tap &&
                        ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(transit_tap->GetId(), ip_key);
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    bool identity_valid = !disposed_.load(std::memory_order_acquire) &&
                        ipv6_transit_tap_ == transit_tap;
                    if (identity_valid && permanent_neighbor_owned && permanent_neighbor_removed) {
                        ipv6_transit_neighbor_owned_.erase(ip_key);
                    }
                    elif (!identity_valid) {
                        permanent_neighbor_removed = false;
                    }
                    // On failure the ownership record is deliberately retained for Finalize()
                    // or a later cleanup attempt.
                }
#endif

                ppp::telemetry::Count("server.ipv6.withdrawn", 1);
                ppp::telemetry::Log(Level::kDebug, "server", "ipv6 withdrawn");

                RevokeIPv6Lease(session_id);
                if (!route_removed) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteDeleteFailed);
                }

                if (!proxy_removed) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                }

                return route_removed && proxy_removed && permanent_neighbor_removed;
            }

            /**
             * @brief Removes all IPv6 exchanger bindings owned by the session.
             * @param session_id Session identifier.
             * @return true if any matching binding existed and was removed.
             */
            bool VirtualEthernetSwitcher::DeleteIPv6Exchanger(const Int128& session_id) noexcept {
                bool any          = false;
                bool released_any = false;

#if defined(_LINUX)
                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
                ITapPtr transit_tap;
#endif
                /**
                 * @note  Two-phase pattern: IPv6 addresses to clean up are collected and
                 *        map entries are erased while syncobj_ is held; route, permanent
                 *        neighbor, and proxy cleanup then executes OUTSIDE the lock. This
                 *        avoids holding syncobj_ across potentially blocking kernel operations.
                 *
                 *        RevokeIPv6Lease() MUST NOT be called here because it also acquires
                 *        syncobj_ — doing so on a non-recursive std::mutex would cause an
                 *        immediate self-deadlock on the calling thread.  Instead, the
                 *        lease/request erasure is inlined directly inside this existing lock
                 *        region to satisfy the same invariant without re-entering the mutex.
                 */

                ppp::vector<std::pair<boost::asio::ip::address, ppp::string>> cleanup_ipv6_entries;
#if defined(_LINUX)
                ppp::unordered_set<ppp::string> cleanup_owned_neighbors;
#endif

                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }
#if defined(_LINUX)
                    transit_tap = ipv6_transit_tap_;
#endif
                    for (auto tail = ipv6s_.begin(); tail != ipv6s_.end();) {
                        VirtualEthernetExchangerPtr current = tail->second;
                        if (!current || current->GetId() != session_id) {
                            ++tail;
                            continue;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address ip = StringToAddress(tail->first, ec);
                        if (!ec && ip.is_v6()) {
                            cleanup_ipv6_entries.emplace_back(ip, tail->first);
                        }
#if defined(_LINUX)
                        if (ipv6_transit_neighbor_owned_.count(tail->first) > 0) {
                            cleanup_owned_neighbors.insert(tail->first);
                        }
#endif

                        tail = ipv6s_.erase(tail);
                        released_any = true;
                        any          = true;
                        ppp::telemetry::Count("server.ipv6.withdrawn", 1);
                        ppp::telemetry::Log(Level::kDebug, "server", "ipv6 withdrawn");
                    }

                    if (released_any) {
                        /**
                         * @brief Inline the RevokeIPv6Lease() body to avoid re-acquiring
                         *        syncobj_ (which is already held above).  The semantic
                         *        result is identical: both lease and request records for
                         *        this session are removed under the same lock region.
                         */
                        ipv6_leases_.erase(session_id);
                        ipv6_requests_.erase(session_id);
                    }
                }

#if defined(_LINUX)
                ppp::unordered_set<ppp::string> removed_owned_neighbors;
#endif
                // Perform route and neighbor cleanup outside the table lock. The lifecycle
                // lock keeps the snapshotted TAP alive and prevents identity replacement.
                for (const auto& entry : cleanup_ipv6_entries) {
#if defined(_LINUX)
                    DeleteIPv6TransitRouteOnTap(
                        transit_tap, entry.first, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#else
                    DeleteIPv6TransitRoute(entry.first, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
#endif
                    DeleteIPv6NeighborProxy(entry.first);
#if defined(_LINUX)
                    if (cleanup_owned_neighbors.count(entry.second) > 0 && NULLPTR != transit_tap &&
                        ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(transit_tap->GetId(), entry.second)) {
                        removed_owned_neighbors.insert(entry.second);
                    }
#endif
                }

#if defined(_LINUX)
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (!disposed_.load(std::memory_order_acquire) && ipv6_transit_tap_ == transit_tap) {
                        for (const ppp::string& ip_key : removed_owned_neighbors) {
                            ipv6_transit_neighbor_owned_.erase(ip_key);
                        }
                    }
                    // Failed deletions stay owned so Finalize() can retry them even though
                    // their exchanger mappings have already been removed.
                }
#endif
                return any;
            }

            /**
             * @brief Finds the session exchanger that owns a given IPv6 address.
             * @param ip IPv6 address key.
             * @return Matching exchanger pointer or null when not found.
             */
            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::FindIPv6Exchanger(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v6()) {
                    return NULLPTR;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                SynchronizedObjectScope scope(syncobj_);
                auto tail = ipv6s_.find(ip_key);
                if (tail != ipv6s_.end()) {
                    return tail->second;
                }
                return NULLPTR;
            }

            /**
             * @brief Enables host-level IPv6 neighbor proxy when required by mode.
             * @return true if proxy state is ready or not required; otherwise false.
             */
            bool VirtualEthernetSwitcher::OpenIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                CloseIPv6NeighborProxyIfNeed();
                if (!IsIPv6ServerEnabled() || AppConfiguration::IPv6Mode_Gua != ipv6.mode) {
                    return true;
                }


                ppp::string uplink_name = ResolvePreferredIPv6UplinkInterface(preferred_nic_);
                if (uplink_name.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyEnableFailed);
                    return false;
                }

                bool proxy_enabled = false;
                bool query_ok = ppp::tap::TapLinux::QueryIPv6NeighborProxy(uplink_name, proxy_enabled);
                if (!ppp::tap::TapLinux::EnableIPv6NeighborProxy(uplink_name)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyEnableFailed);
                    return false;
                }

                ipv6_neighbor_proxy_ifname_ = uplink_name;
                ipv6_neighbor_proxy_owned_ = query_ok ? !proxy_enabled : false;
#else
                if (IsIPv6ServerEnabled()) {
                }
#endif
                return true;
            }

            /**
             * @brief Restores neighbor proxy configuration when switcher is closing.
             * @return true after cleanup path completes.
             */
            bool VirtualEthernetSwitcher::CloseIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                if (ipv6_neighbor_proxy_ifname_.empty()) {
                    return true;
                }

                bool ok = true;
                if (ipv6_neighbor_proxy_owned_) {
                    ok = ppp::tap::TapLinux::DisableIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_);
                }
                ipv6_neighbor_proxy_ifname_.clear();
                ipv6_neighbor_proxy_owned_ = false;
                ipv6_ndp_proxy_applied_    = false; ///< Reset so the sysctl runs again on next Open.
#endif
                return true;
            }

            /**
             * @brief Installs a host route for an assigned IPv6 client address.
             * @param ip Client IPv6 address.
             * @param prefix_length Route prefix length.
             * @return true when route add operation succeeds.
             */
            bool VirtualEthernetSwitcher::AddIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept {
#if defined(_LINUX)
                ppp::telemetry::SpanScope span("server.route.add");
                if (!ip.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (!(AppConfiguration::IPv6Mode_Nat66 == mode || AppConfiguration::IPv6Mode_Gua == mode)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
                ITapPtr tap;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }
                    tap = ipv6_transit_tap_;
                }

                bool ok = AddIPv6TransitRouteOnTap(tap, ip, prefix_length);
                bool identity_valid = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    identity_valid = !disposed_.load(std::memory_order_acquire) && ipv6_transit_tap_ == tap;
                }
                if (!identity_valid) {
                    if (ok) {
                        DeleteIPv6TransitRouteOnTap(tap, ip, prefix_length);
                    }
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    return false;
                }
                return ok;
#else
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteAddFailed);
                return false;
#endif
            }

            /**
             * @brief Removes a previously installed IPv6 transit route.
             * @param ip Client IPv6 address.
             * @param prefix_length Route prefix length.
             * @return true when route delete operation succeeds.
             */
            bool VirtualEthernetSwitcher::DeleteIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept {
#if defined(_LINUX)
                ppp::telemetry::SpanScope span("server.route.delete");
                if (!ip.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (!(AppConfiguration::IPv6Mode_Nat66 == mode || AppConfiguration::IPv6Mode_Gua == mode)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
                ITapPtr tap;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }
                    tap = ipv6_transit_tap_;
                }

                bool ok = DeleteIPv6TransitRouteOnTap(tap, ip, prefix_length);
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire) || ipv6_transit_tap_ != tap) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                        return false;
                    }
                }
                return ok;
#else
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitRouteDeleteFailed);
                return false;
#endif
            }

            /**
             * @brief Snapshots all mapped and orphan-owned IPv6 cleanup keys, then clears mappings.
             */
            void VirtualEthernetSwitcher::ClearIPv6ExchangersUnsafe(
                ppp::unordered_set<ppp::string>& cleanup_keys,
                ppp::unordered_set<ppp::string>& cleanup_owned_neighbors) noexcept {
                for (const auto& kv : ipv6s_) {
                    cleanup_keys.insert(kv.first);
                }
                for (const ppp::string& ip_key : ipv6_transit_neighbor_owned_) {
                    cleanup_keys.insert(ip_key);
                    cleanup_owned_neighbors.insert(ip_key);
                }

                ipv6s_.clear();
                ipv6_leases_.clear();
                ipv6_requests_.clear();
            }

            /**
             * @brief Adds an IPv6 neighbor proxy entry for one client address.
             * @param ip Client IPv6 address.
             * @return true when proxy entry is installed or not required.
             */
            bool VirtualEthernetSwitcher::AddIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (AppConfiguration::IPv6Mode_Gua != ipv6.mode) {
                    return true;
                }

                if (!ip.is_v6() || ipv6_neighbor_proxy_ifname_.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyAddFailed);
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::AddIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_, ip_str);
                if (ok) {
                    ppp::telemetry::Log(Level::kDebug, "server", "neighbor proxy added");
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyAddFailed);
                }
                return ok;
#else
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyAddFailed);
                return false;
#endif
            }

            /**
             * @brief Removes an IPv6 neighbor proxy entry from active uplink.
             * @param ip Client IPv6 address.
             * @return true when proxy delete succeeds.
             */
            bool VirtualEthernetSwitcher::DeleteIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6() || ipv6_neighbor_proxy_ifname_.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::DeleteIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_, ip_str);
                if (ok) {
                    ppp::telemetry::Log(Level::kDebug, "server", "neighbor proxy deleted");
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                }
                return ok;
#else
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                return false;
#endif
            }

            /**
             * @brief Removes an IPv6 neighbor proxy entry from a specific interface.
             * @param ifname Interface name.
             * @param ip Client IPv6 address.
             * @return true when proxy delete succeeds.
             */
            bool VirtualEthernetSwitcher::DeleteIPv6NeighborProxy(const ppp::string& ifname, const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6() || ifname.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::DeleteIPv6NeighborProxy(ifname, ip_str);
                if (ok) {
                    ppp::telemetry::Log(Level::kDebug, "server", "neighbor proxy deleted");
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                }
                return ok;
#else
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyDeleteFailed);
                return false;
#endif
            }

            /**
             * @brief Starts accept loops for all configured inbound listener categories.
             * @return true if at least one acceptor starts successfully.
             */
             bool VirtualEthernetSwitcher::Run() noexcept {
                ppp::telemetry::SpanScope span("server.acceptors.start");
                // Snapshot the acceptor list under the lock, then start accept loops
                // outside the lock to avoid holding syncobj_ across socket operations.
                std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptors_snapshot[NetworkAcceptorCategories_Max];

                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return false;
                    }

                    for (int categories = NetworkAcceptorCategories_Min; categories < NetworkAcceptorCategories_Max; categories++) {
                        acceptors_snapshot[categories] = acceptors_[categories];
                    }
                }

                auto self = shared_from_this();
                bool bany = false;
                auto started_at = std::chrono::steady_clock::now();
                for (int categories = NetworkAcceptorCategories_Min; categories < NetworkAcceptorCategories_Max; categories++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_snapshot[categories];
                    if (NULLPTR == acceptor) {
                        continue;
                    }

                    Socket::GetContextCallback pinned_context;
                    if (categories == NetworkAcceptorCategories_WebSocketSSL &&
                        configuration_->server.session_resume.enabled) {
                        pinned_context = [this]() noexcept { return context_; };
                    }

                    bool bok = Socket::AcceptLoopbackAsync(acceptor,
                        [self, this, acceptor, categories](const Socket::AsioContext& context, const Socket::AsioTcpSocket& socket) noexcept {
                            if (NULLPTR == socket || !socket->is_open()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketNotOpen);
                                return false;
                            }

                            if (!Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                                return false;
                            }

                            if (!socket->is_open()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketNotOpen);
                                return false;
                            }

                            ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                            return !disposed_ && Accept(context, socket, categories);
                        }, pinned_context);

                    if (bok) {
                        bany = true;
                    }
                    else {
                        SynchronizedObjectScope scope(syncobj_);
                        Socket::Closesocket(acceptor);
                        acceptors_[categories] = NULLPTR;
                    }
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("server.acceptors.start.us", elapsed);
                if (bany) {
                    ppp::telemetry::Log(Level::kInfo, "server", "server acceptors running");
                }
                running_.store(bany, std::memory_order_release);
                return bany;
            }

            static constexpr int STATUS_ERROR = -1;
            static constexpr int STATUS_RUNING = +1;
            static constexpr int STATUS_RUNNING_SWAP = +0;

            bool VirtualEthernetSwitcher::AuthenticatePlainTransport(
                const ITransmissionPtr& transmission, const Int128& session_id,
                YieldContext& y) noexcept {
                using ppp::app::protocol::TransportAuthAction;
                using ppp::app::protocol::TransportAuthCarrier;
                using ppp::app::protocol::TransportAuthControl;
                using ppp::app::protocol::TransportAuthNegotiationContext;
                using ppp::app::protocol::TransportAuthResponder;
                using ppp::transmissions::AuthenticatedCarrierKind;

                if (NULLPTR == transmission || NULLPTR == configuration_) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                const AuthenticatedCarrierKind kind =
                    transmission->GetAuthenticatedCarrierKind();
                const bool plain_carrier = kind == AuthenticatedCarrierKind::Tcp ||
                    kind == AuthenticatedCarrierKind::WebSocket;
                if (!plain_carrier || transmission->IsServerLoopbackIngress() ||
                    !configuration_->server.transport_auth.enabled ||
                    !transmission->PeerSupportsTransportAuthV1() ||
                    !transmission->PeerEnablesTransportAuthV1()) {
                    return true;
                }

                ppp::app::protocol::SessionResumeId binary_session_id{};
                if (!BuildSessionResumeId(session_id, binary_session_id)) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                const auto& strand = transmission->GetStrand();
                if (NULLPTR == strand) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                static constexpr int HandshakePending = 0;
                static constexpr int HandshakeCompleted = 1;
                static constexpr int HandshakeTimedOut = 2;
                std::shared_ptr<std::atomic_int> handshake_state =
                    make_shared_object<std::atomic_int>(HandshakePending);
                std::shared_ptr<boost::asio::steady_timer> handshake_timer =
                    make_shared_object<boost::asio::steady_timer>(*strand);
                if (NULLPTR == handshake_state || NULLPTR == handshake_timer) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                handshake_timer->expires_after(std::chrono::milliseconds(
                    std::max(1, configuration_->transport_auth.handshake_timeout_ms)));
                handshake_timer->async_wait(
                    [transmission, handshake_state](const boost::system::error_code& ec) noexcept {
                        int expected = HandshakePending;
                        if (!ec && handshake_state->compare_exchange_strong(
                                expected, HandshakeTimedOut, std::memory_order_acq_rel)) {
                            transmission->Dispose();
                        }
                    });

                auto finish = [&]() noexcept {
                    int expected = HandshakePending;
                    const bool timed_out = !handshake_state->compare_exchange_strong(
                        expected, HandshakeCompleted, std::memory_order_acq_rel) &&
                        expected == HandshakeTimedOut;
                    handshake_timer->cancel();
                    if (timed_out) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::SocketTimeout);
                    }
                    return !timed_out;
                };

                auto read_control = [&](TransportAuthControl& control,
                    bool& envelope_received) noexcept {
                    InformationEnvelope envelope;
                    if (!ppp::app::protocol::VirtualEthernetLinklayer::ReadInformation(
                            transmission, envelope, y)) {
                        return false;
                    }
                    envelope_received = true;
                    VirtualEthernetInformationExtensions extensions = envelope.Extensions;
                    control = extensions.TransportAuth;
                    extensions.TransportAuth.Clear();
                    return control.HasAny() && !extensions.HasAny();
                };

                std::shared_ptr<ppp::app::protocol::VirtualEthernetLinklayer> writer =
                    make_shared_object<ppp::app::protocol::VirtualEthernetLinklayer>(
                        configuration_, transmission->GetContext(), session_id);
                auto send_control = [&](const TransportAuthControl& control) noexcept {
                    if (NULLPTR == writer || !control.Valid()) {
                        return false;
                    }
                    InformationEnvelope envelope;
                    envelope.Base.Clear();
                    envelope.Base.IncomingTraffic = std::numeric_limits<UInt64>::max();
                    envelope.Base.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                    envelope.Base.ExpiredTime = std::numeric_limits<UInt32>::max();
                    envelope.Extensions.Clear();
                    envelope.Extensions.TransportAuth = control;
                    envelope.ExtendedJson = envelope.Extensions.ToJson();
                    return writer->DoInformation(transmission, envelope, y);
                };

                auto canonical_token = [](const ppp::string& token) noexcept {
                    if (token.size() != ppp::app::protocol::TransportAuthTokenHexLength) {
                        return false;
                    }
                    for (char value : token) {
                        if (!((value >= '0' && value <= '9') ||
                                (value >= 'a' && value <= 'f'))) {
                            return false;
                        }
                    }
                    return true;
                };
                auto reject = [&](const ppp::string* token) noexcept {
                    TransportAuthControl control;
                    control.Clear();
                    control.action = TransportAuthAction::Reject;
                    control.reason = "authentication-failed";
                    if (NULLPTR != token && canonical_token(*token)) {
                        control.token = *token;
                    }
                    (void)send_control(control);
                };

                TransportAuthNegotiationContext auth_context;
                auth_context.carrier = kind == AuthenticatedCarrierKind::Tcp
                    ? TransportAuthCarrier::Tcp
                    : TransportAuthCarrier::WebSocket;
                auth_context.session_id = binary_session_id;
                auth_context.token.clear();
                TransportAuthResponder responder(
                    configuration_->transport_auth_keyring, auth_context);

                bool advertisement_received = false;
                bool proof_received = false;
                TransportAuthControl advertisement;
                TransportAuthControl response;
                bool authenticated = read_control(
                    advertisement, advertisement_received);
                bool reject_sent = false;
                if (authenticated) {
                    authenticated = responder.ConsumeAdvertisement(
                        advertisement, response);
                    if (!authenticated) {
                        (void)send_control(response);
                        reject_sent = true;
                    }
                }
                if (authenticated) {
                    authenticated = send_control(response);
                }

                TransportAuthControl proof;
                if (authenticated) {
                    authenticated = read_control(proof, proof_received);
                }
                if (authenticated) {
                    authenticated = responder.ConsumeClientProof(proof, response);
                    if (!authenticated) {
                        (void)send_control(response);
                        reject_sent = true;
                    }
                }

                ppp::cryptography::noise::NoisePskHandshakeResult result;
                if (authenticated) {
                    authenticated = responder.TakeNoiseResult(result) &&
                        transmission->InstallNoiseAuthenticatedCarrierBinding(
                            std::move(result));
                }
                if (authenticated) {
                    authenticated = send_control(response);
                }

                if (!authenticated && advertisement_received && !reject_sent) {
                    const ppp::string* token = canonical_token(advertisement.token)
                        ? &advertisement.token
                        : NULLPTR;
                    reject(token);
                }
                if (!authenticated &&
                    ppp::diagnostics::GetLastErrorCode() ==
                        ppp::diagnostics::ErrorCode::Success) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                }
                (void)proof_received;
                return finish() && authenticated;
            }

            /**
             * @brief Handles one accepted transport: handshake, establish, or connect.
             * @param context I/O context associated with the accepted socket.
             * @param transmission Accepted transport object.
             * @param y Coroutine context for async workflow.
             * @return Internal status code describing ownership/run outcome.
             */
            int VirtualEthernetSwitcher::Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return STATUS_ERROR;
                }

                bool mux = false;
                Int128 session_id = transmission->HandshakeClient(y, mux);
                if (session_id == 0) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                    }

                    // Mirror an `ObfuscationFlagsMismatch` diagnosis into the
                    // structured server event log (`server.log`) so the operator
                    // sees it on BOTH log channels.  Telemetry (the other
                    // channel) was already emitted inside the inner handshake.
                    if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::ObfuscationFlagsMismatch) {
                        VirtualEthernetLoggerPtr logger = GetLogger();
                        if (NULLPTR != logger) {
                            const auto& k = configuration_->key;
                            char buf[256];
                            int n = snprintf(buf, sizeof(buf),
                                "server_flags=[masked=%d,plaintext=%d,delta-encode=%d,shuffle-data=%d,kf=%d]; "
                                "client transport sent garbage immediately after handshake -- "
                                "align key.{masked,plaintext,delta-encode,shuffle-data,kf} on both ends.",
                                k.masked ? 1 : 0,
                                k.plaintext ? 1 : 0,
                                k.delta_encode ? 1 : 0,
                                k.shuffle_data ? 1 : 0,
                                k.kf);
                            (void)n;
                            logger->Mismatch(transmission, ppp::string(buf));
                        }
                    }

                    ppp::telemetry::Count("server.session.rejected", 1);
                    ppp::telemetry::Log(Level::kInfo, "server", "session rejected");
                    return STATUS_ERROR;
                }

                if (!AuthenticatePlainTransport(transmission, session_id, y)) {
                    ppp::telemetry::Count("server.transport_auth.rejected", 1);
                    return STATUS_ERROR;
                }

                if (!mux) {
                    return Connect(transmission, session_id, y);
                }

                VirtualEthernetManagedServerPtr managed_server = managed_server_;
                if (NULLPTR == managed_server) {
                    return Establish(transmission, session_id, NULLPTR, y) ? STATUS_RUNING : STATUS_ERROR;
                }

                VirtualEthernetExchanger* exchanger = GetExchanger(session_id).get();
                if (NULLPTR != exchanger) {
                    return Establish(transmission, session_id, NULLPTR, y) ? STATUS_RUNING : STATUS_ERROR;
                }

                auto self = shared_from_this();
                return managed_server->AuthenticationToManagedServer(session_id,
                    [self, this, transmission, session_id, context](bool ok, VirtualEthernetManagedServer::VirtualEthernetInformationPtr& i) noexcept {
                        auto allocator = transmission->BufferAllocator;
                        if (ok) {
                            ok = YieldContext::Spawn(allocator.get(), *context,
                                [self, this, context, transmission, session_id, i](YieldContext& y) noexcept {
                                    if (y) {
                                        Establish(transmission, session_id, i, y);
                                    }

                                    transmission->Dispose();
                                });
                        }

                        if (!ok) {
                            transmission->Dispose();
                        }
                    }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
            }

            /**
             * @brief Dispatches accepted TCP sockets to proxy or transport handshake flows.
             * @param context Socket execution context.
             * @param socket Accepted socket.
             * @param categories Listener category.
             * @return true if async handling was started successfully.
             */
            bool VirtualEthernetSwitcher::Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept {
                if (categories == NetworkAcceptorCategories_CDN1 || categories == NetworkAcceptorCategories_CDN2) {
                    std::shared_ptr<ppp::net::proxies::sniproxy> sniproxy = make_shared_object<ppp::net::proxies::sniproxy>(categories == NetworkAcceptorCategories_CDN1 ? 0 : 1,
                        configuration_,
                        context,
                        socket);
                    if (NULLPTR == sniproxy) {
                        return false;
                    }

                    bool ok = sniproxy->handshake();
                    if (!ok) {
                        sniproxy->close();
                    }

                    return ok;
                }
                else {
                    ITransmissionPtr transmission = Accept(categories, context, socket);
                    if (NULLPTR == transmission) {
                        return false;
                    }

                    auto allocator = transmission->BufferAllocator;
                    auto self = shared_from_this();
                    auto& strand = transmission->GetStrand();
                    if (NULLPTR == strand) {
                        strand = make_shared_object<ppp::threading::Executors::Strand>(
                            context->get_executor());
                        if (NULLPTR == strand) {
                            return false;
                        }
                    }
                    return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                        [self, this, context, transmission](YieldContext& y) noexcept {
                            int status = Run(context, transmission, y);
                            if (status != STATUS_RUNNING_SWAP) {
                                if (status < STATUS_RUNNING_SWAP) {
                                    ppp::diagnostics::ErrorCode error_code = ppp::diagnostics::GetLastErrorCode();
                                    if (ppp::diagnostics::ErrorCode::SocketDisconnected != error_code) {
                                        FlowerArrangement(
                                            transmission,
                                            y);
                                    }
                                }

                                transmission->Dispose();
                            }
                        });
                }
            }

            /**
             * @brief Performs fallback noop handshake response for failed sessions.
             * @param transmission Transport used to send response.
             * @param y Coroutine context.
             * @return true if handshake response is sent; otherwise false.
             */
            bool VirtualEthernetSwitcher::FlowerArrangement(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return false;
                }

                return ppp::transmissions::Transmission_Handshake_Nop(configuration_, transmission.get(), y);
            }

            /**
             * @brief Looks up an active exchanger by session id.
             * @param session_id Session identifier.
             * @return Exchanger pointer when present; otherwise null.
             */
            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::GetExchanger(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULLPTR;
                }

                return Dictionary::FindObjectByKey(exchangers_, session_id);
            }

            /**
             * @brief Creates, opens, and registers a new exchanger for a session.
             * @param transmission Transport bound to exchanger.
             * @param session_id Session identifier.
             * @return New registered exchanger or null on failure.
             */
            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                /**
                 * @brief Phase 1 — guard check only (minimal lock window).
                 *
                 *        newExchanger->Open() is intentionally called OUTSIDE syncobj_
                 *        to prevent a lock-inversion deadlock: Open() is a virtual
                 *        function that may — in derived classes — call back into any
                 *        switcher method that also acquires syncobj_ (e.g. AddNatInformation,
                 *        StaticEchoAllocated), which would immediately deadlock because
                 *        std::mutex is non-recursive.
                 */
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_ || exchangers_.find(session_id) != exchangers_.end()) {
                        return NULLPTR;
                    }
                }

                /**
                 * @brief Phase 2 — construct and open the exchanger without any lock held.
                 *
                 *        NewExchanger() is a simple factory that does not touch the
                 *        switcher's shared state, so it is safe to call lock-free.
                 *        Open() performs protocol / ICMP subsystem initialization and
                 *        may re-enter the switcher; no switcher lock is held here.
                 */
                VirtualEthernetExchangerPtr newExchanger = NewExchanger(transmission, session_id);
                if (NULLPTR == newExchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return NULLPTR;
                }

                if (!newExchanger->Open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                    IDisposable::Dispose(newExchanger);
                    return NULLPTR;
                }

                /**
                 * @brief Phase 3 — re-acquire lock and publish only into an empty slot.
                 *
                 *        Re-check both disposed_ and session identity after the unlocked
                 *        construction window. An active or suspended exchanger is never
                 *        replaced by a racing connection.
                 */
                bool rejected = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_ || exchangers_.find(session_id) != exchangers_.end()) {
                        rejected = true;
                    }
                    else {
                        exchangers_.emplace(session_id, newExchanger);
                        ppp::telemetry::Gauge("server.exchanger_count", (int64_t)exchangers_.size());
                    }
                }

                if (rejected) {
                    IDisposable::Dispose(newExchanger);
                    return NULLPTR;
                }

                ppp::telemetry::Count("server.exchanger.add", 1);
                ppp::telemetry::Log(Level::kInfo, "server", "exchanger added");
                return newExchanger;
            }

            /**
             * @brief Allocates a new exchanger instance for a session.
             * @param transmission Transport bound to exchanger.
             * @param session_id Session identifier.
             * @return New exchanger instance or null on allocation failure.
             */
            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto self = shared_from_this();
                return make_shared_object<VirtualEthernetExchanger>(self, configuration_, transmission, session_id);
            }

            /**
             * @brief Establishes or updates a primary exchanger session connection.
             * @param transmission Transport bound to session.
             * @param session_id Session identifier.
             * @param i Optional managed-server information payload.
             * @param y Coroutine context for protocol exchange.
             * @return true if the carrier lifecycle is accepted or suspended; false on terminal failure.
             */
            bool VirtualEthernetSwitcher::Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept {
                ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                ppp::telemetry::SpanScope span("server.session.establish", session_guid.c_str());
                struct ScopedEstablishHistogram final {
                    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                    ~ScopedEstablishHistogram() noexcept {
                        int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                        ppp::telemetry::Histogram("server.session.establish.us", elapsed);
                    }
                } establish_histogram;

                if (NULLPTR == transmission) {
                    return false;
                }

                bool fresh = false;
                VirtualEthernetExchangerPtr channel = GetExchanger(session_id);
                if (NULLPTR != channel) {
                    ppp::app::protocol::SessionResumePendingAttempt candidate_material;
                    ppp::app::protocol::SessionResumeCandidateBinding& candidate =
                        candidate_material.fields.candidate_binding;
                    const bool resume_enabled =
                        configuration_->server.session_resume.enabled;
                    const bool candidate_available = resume_enabled &&
                        DeriveSessionResumeCandidateBinding(
                            transmission, session_id, candidate);
                    if (!candidate_available) {
                        const SessionResumeFallbackReason fallback_reason = resume_enabled
                            ? SessionResumeFallbackReason::IneligibleCarrier
                            : SessionResumeFallbackReason::ResumeDisabled;
                        ppp::telemetry::Count("server.session.resume_rejected", 1);
                        if (DecideSessionResumeFallback(fallback_reason) !=
                            SessionResumeFallbackDecision::Fresh) {
                            return false;
                        }

                        /**
                         * Session resume is explicitly disabled, so preserve the
                         * pre-resume behavior and replace the existing exchanger.
                         * When resume is enabled, an ineligible carrier must never
                         * reach this path or claim the session by ID alone.
                         */
                        VirtualEthernetExchangerPtr removed = DeleteExchanger(channel.get());
                        if (NULLPTR == removed) {
                            return false;
                        }
                        removed->Finalize();

                        channel = AddNewExchanger(transmission, session_id);
                        if (NULLPTR == channel) {
                            return false;
                        }
                        fresh = true;

                        ppp::telemetry::Gauge("server.active_sessions", (int64_t)exchangers_.size());
                        ppp::telemetry::Count("server.session.accepted", 1);
                        ppp::telemetry::Log(Level::kInfo, "server", "session accepted (fresh, resume disabled)");
                    }

                    auto read_resume_control = [&](ppp::app::protocol::SessionResumeControl& control) noexcept {
                        InformationEnvelope envelope;
                        if (!ppp::app::protocol::VirtualEthernetLinklayer::ReadInformation(
                                transmission, envelope, y)) {
                            return false;
                        }
                        VirtualEthernetInformationExtensions extensions = envelope.Extensions;
                        control = extensions.SessionResume;
                        extensions.SessionResume.Clear();
                        return control.HasAny() && !extensions.HasAny();
                    };
                    auto send_resume_control = [&](const ppp::app::protocol::SessionResumeControl& control) noexcept {
                        if (!control.Valid()) {
                            return false;
                        }

                        InformationEnvelope envelope;
                        envelope.Base.Clear();
                        envelope.Base.BandwidthQoS = 0;
                        envelope.Base.IncomingTraffic = std::numeric_limits<UInt64>::max();
                        envelope.Base.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                        envelope.Base.ExpiredTime = std::numeric_limits<UInt32>::max();
                        envelope.Extensions.Clear();
                        envelope.Extensions.SessionResume = control;
                        envelope.ExtendedJson = envelope.Extensions.ToJson();
                        return channel->DoInformation(transmission, envelope, y);
                    };

                    bool resumed = false;
                    SessionResumeFallbackReason fallback_reason =
                        SessionResumeFallbackReason::OtherResumeFailure;
                    if (!fresh) {
                        using ReadResumeControl = decltype(read_resume_control);
                        using SendResumeControl = decltype(send_resume_control);
                        class EstablishResumeOperations final :
                            public SessionResumeEstablishOperations {
                        public:
                            EstablishResumeOperations(
                                ReadResumeControl& read_control,
                                SendResumeControl& send_control,
                                VirtualEthernetExchangerPtr& channel,
                                const ITransmissionPtr& transmission,
                                const ppp::app::protocol::SessionResumeCandidateBinding& candidate) noexcept
                                : read_control_(read_control)
                                , send_control_(send_control)
                                , channel_(channel)
                                , transmission_(transmission)
                                , candidate_(candidate) {
                            }

                            bool ReadControl(Control& control) noexcept override {
                                return read_control_(control);
                            }

                            bool SendControl(const Control& control) noexcept override {
                                return send_control_(control);
                            }

                            SessionResumeTransactionBeginStatus Begin(
                                const Control& request,
                                std::uint64_t& reservation_token,
                                Control& response) noexcept override {
                                const VirtualEthernetExchanger::ResumeBeginStatus status =
                                    channel_->BeginResume(transmission_, request,
                                        candidate_, Executors::GetTickCount(),
                                        reservation_token, response);
                                if (status == VirtualEthernetExchanger::ResumeBeginStatus::Reserved) {
                                    return SessionResumeTransactionBeginStatus::Accepted;
                                }
                                if (status == VirtualEthernetExchanger::ResumeBeginStatus::GenerationSync) {
                                    return SessionResumeTransactionBeginStatus::GenerationSync;
                                }
                                return SessionResumeTransactionBeginStatus::Rejected;
                            }

                            bool Commit(const Control& confirm,
                                std::uint64_t reservation_token,
                                Control& committed) noexcept override {
                                return channel_->CommitResume(transmission_, confirm,
                                    candidate_, reservation_token,
                                    Executors::GetTickCount(), committed);
                            }

                            bool Publish(
                                std::uint64_t reservation_token) noexcept override {
                                return channel_->PublishCommittedResume(transmission_,
                                    reservation_token, Executors::GetTickCount());
                            }

                            void Cancel(
                                std::uint64_t reservation_token) noexcept override {
                                channel_->CancelResume(transmission_, reservation_token);
                            }

                        private:
                            ReadResumeControl& read_control_;
                            SendResumeControl& send_control_;
                            VirtualEthernetExchangerPtr& channel_;
                            const ITransmissionPtr& transmission_;
                            const ppp::app::protocol::SessionResumeCandidateBinding& candidate_;
                        } operations(read_resume_control, send_resume_control,
                            channel, transmission, candidate);

                        const SessionResumeTransactionResult transaction =
                            RunSessionResumeEstablishTransaction(operations);
                        resumed = transaction.outcome ==
                            SessionResumeTransactionOutcome::Resumed;
                        fallback_reason = transaction.fallback_reason;
                        if (transaction.outcome ==
                            SessionResumeTransactionOutcome::PreserveSuspended) {
                            return true;
                        }
                        if (transaction.outcome ==
                            SessionResumeTransactionOutcome::Fatal) {
                            return false;
                        }
                    }

                    if (!resumed && !fresh) {
                        ppp::telemetry::Count("server.session.resume_rejected", 1);
                        if (DecideSessionResumeFallback(fallback_reason) !=
                            SessionResumeFallbackDecision::Fresh) {
                            return false;
                        }

                        ppp::app::protocol::SessionResumeControl reject;
                        reject.action = ppp::app::protocol::SessionResumeAction::Reject;
                        reject.reason = "session-unavailable";
                        if (!send_resume_control(reject)) {
                            return false;
                        }

                        VirtualEthernetExchangerPtr removed = DeleteExchanger(channel.get());
                        if (NULLPTR == removed) {
                            return false;
                        }
                        removed->Finalize();

                        channel = AddNewExchanger(transmission, session_id);
                        if (NULLPTR == channel) {
                            return false;
                        }
                        fresh = true;

                        ppp::telemetry::Gauge("server.active_sessions", (int64_t)exchangers_.size());
                        ppp::telemetry::Count("server.session.accepted", 1);
                        ppp::telemetry::Log(Level::kInfo, "server", "session accepted");
                    }
                }
                else {
                    channel = AddNewExchanger(transmission, session_id);
                    if (NULLPTR == channel) {
                        return false;
                    }
                    fresh = true;

                    ppp::telemetry::Gauge("server.active_sessions", (int64_t)exchangers_.size());
                    ppp::telemetry::Count("server.session.accepted", 1);
                    ppp::telemetry::Log(Level::kInfo, "server", "session accepted");
                }

                bool run = true;
                if (fresh) {
                    VirtualEthernetInformation fallback_information;
                    const VirtualEthernetInformation* established_information = i.get();
                    if (NULLPTR == established_information && configuration_->server.backend.empty() &&
                        IsIPv6ServerEnabled()) {
                        fallback_information.Clear();
                        fallback_information.BandwidthQoS = 0;
                        fallback_information.IncomingTraffic = std::numeric_limits<UInt64>::max();
                        fallback_information.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                        fallback_information.ExpiredTime = std::numeric_limits<UInt32>::max();
                        established_information = &fallback_information;
                    }

                    if (NULLPTR == established_information && !configuration_->server.backend.empty()) {
                        DeleteExchanger(channel.get());
                        return false;
                    }

                    if (NULLPTR != established_information) {
                        InformationEnvelope envelope = BuildInformationEnvelope(session_id, *established_information);
                        if (envelope.Extensions.AssignedIPv6Address.is_v6() && !AddIPv6Exchanger(session_id, envelope.Extensions)) {
                            RevokeIPv6Lease(session_id);
                            DeleteIPv6Exchanger(session_id);
                            envelope.Extensions.AssignedIPv6Address = boost::asio::ip::address();
                            envelope.Extensions.AssignedIPv6Gateway = boost::asio::ip::address();
                            envelope.Extensions.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                            envelope.Extensions.AssignedIPv6RoutePrefixLength = 0;
                            envelope.Extensions.AssignedIPv6Dns1 = boost::asio::ip::address();
                            envelope.Extensions.AssignedIPv6Dns2 = boost::asio::ip::address();
                            envelope.Extensions.AssignedIPv6Flags = 0;
                            envelope.Extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                            envelope.Extensions.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                        }

                        boost::asio::ip::tcp::endpoint remote_ep = transmission->GetRemoteEndPoint();
                        boost::asio::ip::address remote_addr = remote_ep.address();
                        if (!remote_addr.is_unspecified()) {
                            envelope.Extensions.ClientExitIP = remote_addr;
                        }

                        ppp::app::protocol::SessionResumeControl offer;
                        if (channel->PrepareFreshResumeOffer(transmission, offer)) {
                            envelope.Extensions.SessionResume = offer;
                        }
                        envelope.ExtendedJson = envelope.Extensions.ToJson();

                        run = channel->DoInformation(transmission, envelope, y);
                        if (run) {
                            run = VirtualEthernetInformation::Valid(
                                const_cast<VirtualEthernetInformation*>(established_information), (UInt32)time(NULL));
                        }
                    }
                }

                if (!run) {
                    DeleteExchanger(channel.get());
                    return false;
                }

                VirtualEthernetLoggerPtr logger = GetLogger();
                if (NULLPTR != logger) {
                    logger->Vpn(session_id, transmission);
                }

                const std::uint64_t generation = channel->GetCarrierGeneration();
                run = channel->Run(transmission, y);
                const ppp::diagnostics::ErrorCode run_error = ppp::diagnostics::GetLastErrorCode();
                VirtualEthernetExchanger::CarrierStopResult stop =
                    channel->OnCarrierStopped(transmission, generation, run_error, Executors::GetTickCount());
                if (stop == VirtualEthernetExchanger::CarrierStopResult::Terminal) {
                    DeleteExchanger(channel.get());
                    return run;
                }
                return true;
            }

            /**
             * @brief Creates a firewall instance for traffic filtering.
             * @return Shared firewall pointer.
             */
            VirtualEthernetSwitcher::FirewallPtr VirtualEthernetSwitcher::NewFirewall() noexcept {
                return make_shared_object<Firewall>();
            }

            /**
             * @brief Attaches an auxiliary transport to an existing session exchanger.
             * @param transmission Transport to attach.
             * @param session_id Session identifier.
             * @param y Coroutine context.
             * @return Internal status code describing run/scheduler ownership.
             */
            int VirtualEthernetSwitcher::Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                if (y) {
                    VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                    if (NULLPTR == exchanger) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                        return STATUS_ERROR;
                    }

                    ITransmissionPtr owner = exchanger->GetTransmission();
                    if (NULLPTR != owner) {
                        std::shared_ptr<ITransmissionStatistics> left = owner->Statistics;
                        std::shared_ptr<ITransmissionStatistics> reft = transmission->Statistics;
                        if (left != reft) {
                            if (NULLPTR != reft) {
                                left->IncomingTraffic += reft->IncomingTraffic;
                                left->OutgoingTraffic += reft->OutgoingTraffic;
                            }

                            transmission->Statistics = left;
                        }
                    }
                }

                auto self = shared_from_this();
                /**
                 * @brief Creates and runs transient TCP/IP connection wrappers.
                 */
                auto run =
                    [self, this](const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                        VirtualEthernetNetworkTcpipConnectionPtr connection = AddNewConnection(transmission, session_id);
                        if (NULLPTR == connection) {
                            return -1;
                        }
                        elif(connection->Run(y)) {
                            if (connection->IsMux()) {
                                SynchronizedObjectScope scope(syncobj_);
                                if (Dictionary::RemoveValueByKey(connections_, (void*)connection.get())) {
                                    return 0;
                                }
                                else {
                                    return -1; // The rear check, which is beyond the expected design, is roughly possible that the switch is being released.
                                }
                            }

                            return 1;
                        }
                        else {
                            return -1;
                        }
                    };

                // Transfer the current link to the scheduler for processing, if the transfer succeeds.
                if (transmission->ShiftToScheduler()) {
                    ppp::threading::Executors::ContextPtr scheduler = transmission->GetContext();
                    ppp::threading::Executors::StrandPtr strand = transmission->GetStrand();
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;

                    return YieldContext::Spawn(allocator.get(), *scheduler, strand.get(),
                        [scheduler, strand, run, transmission, session_id](YieldContext& y) noexcept {
                            int status = run(transmission, session_id, y);
                            if (status != 0) {
                                transmission->Dispose();
                            }
                        }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
                }
                else {
                    int status = run(transmission, session_id, y);
                    if (status < 0) {
                        return STATUS_ERROR;
                    }
                    elif(status > 0) {
                        return STATUS_RUNING;
                    }
                    else {
                        return STATUS_RUNNING_SWAP;
                    }
                }
            }

            /**
             * @brief Creates and registers a temporary network TCP/IP connection object.
             * @param transmission Incoming transport channel.
             * @param session_id Session identifier.
             * @return Registered connection object or null.
             */
            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                std::shared_ptr<VirtualEthernetNetworkTcpipConnection> connection = NewConnection(transmission, session_id);
                if (NULLPTR == connection) {
                    return NULLPTR;
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULLPTR;
                    }

                    if (Dictionary::TryAdd(connections_, connection.get(), connection)) {
                        return connection;
                    }
                }

                connection->Dispose();
                return NULLPTR;
            }

            /**
             * @brief Removes one exchanger by pointer identity and disposes it.
             * @param exchanger Raw exchanger pointer key.
             * @return Detached exchanger shared pointer, already disposed when non-null.
             */
            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept {
                VirtualEthernetExchangerPtr channel;
                if (NULLPTR != exchanger) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (auto tail = exchangers_.find(exchanger->GetId()); tail != exchangers_.end()) {
                        const VirtualEthernetExchangerPtr& p = tail->second;
                        if (p.get() == exchanger) {
                            channel = std::move(tail->second);
                            exchangers_.erase(tail);
                            ppp::telemetry::Gauge("server.active_sessions", (int64_t)exchangers_.size());
                            ppp::telemetry::Gauge("server.exchanger_count", (int64_t)exchangers_.size());
                        }
                    }
                }

                if (channel) {
                    DeleteIPv4Lease(channel->GetId());
                    ppp::telemetry::Count("server.exchanger.remove", 1);
                    ppp::telemetry::Log(Level::kInfo, "server", "exchanger removed");
                    channel->Dispose();
                }
                return channel;
            }

            /**
             * @brief Allocates a network connection wrapper for one accepted transport.
             * @param transmission Accepted transport.
             * @param session_id Session identifier.
             * @return New connection wrapper or null.
             */
            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetNetworkTcpipConnection>(self, session_id, transmission);
            }

            /**
             * @brief Creates a packet/session logger according to configuration.
             * @return Logger instance when configured and valid; otherwise null.
             */
            VirtualEthernetSwitcher::VirtualEthernetLoggerPtr VirtualEthernetSwitcher::NewLogger() noexcept {
                ppp::string& log = configuration_->server.log;
                if (log.empty()) {
                    return NULLPTR;
                }

                VirtualEthernetLoggerPtr logger = make_shared_object<VirtualEthernetLogger>(context_, log);
                if (NULLPTR == logger) {
                    return NULLPTR;
                }

                if (logger->Valid()) {
                    return logger;
                }

                IDisposable::Dispose(logger);
                return NULLPTR;
            }

            /**
             * @brief Creates and binds all configured TCP acceptors.
             * @return true if at least one acceptor opens successfully.
             */
            bool VirtualEthernetSwitcher::CreateAllAcceptors() noexcept {
                if (disposed_) {
                    return false;
                }

                int acceptor_ports[NetworkAcceptorCategories_Max];
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[i];
                    if (NULLPTR != acceptor) {
                        return false;
                    }

                    acceptor_ports[i] = IPEndPoint::MinPort;
                }

                boost::asio::ip::address interface_ips[] = { GetInterfaceIP(), boost::asio::ip::address_v6::any(), boost::asio::ip::address_v4::any() };
                acceptor_ports[NetworkAcceptorCategories_Tcpip] = configuration_->tcp.listen.port;
                acceptor_ports[NetworkAcceptorCategories_WebSocket] = configuration_->websocket.listen.ws;
                acceptor_ports[NetworkAcceptorCategories_WebSocketSSL] = configuration_->websocket.listen.wss;
                acceptor_ports[NetworkAcceptorCategories_CDN1] = configuration_->cdn[0];
                acceptor_ports[NetworkAcceptorCategories_CDN2] = configuration_->cdn[1];

                bool bany = false;
                auto& cfg = configuration_->tcp;
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    int port = acceptor_ports[i];
                    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                        continue;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(*context_);
                    if (NULLPTR == acceptor) {
                        return false;
                    }

                    for (boost::asio::ip::address& interface_ip : interface_ips) {
                        if (Socket::OpenAcceptor(*acceptor, interface_ip, port, cfg.backlog, cfg.fast_open, cfg.turbo)) {
                            Socket::SetWindowSizeIfNotZero(acceptor->native_handle(), cfg.cwnd, cfg.rwnd);
                            bany |= true;
                            acceptors_[i] = std::move(acceptor);
                            break;
                        }
                        elif(!Socket::Closesocket(*acceptor)) {
                            return false;
                        }
                    }
                }

                return bany;
            }

            /**
             * @brief Opens switch subsystems and prepares runtime state.
             * @param firewall_rules Firewall rule file path.
             * @return true when all required subsystems initialize successfully.
             *
             * @note The syncobj_ lock is held only for the guard checks and
             *       collection reset.  The heavy subsystem-initialization calls
             *       (socket creation, I/O, ioctl, managed-server TLS handshake)
             *       execute without the lock to prevent blocking incoming connection
             *       handlers for hundreds of milliseconds during startup.
             */
            bool VirtualEthernetSwitcher::Open(const ppp::string& firewall_rules) noexcept {
                // Narrow critical section: guard check + collection reset only.
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return false;
                    }

                    if (timeout_) {
                        return false;
                    }

                    ipv6s_.clear();
                    ipv6_requests_.clear();
                    ipv6_leases_.clear();
                    p2p_peers_.clear();
                    p2p_virtual_ips_.clear();
                    peer_prefix_gateways_.clear();
                    peer_prefix_rib_.Clear();
                }  // Release syncobj_ before heavy subsystem initialization.

                bool ok = CreateAllAcceptors() &&
                    CreateAlwaysTimeout() &&
                    CreateFirewall(firewall_rules) &&
                    OpenManagedServerIfNeed() &&
                    OpenIPv6TransitIfNeed() &&
                    OpenNamespaceCacheIfNeed() &&
                    OpenDatagramSocket() &&
                    OpenIPv6NeighborProxyIfNeed();

                // Configure the IPv4 lease pool from configuration.
                // Failure is non-fatal: log and continue so the server
                // still operates without IPv4 pool assignment.
                if (configuration_->server.ipv4_pool.configured) {
                    boost::system::error_code ec;
                    boost::asio::ip::address network_addr = StringToAddress(configuration_->server.ipv4_pool.network, ec);
                    if (!ec && network_addr.is_v4()) {
                        ec.clear();
                        boost::asio::ip::address mask_addr = StringToAddress(configuration_->server.ipv4_pool.mask, ec);
                        if (!ec && mask_addr.is_v4()) {
                            if (!ipv4_pool_.Configure(network_addr.to_v4(), mask_addr.to_v4())) {
                                ppp::telemetry::Log(Level::kInfo, "server", "ipv4 pool configure failed");
                                ppp::telemetry::Count("server.ipv4.pool.configure_failed", 1);
                            }
                            else {
                                ppp::telemetry::Log(Level::kInfo, "server", "ipv4 pool configured");
                            }
                        }
                        else {
                            ppp::telemetry::Log(Level::kInfo, "server", "ipv4 pool mask invalid");
                            ppp::telemetry::Count("server.ipv4.pool.mask_invalid", 1);
                        }
                    }
                    else {
                        ppp::telemetry::Log(Level::kInfo, "server", "ipv4 pool network invalid");
                        ppp::telemetry::Count("server.ipv4.pool.network_invalid", 1);
                    }
                }

                // Update IPv6 data-plane runtime state atomically so all cross-thread
                // readers (GetIPv6RuntimeState, OnTick, inet6: console field) observe a
                // consistent view without holding syncobj_.
                {
                    bool ipv6_enabled = IsIPv6ServerEnabled();
                    if (!ipv6_enabled) {
                        // IPv6 is not configured; plane is off.
                        ipv6_runtime_state_.store(0, std::memory_order_release);
                        ipv6_runtime_cause_.store(0, std::memory_order_release);
                    }
                    elif (ok) {
                        // Plane came up successfully; record nat66 (1) or gua (2).
                        const auto& ipv6cfg = configuration_->server.ipv6;
                        uint8_t state = (ipv6cfg.mode == AppConfiguration::IPv6Mode_Gua) ? 2 : 1;
                        ipv6_runtime_state_.store(state, std::memory_order_release);
                        ipv6_runtime_cause_.store(0, std::memory_order_release);
                    }
                    else {
                        // Plane attempted but failed; capture the diagnostic cause.
                        ipv6_runtime_state_.store(3, std::memory_order_release);
                        uint32_t cause = static_cast<uint32_t>(ppp::diagnostics::GetLastErrorCode());
                        ipv6_runtime_cause_.store(cause, std::memory_order_release);
                    }
                }

                if (ok) {
                    OpenLogger();
                    ppp::telemetry::Log(Level::kInfo, "server", "server opened");
                }

                return ok;
            }

            /**
             * @brief Initializes DNS namespace cache when TTL is enabled.
             * @return true if cache setup succeeds or is not required.
             */
            bool VirtualEthernetSwitcher::OpenNamespaceCacheIfNeed() noexcept {
                int ttl = configuration_->udp.dns.ttl;
                if (configuration_->udp.dns.cache && ttl > 0) {
                    VirtualEthernetNamespaceCachePtr cache = NewNamespaceCache(ttl);
                    if (NULLPTR == cache) {
                        return false;
                    }

                    namespace_cache_ = std::move(cache);
                }

                return true;
            }

            /**
             * @brief Forwards an IPv6 packet from server/client side to transit TAP.
             * @param packet Packet buffer.
             * @param packet_length Packet length in bytes.
             * @return true when packet is emitted to TAP.
             */
            bool VirtualEthernetSwitcher::SendIPv6TransitPacket(Byte* packet, int packet_length) noexcept {
                ITapPtr tap;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }
                    tap = ipv6_transit_tap_;
                }
                if (NULLPTR == tap || NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }

                Int128 session_id = 0;
                VirtualEthernetLoggerPtr logger = GetLogger();

#if defined(_LINUX)
                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    VirtualEthernetExchangerPtr exchanger = FindIPv6Exchanger(destination);
                    if (NULLPTR != exchanger) {
                        session_id = exchanger->GetId();
                        int affinity_fd = exchanger->GetPreferredTunFd();
                        if (affinity_fd >= 0) {
                            if (NULLPTR != logger) {
                                logger->Packet(session_id, packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToUplink);
                            }

                            int last_fd = ppp::tap::TapLinux::SetLastHandle(affinity_fd);
                            bool ok = tap->Output(packet, packet_length);
                            ppp::tap::TapLinux::SetLastHandle(last_fd);
                            return ok;
                        }
                    }
                }
#endif

                if (NULLPTR != logger) {
                    logger->Packet(session_id, packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToUplink);
                }

                return tap->Output(packet, packet_length);
            }

            /**
             * @brief Encapsulates and sends an IPv6 packet to a client session.
             * @param transmission Destination transport.
             * @param session_id Session identifier for logging.
             * @param packet IPv6 packet bytes.
             * @param packet_length Packet length in bytes.
             * @return true if write is queued successfully.
             */
            bool VirtualEthernetSwitcher::SendIPv6PacketToClient(const ITransmissionPtr& transmission, const Int128& session_id, Byte* packet, int packet_length) noexcept {
                if (NULLPTR == transmission || NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = GetLogger();
                if (NULLPTR != logger) {
                    logger->Packet(session_id, packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToClient);
                }

                ppp::io::MemoryStream ms;
                if (!ms.WriteByte((Byte)app::protocol::VirtualEthernetLinklayer::PacketAction_NAT)) {
                    return false;
                }

                if (!ms.Write(packet, 0, packet_length)) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                return transmission->Write(buffer.get(), ms.GetPosition(),
                    [transmission](bool ok) noexcept {
                        if (!ok) {
                            transmission->Dispose();
                        }
                    });
            }

            /**
             * @brief Handles IPv6 packets received from transit TAP toward clients.
             * @param packet Packet buffer.
             * @param packet_length Packet length in bytes.
             * @return true when packet is accepted and forwarded to session.
             */
            bool VirtualEthernetSwitcher::ReceiveIPv6TransitPacket(Byte* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                    return false;
                }

                VirtualEthernetExchangerPtr exchanger = FindIPv6Exchanger(destination);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                boost::system::error_code prefix_ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, prefix_ec);
                if (!prefix_ec && prefix.is_v6()) {
                    int allowed_prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, ipv6.prefix_length));
                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    if (!ipv6_transit_policy::IsPacketAllowed(
                        source,
                        destination,
                        prefix.to_v6(),
                        allowed_prefix_length,
                        &transit_gateway,
                        true)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                        return false;
                    }
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                    return false;
                }

#if defined(_LINUX)
                exchanger->SetPreferredTunFd(ppp::tap::TapLinux::GetLastHandle());
#endif

                VirtualEthernetLoggerPtr logger = GetLogger();
                if (NULLPTR != logger) {
                    logger->Packet(exchanger->GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::UplinkToServer);
                }

                app::protocol::ClampTcpMssIPv6(packet, packet_length, app::protocol::ComputeDynamicTcpMss(false, app::protocol::kVEthernetTunnelOverhead));

                if (!SendIPv6PacketToClient(transmission, exchanger->GetId(), packet, packet_length)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                    return false;
                }
                return true;
            }

            /**
             * @brief Opens and configures Linux TAP used for IPv6 transit dataplane.
             * @return true when transit TAP is ready or not required.
             */
            bool VirtualEthernetSwitcher::OpenIPv6TransitIfNeed() noexcept {
#if defined(_LINUX)
                SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }
                    if (NULLPTR != ipv6_transit_tap_) {
                        return true;
                    }
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                bool enable_transit = IsIPv6ServerEnabled() && (mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua);
                if (!enable_transit) {
                    return true;
                }

                boost::system::error_code ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6CidrInvalid);
                    return false;
                }

                boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                boost::asio::ip::address_v6 transit = prefix.to_v6();
                if (transit.is_unspecified()) {
                    boost::asio::ip::address_v6::bytes_type bytes = {};
                    bytes[0] = 0xfd;
                    bytes[1] = 0x42;
                    bytes[2] = 0x42;
                    bytes[3] = 0x42;
                    bytes[4] = 0x42;
                    bytes[15] = 1;
                    transit = boost::asio::ip::address_v6(bytes);
                }

                if (transit_gateway.is_v6()) {
                    transit = transit_gateway.to_v6();
                }
                else {
                    boost::asio::ip::address_v6 derived_transit;
                    if (!TryGetFirstHostIPv6(transit, ipv6.prefix_length, derived_transit)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6GatewayNotReachable);
                        return false;
                    }

                    transit = derived_transit;
                }

                std::string transit_std = transit.to_string();
                ppp::string transit_ip(transit_std.data(), transit_std.size());
                int prefix_length = mode == AppConfiguration::IPv6Mode_Gua ? ppp::ipv6::IPv6_MAX_PREFIX_LENGTH : std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, ipv6.prefix_length));

                ppp::vector<ppp::string> no_dns;
                ppp::string tun_name = tun_name_;
                if (tun_name.empty()) {
                    tun_name = BOOST_BEAST_VERSION_STRING;
                }

                ITapPtr tap = ppp::tap::ITap::Create(context_, tun_name, "169.254.254.1", "169.254.254.2", "255.255.255.252", false, false, no_dns);
                if (NULLPTR == tap || !tap->Open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    return false;
                }

                bool address_ok = ppp::tap::TapLinux::SetIPv6Address(tap->GetId(), transit_ip, prefix_length);
                if (!address_ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    tap->Dispose();
                    return false;
                }


                tap->SetPacketInput(
                    [self = shared_from_this()](ppp::tap::ITap* sender, ppp::tap::ITap::PacketInputEventArgs& e) noexcept -> bool {
                        if (NULLPTR == sender || NULLPTR == e.Packet || e.PacketLength < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                            return false;
                        }

                        auto switcher = std::dynamic_pointer_cast<VirtualEthernetSwitcher>(self);
                        if (NULLPTR == switcher) {
                            return false;
                        }

                        return switcher->ReceiveIPv6TransitPacket(reinterpret_cast<Byte*>(e.Packet), e.PacketLength);
                    });

                if (!OpenIPv6TransitSsmtIfNeed(tap)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    tap->Dispose();
                    return false;
                }

                bool published = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (!disposed_.load(std::memory_order_acquire) && NULLPTR == ipv6_transit_tap_) {
                        ipv6_transit_tap_ = tap;
                        published = true;
                    }
                }
                if (!published) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                    tap->Dispose();
                    return false;
                }
#else
                if (IsIPv6ServerEnabled()) {
                }
#endif
                return true;
            }

            /**
             * @brief Refreshes uplink neighbor-proxy interface and replays active entries.
             * @return true when refresh succeeds; otherwise false.
             */
            bool VirtualEthernetSwitcher::RefreshIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled() || ipv6.mode != AppConfiguration::IPv6Mode_Gua) {
                    return true;
                }

                ppp::string uplink_name = ResolvePreferredIPv6UplinkInterface(preferred_nic_);

                if (uplink_name.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyEnableFailed);
                    return false;
                }

                ppp::string old_ifname;
                bool old_owned = false;
                ppp::vector<std::pair<Int128, boost::asio::ip::address>> replay_entries;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    old_ifname = ipv6_neighbor_proxy_ifname_;
                    old_owned  = ipv6_neighbor_proxy_owned_;

                    // Skip the sysctl + popen work when the uplink interface has not changed
                    // and the proxy was already applied.  This avoids blocking the IO thread
                    // with a shell fork on every OnTick interval (~1 s) when nothing has
                    // changed.  The interface-migration path (old_ifname != uplink_name)
                    // intentionally bypasses this guard and continues normally.
                    if (ipv6_ndp_proxy_applied_ && old_ifname == uplink_name) {
                        return true;
                    }

                    replay_entries.reserve(ipv6s_.size());
                    for (const auto& kv : ipv6s_) {
                        if (!kv.second) {
                            continue;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address ip = StringToAddress(kv.first, ec);
                        if (ec || !ip.is_v6()) {
                            continue;
                        }

                        replay_entries.emplace_back(kv.second->GetId(), ip);
                    }
                }

                bool proxy_enabled = false;
                bool query_ok = ppp::tap::TapLinux::QueryIPv6NeighborProxy(uplink_name, proxy_enabled);
                if (!ppp::tap::TapLinux::EnableIPv6NeighborProxy(uplink_name)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NeighborProxyEnableFailed);
                    return false;
                }

                if (!old_ifname.empty() && old_ifname != uplink_name) {
                    for (const auto& entry : replay_entries) {
                        DeleteIPv6NeighborProxy(old_ifname, entry.second);
                    }

                    if (old_owned) {
                        ppp::tap::TapLinux::DisableIPv6NeighborProxy(old_ifname);
                    }
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    ipv6_neighbor_proxy_ifname_ = uplink_name;
                    ipv6_neighbor_proxy_owned_  = old_ifname == uplink_name ? old_owned : (query_ok ? !proxy_enabled : false);
                    ipv6_ndp_proxy_applied_     = true; ///< Mark sysctl as applied for this uplink.
                }

                ppp::vector<Int128> broken_sessions;
                for (const auto& entry : replay_entries) {
                    const boost::asio::ip::address& ip = entry.second;
                    bool route_ok = AddIPv6TransitRoute(ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
                    bool proxy_ok = AddIPv6NeighborProxy(ip);
                    if (!route_ok || !proxy_ok) {
                        broken_sessions.emplace_back(entry.first);
                    }
                }

                for (const Int128& session_id : broken_sessions) {
                    RevokeIPv6Lease(session_id);
                    DeleteIPv6Exchanger(session_id);
                }

                if (!broken_sessions.empty()) {
                    return false;
                }
#endif
                return true;
            }

            /**
             * @brief Starts optional SSMT worker contexts for transit TAP queues.
             * @param tap Transit TAP instance.
             * @return true when SSMT is ready or not required.
             */
            bool VirtualEthernetSwitcher::OpenIPv6TransitSsmtIfNeed(const ITapPtr& tap) noexcept {
#if defined(_LINUX)
                if (tun_ssmt_ <= 0 || !tun_ssmt_mq_) {
                    return true;
                }

                auto linux_tap = std::dynamic_pointer_cast<ppp::tap::TapLinux>(tap);
                if (NULLPTR == linux_tap) {
                    return false;
                }

                ppp::vector<std::shared_ptr<boost::asio::io_context>> contexts;
                contexts.reserve(tun_ssmt_);
                for (int i = 0; i < tun_ssmt_; ++i) {
                    std::shared_ptr<boost::asio::io_context> worker = make_shared_object<boost::asio::io_context>();
                    if (NULLPTR == worker) {
                        for (auto& context : contexts) {
                            context->stop();
                        }
                        return false;
                    }

                    std::thread ssmt_thread(
                        [worker]() noexcept {
                            if (ppp::RT) {
                                SetThreadPriorityToMaxLevel();
                            }

                            SetThreadName("srv-ssmt");
                            auto work = boost::asio::make_work_guard(*worker);
                            worker->restart();
                            try
                            {
                                worker->run();
                            }
                            catch (...)
                            {
                                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "server", "linux ssmt worker terminated with exception");
                            }
                        });
                    ssmt_thread.detach();

                    if (!linux_tap->Ssmt(worker)) {
                        worker->stop();
                        for (auto& context : contexts) {
                            context->stop();
                        }
                        return false;
                    }

                    contexts.emplace_back(worker);
                }

                SynchronizedObjectScope scope(syncobj_);
                ipv6_transit_ssmt_contexts_ = std::move(contexts);
#else
#endif
                return true;
            }

            /**
             * @brief Stops all previously created IPv6 transit SSMT worker contexts.
             */
            void VirtualEthernetSwitcher::CloseIPv6TransitSsmtContexts() noexcept {
#if defined(_LINUX)
                ppp::vector<std::shared_ptr<boost::asio::io_context>> contexts;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    contexts = std::move(ipv6_transit_ssmt_contexts_);
                    ipv6_transit_ssmt_contexts_.clear();
                }

                for (auto& context : contexts) {
                    context->stop();
                }
#endif
            }

            /**
             * @brief Creates and stores the runtime logger instance.
             * @return true when logger exists and is ready.
             */
            bool VirtualEthernetSwitcher::OpenLogger() noexcept {
                VirtualEthernetLoggerPtr logger = NewLogger();
                if (NULLPTR == logger) {
                    return false;
                }

                logger_ = std::move(logger);
                return true;
            }

            /**
             * @brief Opens UDP socket used for static-echo transport ingress.
             * @return true when socket is ready or UDP listener is disabled.
             */
            bool VirtualEthernetSwitcher::OpenDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                int bind_port = configuration_->udp.listen.port;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return true;
                }

                boost::asio::ip::address interface_ip = GetInterfaceIP();
                boost::asio::ip::udp::endpoint bind_endpoint(interface_ip, bind_port);

                bool ok = VirtualEthernetPacket::OpenDatagramSocket(static_echo_socket_, interface_ip, bind_port, bind_endpoint);
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(static_echo_socket_.native_handle(), configuration_->udp.cwnd, configuration_->udp.rwnd);
                }

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionGetFailed);
                    return false;
                }

                static_echo_bind_port_ = localEP.port();
                ppp::telemetry::Log(Level::kInfo, "server", "static echo socket opened");
                return LoopbackDatagramSocket();
            }

            /**
             * @brief Continues asynchronous UDP receive loop for static-echo packets.
             * @return true when receive loop is armed.
             */
            bool VirtualEthernetSwitcher::LoopbackDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = static_echo_socket_.is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                static_echo_socket_.async_receive_from(boost::asio::buffer(static_echo_buffers_.get(), PPP_BUFFER_SIZE), static_echo_source_ep_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::operation_canceled) {
                            return false;
                        }

                        if (disposed_) {
                            return false;
                        }

                        if (ec == boost::system::errc::success && sz > 0) {
                            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                            VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;

                            std::shared_ptr<VirtualEthernetPacket> packet =
                                VirtualEthernetPacket::Unpack(configuration_, allocator,
                                    [this, &allocated_context](int session_id) noexcept {
                                        return StaticEchoSelectCiphertext(session_id, true, allocated_context);
                                    },
                                    [this, &allocated_context](int session_id) noexcept {
                                        return StaticEchoSelectCiphertext(session_id, false, allocated_context);
                                    }, static_echo_buffers_.get(), sz);
                            if (NULLPTR != allocated_context && NULLPTR != packet) {
                                StaticEchoPacketInput(allocated_context, allocator, packet, sz, static_echo_source_ep_);
                            }
                        }

                        return LoopbackDatagramSocket();
                    });
                return true;
            }

            /**
             * @brief Resolves protocol or transport ciphertext by static-echo allocation id.
             * @param allocated_id Allocation identifier.
             * @param protocol_or_transport true for protocol key; false for transport key.
             * @param allocated_context Receives allocation context if found.
             * @return Ciphertext pointer for requested channel or null.
             */
            std::shared_ptr<ppp::cryptography::Ciphertext> VirtualEthernetSwitcher::StaticEchoSelectCiphertext(int allocated_id, bool protocol_or_transport, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept {
                if (NULLPTR == allocated_context && !StaticEchoQuery(allocated_id, allocated_context)) {
                    return NULLPTR;
                }

                return protocol_or_transport ? allocated_context->protocol : allocated_context->transport;
            }

            /**
             * @brief Processes one decoded static-echo packet and dispatches by protocol.
             * @param allocated_context Allocation metadata for packet owner.
             * @param allocator Buffer allocator used by packet pipeline.
             * @param packet Decoded virtual ethernet packet.
             * @param packet_length Raw datagram length in bytes.
             * @param sourceEP Source UDP endpoint.
             * @return true when packet is accepted by destination handler.
             */
            bool VirtualEthernetSwitcher::StaticEchoPacketInput(const VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                VirtualEthernetExchangerPtr exchanger;
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP || packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (!ppp::collections::Dictionary::TryGetValue(exchangers_, allocated_context->guid, exchanger)) {
                        return false;
                    }

                    if (exchanger->IsDisposed()) {
                        return false;
                    }
                }
                else {
                    return false;
                }

                auto statistics = exchanger->GetStatistics();
                if (NULLPTR != statistics) {
                    statistics->AddIncomingTraffic(packet_length);
                }

                exchanger->static_echo_source_ep_ = sourceEP;
                ObserveP2PUdpEndpoint(exchanger, packet->SourceIP, sourceEP);
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return exchanger->StaticEchoSendToDestination(packet);
                }
                elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return exchanger->StaticEchoEchoToDestination(packet, sourceEP);
                }
                else {
                    return true;
                }
            }

            /**
             * @brief Releases and returns a static-echo allocation entry by id.
             * @param allocated_id Allocation identifier.
             * @return Removed allocation context or null when not found.
             */
            VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContextPtr VirtualEthernetSwitcher::StaticEchoUnallocated(int allocated_id) noexcept {
                if (allocated_id < 1) {
                    return NULLPTR;
                }

                VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    if (Dictionary::TryRemove(static_echo_allocateds_, allocated_id, allocated_context)) {
                        ppp::telemetry::Log(Level::kInfo, "server", "static echo unallocated");
                        return allocated_context;
                    }

                    return NULLPTR;
                }
            }

            /**
             * @brief Queries an existing static-echo allocation entry.
             * @param allocated_id Allocation identifier.
             * @param allocated_context Receives allocation context on success.
             * @return true when a valid allocation exists.
             */
            bool VirtualEthernetSwitcher::StaticEchoQuery(int allocated_id, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept {
                if (allocated_id < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (!Dictionary::TryGetValue(static_echo_allocateds_, allocated_id, allocated_context)) {
                    return false;
                }

                if (NULLPTR != allocated_context) {
                    return true;
                }

                Dictionary::TryRemove(static_echo_allocateds_, allocated_id);
                return false;
            }

            /**
             * @brief Creates or reuses a static-echo allocation for a session.
             * @param session_id Session identifier.
             * @param allocated_id In/out allocation id; zero requests new allocation.
             * @param remote_port Receives remote UDP port exposed to client.
             * @return Allocation context on success; otherwise null.
             */
            VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContextPtr VirtualEthernetSwitcher::StaticEchoAllocated(Int128 session_id, int& allocated_id, int& remote_port) noexcept {
                remote_port = IPEndPoint::MinPort;
                if (session_id == 0) {
                    return NULLPTR;
                }

                if (disposed_) {
                    return NULLPTR;
                }

                int bind_port = static_echo_bind_port_;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return NULLPTR;
                }

                // --- Fast O(1) lookup path: take the lock once and return. ---
                if (allocated_id != 0) {
                    VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;
                    SynchronizedObjectScope scope(syncobj_);
                    if (!Dictionary::TryGetValue(static_echo_allocateds_, allocated_id, allocated_context)) {
                        return NULLPTR;
                    }

                    remote_port = bind_port;
                    return allocated_context;
                }

                // --- Allocation path (two-phase to minimise lock hold time). ---
                //
                // Phase 1 (outside lock): allocate the context object and generate a
                //   stable FSID.  Construction and GUID generation are the expensive
                //   work; keeping them outside syncobj_ means contending threads do
                //   not block each other during object creation.
                //
                // Phase 2 (short critical section, O(1) per attempt): check that the
                //   candidate ID is still free, finalise the context fields that depend
                //   on the concrete ID, then insert into the map.  If another thread
                //   grabbed the same random ID between Phase 1 and Phase 2 (rare), we
                //   simply pick a new candidate and retry — no long loop inside the lock.
                //
                // kMaxAllocationAttempts bounds the total retries.  With a 16-bit ID
                // space and typical occupancy well below 50 %, the probability of 64
                // consecutive collisions is astronomically small.
                static constexpr int kMaxAllocationAttempts = 64;

                VirtualEthernetStaticEchoAllocatedContextPtr allocated_context =
                    make_shared_object<VirtualEthernetStaticEchoAllocatedContext>();
                if (NULLPTR == allocated_context) {
                    return NULLPTR;
                }

                Int128 fsid = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(GuidGenerate());
                allocated_context->guid = session_id;
                allocated_context->fsid = fsid;

                for (int attempt = 0; attempt < kMaxAllocationAttempts; attempt++) {
                    int generate_id = abs(RandomNext());
                    if (generate_id < 1) {
                        continue;
                    }

                    // Short critical section: O(1) — one map probe + one map insert.
                    SynchronizedObjectScope scope(syncobj_);
                    if (Dictionary::ContainsKey(static_echo_allocateds_, generate_id)) {
                        continue; // ID taken by a concurrent thread; try a new candidate.
                    }

                    // Finalise the fields that depend on the concrete ID while the lock
                    // is held, so the inserted context is always fully initialised.
                    allocated_context->myid = generate_id;
                    VirtualEthernetPacket::Ciphertext(configuration_, session_id, fsid, generate_id,
                        allocated_context->protocol, allocated_context->transport);

                    if (Dictionary::TryAdd(static_echo_allocateds_, generate_id, allocated_context)) {
                        remote_port  = bind_port;
                        allocated_id = generate_id;
                        ppp::telemetry::Log(Level::kInfo, "server", "static echo allocated");
                        return allocated_context;
                    }
                }

                return NULLPTR;
            }

            /**
             * @brief Initializes managed-server integration when backend is configured.
             * @return true if managed mode is connected or not required.
             */
            bool VirtualEthernetSwitcher::OpenManagedServerIfNeed() noexcept {
                if (configuration_->server.node < 1 || configuration_->server.backend.empty()) {
                    return true;
                }

                if (disposed_) {
                    return false;
                }

                VirtualEthernetManagedServerPtr server = NewManagedServer();
                if (NULLPTR == server) {
                    return false;
                }

                auto self = shared_from_this();
                return server->TryVerifyUriAsync(configuration_->server.backend,
                    [self, this, server](bool ok) noexcept {
                        if (ok) {
                            // ConnectToManagedServer performs TLS/TCP handshake — potentially
                            // long-running.  Call it outside the lock to avoid holding syncobj_
                            // across a blocking network operation.
                            ok = server->ConnectToManagedServer(configuration_->server.backend);
                        }

                        if (ok) {
                            // Only the assignment of managed_server_ requires the lock.
                            SynchronizedObjectScope scope(syncobj_);
                            if (disposed_) {
                                ok = false;
                            }
                            else {
                                managed_server_ = server;
                            }
                        }

                        if (!ok) {
                            server->Dispose();
                        }
                    });
            }

            /**
             * @brief Creates a transmission object for an accepted socket category.
             * @param categories Listener category.
             * @param context I/O context.
             * @param socket Accepted TCP socket.
             * @return Constructed transmission instance or null.
             */
            template <typename TTransmission>
            typename std::enable_if<std::is_base_of<VirtualEthernetSwitcher::ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>>::type
            VirtualEthernetSwitcher::NewWebsocketTransmission(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                const ppp::string& host = configuration_->websocket.host;
                const ppp::string& path = configuration_->websocket.path;

                ppp::threading::Executors::StrandPtr strand;
                auto transmission = make_shared_object<TTransmission>(context, strand, socket, configuration_);
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                if (!host.empty() && !path.empty()) {
                    transmission->Host = host;
                    transmission->Path = path;
                }
                return transmission;
            }

            VirtualEthernetSwitcher::ITransmissionPtr VirtualEthernetSwitcher::Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                if (NULLPTR == context || NULLPTR == socket) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::transmissions::ITransmission> transmission;
                if (categories == NetworkAcceptorCategories_Tcpip) {
                    ppp::threading::Executors::StrandPtr strand;
                    transmission = make_shared_object<ppp::transmissions::ITcpipTransmission>(
                        context,
                        strand,
                        socket,
                        configuration_,
                        ppp::transmissions::TcpTransmissionRole::Server);
                }
                elif(categories == NetworkAcceptorCategories_WebSocket) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::IWebsocketTransmission>(context, socket);
                }
                elif(categories == NetworkAcceptorCategories_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::ISslWebsocketTransmission>(context, socket);
                }

                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                boost::system::error_code remote_endpoint_error;
                const auto remote_endpoint = socket->remote_endpoint(remote_endpoint_error);
                if (remote_endpoint_error || remote_endpoint.address().is_loopback()) {
                    transmission->MarkServerLoopbackIngress();
                }

                transmission->Statistics = NewStatistics();
                return transmission;
            }

            /**
             * @brief Posts asynchronous finalization on switch context.
             */
            void VirtualEthernetSwitcher::Dispose() noexcept {
                Dispose(ppp::function<void()>());
            }

            void VirtualEthernetSwitcher::Dispose(
                ppp::function<void()> completion) noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::dispatch(*context,
                    [self, this, completion = std::move(completion)]() mutable noexcept {
                        Finalize(std::move(completion));
                    });
            }

            /**
             * @brief Indicates whether switcher has entered disposed state.
             * @return true after finalization begins.
             */
            bool VirtualEthernetSwitcher::IsDisposed() noexcept {
                return disposed_.load(std::memory_order_relaxed);
            }

            /**
             * @brief Allocates a DNS namespace cache for positive TTL values.
             * @param ttl Cache TTL in seconds.
             * @return Cache instance or null for invalid TTL/allocation failure.
             */
            VirtualEthernetSwitcher::VirtualEthernetNamespaceCachePtr VirtualEthernetSwitcher::NewNamespaceCache(int ttl) noexcept {
                if (ttl < 1) {
                    return NULLPTR;
                }

                return make_shared_object<VirtualEthernetNamespaceCache>(ttl);
            }

            /**
             * @brief Creates a statistics object optionally chained to global totals.
             * @return Shared statistics collector.
             */
            VirtualEthernetSwitcher::ITransmissionStatisticsPtr VirtualEthernetSwitcher::NewStatistics() noexcept {
                class NetworkStatistics final : public ppp::transmissions::ITransmissionStatistics {
                public:
                    /**
                     * @brief Constructs per-connection statistics linked to aggregate owner.
                     * @param owner Aggregate statistics sink.
                     */
                    NetworkStatistics(const ITransmissionStatisticsPtr& owner) noexcept
                        : ITransmissionStatistics()
                        , owner_(owner) {

                    }

                public:
                    /**
                     * @brief Adds inbound traffic to both aggregate and local counters.
                     * @param incoming_traffic Bytes received.
                     * @return Updated local inbound total.
                     */
                    virtual uint64_t                                    AddIncomingTraffic(uint64_t incoming_traffic) noexcept {
                        owner_->AddIncomingTraffic(incoming_traffic);
                        return ITransmissionStatistics::AddIncomingTraffic(incoming_traffic);
                    }
                    /**
                     * @brief Adds outbound traffic to both aggregate and local counters.
                     * @param outcoming_traffic Bytes sent.
                     * @return Updated local outbound total.
                     */
                    virtual uint64_t                                    AddOutgoingTraffic(uint64_t outcoming_traffic) noexcept {
                        owner_->AddOutgoingTraffic(outcoming_traffic);
                        return ITransmissionStatistics::AddOutgoingTraffic(outcoming_traffic);
                    }

                private:
                    ITransmissionStatisticsPtr                          owner_;
                };

                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULLPTR == server) {
                    return statistics_;
                }
                else {
                    return make_shared_object<NetworkStatistics>(statistics_);
                }
            }

            /**
             * @brief Allocates a managed-server helper bound to this switcher.
             * @return Managed-server instance.
             */
            VirtualEthernetSwitcher::VirtualEthernetManagedServerPtr VirtualEthernetSwitcher::NewManagedServer() noexcept {
                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetManagedServer>(self);
            }

            /**
             * @brief Performs full shutdown and releases all runtime resources.
             */
             void VirtualEthernetSwitcher::Finalize() noexcept {
                Finalize(ppp::function<void()>());
             }

             void VirtualEthernetSwitcher::Finalize(
                ppp::function<void()> completion) noexcept {
                ppp::telemetry::Log(Level::kInfo, "server", "server finalizing");
                running_.store(false, std::memory_order_release);
                VirtualEthernetNamespaceCachePtr cache;
                ITapPtr ipv6_transit_tap;
                NatInformationTable nats;
                VirtualEthernetLoggerPtr logger;
                VirtualEthernetExchangerTable exchangers;
                VirtualEthernetNetworkTcpipConnectionTable connections;
                ppp::unordered_set<ppp::string> ipv6_cleanup_keys;
                ppp::unordered_set<ppp::string> ipv6_cleanup_owned_neighbors;

                // Snapshot acceptors and TAP-backed cleanup state under the table lock. Kernel
                // operations run later without syncobj_, while the lifecycle lock prevents a
                // concurrent Add/Delete/Open from changing the TAP identity.
                std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptors_snapshot[NetworkAcceptorCategories_Max];

                {
                    SynchronizedObjectScope lifecycle_scope(ipv6_transit_lifecycle_syncobj_);
                    for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;

                    for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                        acceptors_snapshot[i] = std::move(acceptors_[i]);
                        acceptors_[i].reset();
                    }

                    cache = std::move(namespace_cache_);
                    ipv6_transit_tap = ipv6_transit_tap_;
                    ClearIPv6ExchangersUnsafe(ipv6_cleanup_keys, ipv6_cleanup_owned_neighbors);

                    // Release all IPv4 leases before moving exchangers out.
                    for (const auto& kv : exchangers_) {
                        if (kv.second) {
                            ipv4_pool_.Release(kv.first);
                        }
                    }

                    nats   = std::move(nats_);
                    logger = std::move(logger_);

                    exchangers = std::move(exchangers_);
                    exchangers_.clear();

                    connections = std::move(connections_);
                    connections_.clear();

                    p2p_peers_.clear();
                    p2p_virtual_ips_.clear();
                    peer_prefix_gateways_.clear();
                    peer_prefix_rib_.Clear();
                    static_echo_allocateds_.clear();
                    break;
                }

#if defined(_LINUX)
                for (const ppp::string& ip_key : ipv6_cleanup_keys) {
                    boost::system::error_code ec;
                    boost::asio::ip::address ip = StringToAddress(ip_key, ec);
                    if (ec || !ip.is_v6()) {
                        continue;
                    }

                    DeleteIPv6TransitRouteOnTap(
                        ipv6_transit_tap, ip, ppp::ipv6::IPv6_MAX_PREFIX_LENGTH);
                    DeleteIPv6NeighborProxy(ip);

                    if (ipv6_cleanup_owned_neighbors.count(ip_key) > 0 &&
                        NULLPTR != ipv6_transit_tap &&
                        ppp::tap::TapLinux::DeleteIPv6PermanentNeighbor(ipv6_transit_tap->GetId(), ip_key)) {
                        SynchronizedObjectScope scope(syncobj_);
                        if (ipv6_transit_tap_ == ipv6_transit_tap) {
                            ipv6_transit_neighbor_owned_.erase(ip_key);
                        }
                    }
                    // Failed permanent-neighbor deletions remain in the ownership set. This is
                    // the final in-process retry, so the record is not falsely marked clean.
                }
#endif

                    {
                        SynchronizedObjectScope scope(syncobj_);
                        if (ipv6_transit_tap_ == ipv6_transit_tap) {
                            ipv6_transit_tap_.reset();
                        }
                    }
                }

                // Close snapshotted acceptors outside the lock to avoid holding syncobj_
                // across blocking socket close syscalls.
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    if (NULLPTR != acceptors_snapshot[i]) {
                        Socket::Closesocket(acceptors_snapshot[i]);
                    }
                }

                CloseIPv6TransitSsmtContexts();
                CloseAlwaysTimeout();
                CloseIPv6NeighborProxyIfNeed();
                ppp::ipv6::auxiliary::FinalizeServerEnvironment(configuration_, preferred_nic_, ipv6_transit_tap ? ipv6_transit_tap->GetId() : tun_name_);

                if (NULLPTR != cache) {
                    cache->Clear();
                }

                if (NULLPTR != logger) {
                    IDisposable::Dispose(logger);
                }

                const std::size_t child_count = exchangers.size() +
                    connections.size() + (NULLPTR != ipv6_transit_tap ? 1u : 0u);
                if (child_count == 0) {
                    if (completion) {
                        completion();
                    }
                    return;
                }

                auto remaining = std::make_shared<std::atomic<std::size_t>>(child_count);
                auto completion_holder =
                    std::make_shared<ppp::function<void()>>(std::move(completion));
                auto child_complete = [remaining, completion_holder]() noexcept {
                    if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
                        *completion_holder) {
                        (*completion_holder)();
                    }
                };

                for (auto&& [_, exchanger] : exchangers) {
                    if (exchanger) {
                        exchanger->Dispose(child_complete);
                    }
                    else {
                        child_complete();
                    }
                }
                for (auto&& [_, connection] : connections) {
                    if (connection) {
                        connection->Dispose(child_complete);
                    }
                    else {
                        child_complete();
                    }
                }
                if (ipv6_transit_tap) {
                    const auto tap_context = ipv6_transit_tap->GetContext();
                    if (tap_context) {
                        boost::asio::dispatch(*tap_context,
                            [ipv6_transit_tap, tap_context, child_complete]() noexcept {
                                ipv6_transit_tap->Dispose();
                                boost::asio::post(*tap_context, child_complete);
                            });
                    }
                    else {
                        ipv6_transit_tap->Dispose();
                        child_complete();
                    }
                }
             }

            /**
             * @brief Closes and clears all active TCP acceptors.
             */
            void VirtualEthernetSwitcher::CloseAllAcceptors() noexcept {
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor = acceptors_[i];
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_copy = std::move(acceptor);
                    if (NULLPTR == acceptor_copy) {
                        continue;
                    }

                    acceptor.reset();
                    Socket::Closesocket(acceptor_copy);
                }
            }

            /**
             * @brief Stops and disposes periodic timer if present.
             * @return true when a timer existed and was disposed.
             */
            bool VirtualEthernetSwitcher::CloseAlwaysTimeout() noexcept {
                TimerPtr timeout = std::move(timeout_);
                if (timeout) {
                    timeout->Dispose();
                    return true;
                }
                else {
                    return false;
                }
            }

            /**
             * @brief Creates and loads firewall policy from file.
             * @param firewall_rules Rule file path.
             * @return true when firewall instance is created.
             */
            bool VirtualEthernetSwitcher::CreateFirewall(const ppp::string& firewall_rules) noexcept {
                if (disposed_) {
                    return false;
                }

                FirewallPtr firewall = NewFirewall();
                if (NULLPTR == firewall) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                    return false;
                }

                firewall_ = firewall;

                if (!firewall_rules.empty()) {
                    ppp::string firewall_path = ppp::io::File::GetFullPath(ppp::io::File::RewritePath(firewall_rules.data()).data());
                    if (!firewall_path.empty() && ppp::io::File::Exists(firewall_path.data())) {
                        ppp::string firewall_text = ppp::io::File::ReadAllText(firewall_path.data());
                        firewall_text = ppp::LTrim(ppp::RTrim(firewall_text));
                        if (!firewall_text.empty()) {
                            firewall->LoadWithRules(firewall_text);
                        }
                    }
                }

                return true;
            }

            /**
             * @brief Creates periodic timer driving maintenance tasks.
             * @return true when timer starts successfully.
             */
            bool VirtualEthernetSwitcher::CreateAlwaysTimeout() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<Timer> timeout = make_shared_object<Timer>(context_);
                if (!timeout) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    return false;
                }

                auto self = shared_from_this();
                timeout->TickEvent =
                    [self, this](Timer* sender, Timer::TickEventArgs& e) noexcept {
                        UInt64 now = Executors::GetTickCount();
                        OnTick(now);
                    };

                bool ok = timeout->SetInterval(1000) && timeout->Start();
                if (ok) {
                    timeout_ = timeout;
                    return true;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
                timeout->Dispose();
                return false;
            }

            /**
             * @brief Updates all exchangers and disposes stale ones.
             *
             * @param now  Current tick count in milliseconds.
             *
             * @note  Two-phase pattern: Update() is called under the lock (it is fast —
             *        it only posts a lambda and returns).  Stale exchangers are collected
             *        into a local vector while the lock is held, erased from the map, then
             *        Dispose()d outside the lock.  This eliminates the ABBA window where
             *        Dispose() acquires ASIO's internal queue lock while syncobj_ is held.
             */
            void VirtualEthernetSwitcher::TickAllExchangers(UInt64 now) noexcept {
                ppp::vector<VirtualEthernetExchangerPtr> stale;

                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto tail = exchangers_.begin(); tail != exchangers_.end();) {
                        const VirtualEthernetExchangerPtr& ex = tail->second;
                        if (!ex || !ex->Update(now)) {
                            if (ex) {
                                stale.emplace_back(ex);
                                ppp::telemetry::Count("server.exchanger.remove", 1);
                                ppp::telemetry::Log(Level::kInfo, "server", "exchanger removed (stale)");
                            }

                            tail = exchangers_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }
                    ppp::telemetry::Gauge("server.active_sessions", (int64_t)exchangers_.size());
                }

                // Dispose outside the lock to avoid holding syncobj_ across
                // boost::asio::post() calls inside VirtualEthernetExchanger::Dispose().
                for (auto& ex : stale) {
                    if (ex) {
                        DeleteIPv4Lease(ex->GetId());
                    }
                    IDisposable::Dispose(*ex);
                }
            }

            /**
             * @brief Expires stale TCP connections and disposes them outside the lock.
             *
             * @param now  Current tick count in milliseconds.
             *
             * @note  Snapshot-and-release pattern: expired connection pointers are moved
             *        into a local vector under the lock; the map entries are erased; the
             *        lock is released; then Dispose() is called outside the lock.
             *        This prevents a re-entrant deadlock if a connection's Dispose() path
             *        calls DeleteConnection() which would otherwise re-acquire syncobj_
             *        (std::mutex is non-recursive).
             */
            void VirtualEthernetSwitcher::TickAllConnections(UInt64 now) noexcept {
                ppp::vector<VirtualEthernetNetworkTcpipConnectionPtr> stale;

                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto tail = connections_.begin(); tail != connections_.end();) {
                        const VirtualEthernetNetworkTcpipConnectionPtr& conn = tail->second;
                        if (!conn || conn->IsPortAging(now)) {
                            if (conn) {
                                stale.emplace_back(conn);
                            }

                            tail = connections_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }
                }

                // Dispose outside the lock to avoid re-entrant deadlock on syncobj_.
                for (auto& conn : stale) {
                    IDisposable::Dispose(*conn);
                }
            }

            /**
             * @brief Expires stale IPv6 leases and prunes orphaned request records.
             * @param now Current tick count.
             */
            void VirtualEthernetSwitcher::TickIPv6Leases(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                for (auto it = ipv6_leases_.begin(); it != ipv6_leases_.end();) {
                    IPv6LeaseEntry& lease = it->second;
                    if (lease.StaticBinding || lease.ExpiresAt == UINT64_MAX || lease.ExpiresAt > now) {
                        ++it;
                        continue;
                    }

                    auto exchanger_it = exchangers_.find(it->first);
                    if (exchanger_it != exchangers_.end()) {
                        const VirtualEthernetExchangerPtr& exchanger = exchanger_it->second;
                        if (exchanger && !exchanger->IsDisposed()) {
                            if (configuration_->server.ipv6.lease_time > 0) {
                                lease.ExpiresAt = now + static_cast<UInt64>(configuration_->server.ipv6.lease_time) * 1000ULL;
                            }
                            else {
                                lease.ExpiresAt = UINT64_MAX;
                            }
                            ++it;
                            continue;
                        }
                    }

                    // Remove the stale address-to-exchanger mapping from ipv6s_ before
                    // evicting the lease record.  Without this cleanup, a dangling key
                    // remains in ipv6s_ and TryGetAssignedIPv6Extensions would wrongly
                    // consider the expired address as still assigned.
                    if (lease.Address.is_v6()) {
                        std::string addr_std = lease.Address.to_string();
                        ppp::string addr_key(addr_std.data(), addr_std.size());
                        ipv6s_.erase(addr_key);
                    }

                    ppp::telemetry::Count("server.ipv6.withdrawn", 1);
                    ppp::telemetry::Log(Level::kDebug, "server", "ipv6 withdrawn (expired)");

                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseExpired);
                    it = ipv6_leases_.erase(it);
                }

                for (auto it = ipv6_requests_.begin(); it != ipv6_requests_.end();) {
                    if (ipv6_leases_.find(it->first) == ipv6_leases_.end()) {
                        it = ipv6_requests_.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }

            /**
             * @brief Removes lease/request state for a session.
             * @param session_id Session identifier.
             */
            void VirtualEthernetSwitcher::RevokeIPv6Lease(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                ipv6_leases_.erase(session_id);
                ipv6_requests_.erase(session_id);
            }

            /**
             * @brief Releases the IPv4 lease held by the specified session.
             * @param session_id Session whose IPv4 lease should be released.
             */
            void VirtualEthernetSwitcher::DeleteIPv4Lease(const Int128& session_id) noexcept {
                ipv4_pool_.Release(session_id);
            }

            /**
             * @brief Reserves a specific IPv4 address in the lease pool for a session.
             *
             * @details See header for full contract.  Implementation strategy:
             *          AcquireManual() will (a) succeed when the requested IP is free,
             *          or (b) fall back to AcquireAuto and return a *different* IP with
             *          accepted=false.  The legacy Arp() caller does not actually want
             *          a different IP — it has already committed to the address it
             *          announced — so on a non-accepted result we Release() the
             *          fallback to keep the pool consistent with reality.
             *
             *          When the pool is not configured we return false silently;
             *          legacy clients keep functioning unchanged.
             */
            bool VirtualEthernetSwitcher::ReserveIPv4Lease(const Int128& session_id, uint32_t ip) noexcept {
                if (NULLPTR == configuration_ || !configuration_->server.ipv4_pool.configured) {
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return false;
                }

                boost::asio::ip::address addr = ppp::net::Ipep::ToAddress(ip);
                if (!addr.is_v4()) {
                    return false;
                }

                IPv4LeasePool::Result r = ipv4_pool_.AcquireManual(session_id, addr.to_v4());
                if (r.ok && r.accepted) {
                    return true;
                }

                // Manual reservation conflicted; AcquireManual already swapped in a
                // fallback IP for this session.  The legacy caller does not consume
                // that fallback, so release it now to leave the pool unchanged from
                // the legacy caller's perspective.
                ipv4_pool_.Release(session_id);
                return false;
            }

            /**
             * @brief Periodic maintenance entry called by switch timer.
             * @param now Current tick count.
             * @return true while switch remains active.
             */
            bool VirtualEthernetSwitcher::OnTick(UInt64 now) noexcept {
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    if (disposed_) {
                        return false;
                    }

                    break;
                }

                TickAllExchangers(now);
                TickAllConnections(now);
                TickIPv6Leases(now);
                RefreshIPv6NeighborProxyIfNeed();

                VirtualEthernetNamespaceCachePtr cache = namespace_cache_;
                if (NULLPTR != cache) {
                    cache->Update();
                }

                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULLPTR != server) {
                    server->Update(now);
                }

                return true;
            }

            /**
             * @brief Applies updated session information to an active exchanger.
             * @param session_id Session identifier.
             * @param info Information payload from managed control plane.
             * @param y Coroutine context.
             * @return true when update is delivered and validated.
             */
            bool VirtualEthernetSwitcher::OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULLPTR == exchanger) {
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                bool bok = false;
                if (NULLPTR != info) {
                    InformationEnvelope envelope = BuildInformationEnvelope(session_id, *info);
                    if (envelope.Extensions.AssignedIPv6Address.is_v6() && !AddIPv6Exchanger(session_id, envelope.Extensions)) {
                        RevokeIPv6Lease(session_id);
                        DeleteIPv6Exchanger(session_id);
                        envelope.Extensions.AssignedIPv6Address = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Gateway = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefixLength = 0;
                        envelope.Extensions.AssignedIPv6Dns1 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Dns2 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Flags = 0;
                        envelope.Extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                        envelope.Extensions.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                    }
                    bok = exchanger->DoInformation(transmission, envelope, y);
                    if (bok) {
                        bok = info->Valid();
                    }
                }

                if (!bok) {
                    transmission->Dispose();
                }

                return bok;
            }

            /**
             * @brief Updates stored client IPv6 request and recomputes assignment.
             * @param session_id Session identifier.
             * @param request Client-requested extension fields.
             * @param response Receives updated server response extension fields.
             * @return true when response contains any extension value.
             */
            bool VirtualEthernetSwitcher::UpdateIPv6Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept {
                IPv6RequestEntry entry;
                entry.Present = request.RequestedIPv6Address.is_v6();
                entry.Accepted = false;
                entry.RequestedAddress = request.RequestedIPv6Address;
                entry.StatusCode = VirtualEthernetInformationExtensions::IPv6Status_None;

                if (entry.Present) {
                    entry.Accepted = true;
                    entry.StatusCode = VirtualEthernetInformationExtensions::IPv6Status_ClientRequested;
                    entry.StatusMessage = "client-ipv6-request-pending";
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (entry.Present) {
                        ipv6_requests_[session_id] = entry;
                    }
                    else {
                        ipv6_requests_.erase(session_id);
                    }
                }

                BuildInformationIPv6Extensions(session_id, response);
                if (response.AssignedIPv6Address.is_v6()) {
                    if (!AddIPv6Exchanger(session_id, response)) {
                        RevokeIPv6Lease(session_id);
                        DeleteIPv6Exchanger(session_id);
                        response.AssignedIPv6Address = boost::asio::ip::address();
                        response.AssignedIPv6Gateway = boost::asio::ip::address();
                        response.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                        response.AssignedIPv6RoutePrefixLength = 0;
                        response.AssignedIPv6Dns1 = boost::asio::ip::address();
                        response.AssignedIPv6Dns2 = boost::asio::ip::address();
                        response.AssignedIPv6Flags = 0;
                        response.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                        response.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                    }
                }
                else {
                    DeleteIPv6Exchanger(session_id);
                }

                if (!entry.Accepted && entry.StatusCode != VirtualEthernetInformationExtensions::IPv6Status_None) {
                    response.IPv6StatusCode = entry.StatusCode;
                    response.IPv6StatusMessage = entry.StatusMessage;
                    response.RequestedIPv6Address = request.RequestedIPv6Address;
                }
                return response.HasAny();
            }

            /**
             * @brief Processes a client IPv4 address request and fills the response.
             *
             * @details If the pool is configured, allocates (auto or manual) and
             *          fills the ClientIPv4Assignment in @p response.  If the pool
             *          is not configured, this is a no-op and returns false.
             *
             * @param session_id Session that sent the request.
             * @param request    Client-supplied IPv4 request extensions.
             * @param response   Filled with the server's IPv4 assignment response.
             * @return true if an IPv4 assignment was processed (pool is configured).
             */
            bool VirtualEthernetSwitcher::UpdateIPv4Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept {
                if (!request.ClientIPv4Req.enabled) {
                    return false;
                }

                // If the pool was never configured, tell the client.
                if (!configuration_->server.ipv4_pool.configured) {
                    response.ClientIPv4Assign.enabled  = true;
                    response.ClientIPv4Assign.accepted = false;
                    response.ClientIPv4Assign.reason   = "pool-unavailable";
                    return true;
                }

                const ppp::string& mode    = request.ClientIPv4Req.mode;
                const ppp::string& address = request.ClientIPv4Req.address;

                IPv4LeasePool::Result result;
                if (mode == "manual" && !address.empty()) {
                    boost::system::error_code ec;
                    boost::asio::ip::address req_addr = StringToAddress(address, ec);
                    if (!ec && req_addr.is_v4()) {
                        result = ipv4_pool_.AcquireManual(session_id, req_addr.to_v4());
                    }
                    else {
                        // Address parse failed — fall back to auto.
                        result = ipv4_pool_.AcquireAuto(session_id);
                    }
                }
                else {
                    result = ipv4_pool_.AcquireAuto(session_id);
                }

                // Populate the response regardless of success/failure so
                // the client can inspect reason / conflict flags.
                response.ClientIPv4Assign.enabled  = true;
                response.ClientIPv4Assign.accepted = result.accepted;
                response.ClientIPv4Assign.conflict = result.conflict;
                response.ClientIPv4Assign.mode     = mode;
                if (!result.reason.empty()) {
                    response.ClientIPv4Assign.reason = result.reason;
                }

                if (result.ok) {
                    std::string addr_str = result.address.to_string();
                    response.ClientIPv4Assign.address = ppp::string(addr_str.data(), addr_str.size());

                    std::string gw_str = result.gateway.to_string();
                    response.ClientIPv4Assign.gateway = ppp::string(gw_str.data(), gw_str.size());

                    std::string mask_str = result.mask.to_string();
                    response.ClientIPv4Assign.mask = ppp::string(mask_str.data(), mask_str.size());
                }

                if (!result.requested_address.is_unspecified()) {
                    std::string req_str = result.requested_address.to_string();
                    response.ClientIPv4Assign.requested_address = ppp::string(req_str.data(), req_str.size());
                }

                return result.ok;
            }

            /**
             * @brief Removes and disposes a registered transient network connection.
             * @param connection Raw connection key pointer.
             * @return true when a matching connection is removed.
             */
            bool VirtualEthernetSwitcher::DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept {
                VirtualEthernetNetworkTcpipConnectionPtr ntcp;
                if (connection) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::RemoveValueByKey(connections_, (void*)connection, &ntcp);
                }

                if (ntcp) {
                    ntcp->Dispose();
                    return true;
                }

                return false;
            }

            /**
             * @brief Parses configured DNS endpoint with validity fallbacks.
             * @param dnserver_endpoint Endpoint string from configuration.
             * @return Sanitized UDP endpoint.
             */
            boost::asio::ip::udp::endpoint VirtualEthernetSwitcher::ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept {
                boost::asio::ip::address dnsserverIP = boost::asio::ip::address_v4::any();
                int dnsserverPort = PPP_DNS_SYS_PORT;
                if (dnserver_endpoint.empty()) {
                    return boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                }

                boost::asio::ip::udp::endpoint dnsserverEP = Ipep::ParseEndPoint(dnserver_endpoint);
                dnsserverPort = dnsserverEP.port();
                if (dnsserverPort <= IPEndPoint::MinPort || dnsserverPort > IPEndPoint::MaxPort) {
                    dnsserverPort = PPP_DNS_SYS_PORT;
                }

                dnsserverIP = dnsserverEP.address();
                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                if (IPEndPoint::IsInvalid(dnsserverEP.address())) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }
                elif(dnsserverIP.is_multicast()) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }

                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                return dnsserverEP;
            }

            /**
             * @brief Gets local bind endpoint for a listener category.
             * @param categories Listener category.
             * @return Bound endpoint or wildcard/min-port fallback.
             */
            boost::asio::ip::tcp::endpoint VirtualEthernetSwitcher::GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept {
                boost::system::error_code ec;
                if (categories == NetworkAcceptorCategories_Udpip) {
                    if (static_echo_socket_.is_open()) {
                        boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                        if (ec == boost::system::errc::success) {
                            return boost::asio::ip::tcp::endpoint(localEP.address(), localEP.port());
                        }
                    }
                }
                elif(categories >= NetworkAcceptorCategories_Min && categories < NetworkAcceptorCategories_Max) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULLPTR != acceptor) {
                        if (acceptor->is_open()) {
                            boost::asio::ip::tcp::endpoint localEP = acceptor->local_endpoint(ec);
                            if (ec == boost::system::errc::success) {
                                return localEP;
                            }
                        }
                    }
                }

                return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint::Any(IPEndPoint::MinPort));
            }

            /**
             * @brief Finds NAT mapping information for an IPv4 address.
             * @param ip IPv4 address key.
             * @return NAT mapping entry or null.
             */
            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::FindNatInformation(uint32_t ip) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::FindObjectByKey(nats_, ip);
            }

            /**
             * @brief Adds or refreshes NAT ownership for an IPv4 address.
             * @param exchanger Session exchanger owning mapping.
             * @param ip IPv4 address.
             * @param mask IPv4 subnet mask.
             * @return NAT mapping entry when ownership is accepted.
             */
            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(mask, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                if (exchanger->IsDisposed()) {
                    return NULLPTR;
                }

                // Creating a nat information entry mapping does not mean that the mapping will be added to the nats.
                NatInformationPtr nat = make_shared_object<NatInformation>();
                if (NULLPTR == nat) {
                    return NULLPTR;
                }

                nat->Exchanger = exchanger;
                nat->IPAddress = ip;
                nat->SubmaskAddress = mask;

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULLPTR;
                }

                // If ip addresses conflict, do not directly conflict like traditional routers,
                // And abandon the mapping between IP and Ethernet electrical ports.
                auto kv = nats_.emplace(ip, nat);
                if (kv.second) {
                    return nat;
                }

                NatInformationTable::iterator tail = kv.first;
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return NULLPTR;
                }

                NatInformationPtr& raw = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& raw_exchanger = raw->Exchanger;
                if (raw_exchanger->IsDisposed()) {
                    raw = nat;
                    return nat;
                }
                else {
                    return NULLPTR;
                }
            }

            static ppp::vector<ppp::app::protocol::P2PEndpointCandidate> P2PBuildCandidates(const VirtualEthernetSwitcher::P2PPeerRecord& record) noexcept {
                ppp::vector<ppp::app::protocol::P2PEndpointCandidate> candidates = record.Candidates;
                ppp::app::P2PAppendObservedEndpointCandidate(record.ObservedEndpoint, candidates);
                return candidates;
            }

            static bool P2PAppendCanonicalCandidates(
                const ppp::vector<ppp::app::protocol::P2PEndpointCandidate>& source,
                std::vector<ppp::p2p::P2PCandidateV1>& destination) noexcept {
                try {
                    for (const auto& value : source) {
                        const auto endpoint = Ipep::ParseEndPoint(value.endpoint);
                        ppp::p2p::P2PCandidateV1 candidate;
                        if (!ppp::app::P2PCandidateFromEndpoint(endpoint, candidate)) {
                            return false;
                        }
                        destination.emplace_back(candidate);
                    }
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            static bool P2PCollectPeerCandidates(
                const VirtualEthernetSwitcher::P2PPeerRecord& source,
                const VirtualEthernetSwitcher::P2PPeerRecord& destination,
                std::vector<ppp::p2p::P2PCandidateV1>& candidates) noexcept {
                try {
                    candidates.reserve(source.Candidates.size() + destination.Candidates.size());
                }
                catch (...) {
                    return false;
                }
                return P2PAppendCanonicalCandidates(source.Candidates, candidates) &&
                    P2PAppendCanonicalCandidates(destination.Candidates, candidates) &&
                    !candidates.empty();
            }

            static ppp::p2p::P2PId P2PPeerIdFromVirtualIP(uint32_t virtual_ip) noexcept {
                ppp::p2p::P2PId peer_id{};
                std::memcpy(peer_id.data() + 12, &virtual_ip, sizeof(virtual_ip));
                return peer_id;
            }

            static VirtualEthernetSwitcher::InformationEnvelope P2PBuildEnvelope(const ppp::app::protocol::P2PControlMessage& message) noexcept {
                VirtualEthernetSwitcher::InformationEnvelope envelope;
                envelope.Base.Clear();
                envelope.Base.BandwidthQoS = 0;
                envelope.Base.IncomingTraffic = std::numeric_limits<UInt64>::max();
                envelope.Base.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                envelope.Base.ExpiredTime = std::numeric_limits<UInt32>::max();
                envelope.Extensions.P2P = message;
                envelope.ExtendedJson = envelope.Extensions.ToJson();
                return envelope;
            }

            bool VirtualEthernetSwitcher::UpdateP2PPeer(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, const ITransmissionPtr& transmission, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept {
                if (NULLPTR == exchanger || NULLPTR == transmission || NULLPTR == configuration_) {
                    return false;
                }

                response.P2P.enabled = false;
                response.P2P.mode = "relay";
                response.P2P.virtual_ip = request.P2P.virtual_ip;

                // Fix #3: Only accept explicit "register" actions with enabled=true.
                // Other actions/replies must not be treated as registration.
                if (!request.P2P.enabled || request.P2P.action != "register") {
                    response.P2P.action = "status";
                    response.P2P.reason = "not-a-register";
                    return false;
                }

                const auto p2p_capability = ppp::p2p::P2PCapabilityGate::Evaluate(
                    configuration_->p2p.enabled,
                    configuration_->p2p.mode.c_str(),
                    transmission->HasAuthenticatedSessionExporter(),
                    request.P2P.enabled,
                    ppp::p2p::ProductionAuthenticatedControlV1Ready);
                response.P2P.enabled = p2p_capability.allowed;
                response.P2P.mode = p2p_capability.allowed ? configuration_->p2p.mode : "relay";
                if (!p2p_capability.allowed) {
                    response.P2P.action = "status";
                    response.P2P.reason = p2p_capability.reason;
                    return false;
                }

                ppp::string requested_mode = ToLower(request.P2P.mode);
                if (requested_mode != "direct-preferred") {
                    response.P2P.action = "status";
                    response.P2P.reason = "client-relay-only";
                    return false;
                }

                uint32_t virtual_ip = request.P2P.virtual_ip;
                if (virtual_ip == 0 || IPEndPoint::IsInvalid(IPEndPoint(virtual_ip, IPEndPoint::MinPort))) {
                    response.P2P.action = "reject";
                    response.P2P.reason = "virtual-ip-missing";
                    return false;
                }

                // Fix #4: Validate virtual_ip ownership via the authoritative NAT table.
                // The requesting session must own this virtual_ip in the NAT registry.
                {
                    NatInformationPtr nat = FindNatInformation(virtual_ip);
                    if (NULLPTR == nat || NULLPTR == nat->Exchanger || nat->Exchanger.get() != exchanger.get()) {
                        response.P2P.action = "reject";
                        response.P2P.reason = "virtual-ip-not-owned";
                        return false;
                    }
                }

                UInt64 now = Executors::GetTickCount();
                Int128 session_id = exchanger->GetId();

                P2PPeerRecord record;
                record.SessionId = session_id;
                record.VirtualIP = virtual_ip;
                record.Mode = requested_mode;
                record.Candidates = request.P2P.candidates;
                record.LastSeen = now;
                record.Exchanger = exchanger;

                {
                    SynchronizedObjectScope scope(syncobj_);

                    // Fix #1 (P2 review): When the same session re-registers with a
                    // different virtual_ip, remove the stale reverse-index entry for
                    // the old IP first.  Without this, p2p_virtual_ips_ accumulates
                    // orphaned entries that point at a session whose p2p_peers_ record
                    // now holds a completely different virtual_ip.
                    auto existing_peer_it = p2p_peers_.find(session_id);
                    if (existing_peer_it != p2p_peers_.end()) {
                        uint32_t old_vip = existing_peer_it->second.VirtualIP;
                        if (old_vip == virtual_ip) {
                            record.ObservedEndpoint = existing_peer_it->second.ObservedEndpoint;
                        }
                        if (old_vip != 0 && old_vip != virtual_ip) {
                            auto old_vip_it = p2p_virtual_ips_.find(old_vip);
                            if (old_vip_it != p2p_virtual_ips_.end() && old_vip_it->second == session_id) {
                                p2p_virtual_ips_.erase(old_vip_it);
                            }
                        }
                    }

                    // Fix #5: Clean up any stale record for the same virtual_ip (different session).
                    auto vip_it = p2p_virtual_ips_.find(virtual_ip);
                    if (vip_it != p2p_virtual_ips_.end() && vip_it->second != session_id) {
                        p2p_peers_.erase(vip_it->second);
                        vip_it->second = session_id;
                    }
                    else if (vip_it == p2p_virtual_ips_.end()) {
                        p2p_virtual_ips_[virtual_ip] = session_id;
                    }

                    p2p_peers_[session_id] = record;
                }

                response.P2P.action = "status";
                response.P2P.reason = "registered";
                response.P2P.candidates = P2PBuildCandidates(record);
                return true;
            }

            bool VirtualEthernetSwitcher::ObserveP2PUdpEndpoint(
                const std::shared_ptr<VirtualEthernetExchanger>& exchanger,
                uint32_t virtual_ip,
                const boost::asio::ip::udp::endpoint& source) noexcept {
                if (NULLPTR == exchanger || source.address().is_unspecified() || source.port() == 0) {
                    return false;
                }

                NatInformationPtr nat = FindNatInformation(virtual_ip);
                if (NULLPTR == nat || nat->Exchanger.get() != exchanger.get()) {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint destination = static_echo_socket_.local_endpoint(ec);
                if (ec || destination.address().is_unspecified() || destination.port() == 0) {
                    return false;
                }

                const auto observed = Ipep::V6ToV4(source);
                destination = Ipep::V6ToV4(destination);
                const UInt64 now = Executors::GetTickCount();
                p2p_nat_classifier_.Observe(virtual_ip, observed, destination, now);

                SynchronizedObjectScope scope(syncobj_);
                auto vip = p2p_virtual_ips_.find(virtual_ip);
                if (vip != p2p_virtual_ips_.end()) {
                    auto peer = p2p_peers_.find(vip->second);
                    if (peer != p2p_peers_.end() && peer->second.Exchanger.lock().get() == exchanger.get()) {
                        peer->second.ObservedEndpoint = observed;
                    }
                }
                return true;
            }

            bool VirtualEthernetSwitcher::DeleteP2PPeer(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                auto it = p2p_peers_.find(session_id);
                if (it == p2p_peers_.end()) {
                    return false;
                }
                // Fix #5: Clean up reverse index entry for this virtual_ip.
                uint32_t vip = it->second.VirtualIP;
                auto vip_it = p2p_virtual_ips_.find(vip);
                if (vip_it != p2p_virtual_ips_.end() && vip_it->second == session_id) {
                    p2p_virtual_ips_.erase(vip_it);
                }
                p2p_peers_.erase(it);
                return true;
            }

            bool VirtualEthernetSwitcher::OfferP2PPeerHints(uint32_t source_ip, uint32_t destination_ip, YieldContext& y) noexcept {
                if (NULLPTR == configuration_ || !configuration_->p2p.enabled || configuration_->p2p.mode != "direct-preferred") {
                    return false;
                }

                static constexpr UInt64 OFFER_THROTTLE_MS = 10000;
                UInt64 now = Executors::GetTickCount();
                P2PPeerRecord source_record;
                P2PPeerRecord destination_record;
                bool found = false;

                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto& kv : p2p_peers_) {
                        P2PPeerRecord& record = kv.second;
                        if (record.VirtualIP == source_ip) {
                            source_record = record;
                        }
                        else if (record.VirtualIP == destination_ip) {
                            destination_record = record;
                        }
                    }

                    if (source_record.SessionId == 0 || destination_record.SessionId == 0 || source_record.SessionId == destination_record.SessionId) {
                        return false;
                    }

                    if (source_record.Mode != "direct-preferred" || destination_record.Mode != "direct-preferred") {
                        return false;
                    }

                    // Throttle: skip this offer only when BOTH sides are still within
                    // their per-peer cooldown window.  Using && (not ||) is intentional:
                    // if either peer's cooldown has expired the pair is eligible again,
                    // which prevents one stale peer from indefinitely blocking the other
                    // side from receiving offers in a different pairing.
                    if (now < source_record.LastOfferAt + OFFER_THROTTLE_MS && now < destination_record.LastOfferAt + OFFER_THROTTLE_MS) {
                        return false;
                    }

                    found = true;
                }

                if (!found) {
                    return false;
                }

                // Fix #4: Cross-validate that the NAT table still confirms the same owner for
                // both virtual IPs.  A stale/expired P2P record could point at a recycled session.
                {
                    NatInformationPtr source_nat = FindNatInformation(source_ip);
                    NatInformationPtr destination_nat = FindNatInformation(destination_ip);
                    if (NULLPTR == source_nat || NULLPTR == destination_nat) {
                        // One or both IPs no longer in NAT table — clean up stale P2P records.
                        SynchronizedObjectScope scope(syncobj_);
                        if (NULLPTR == source_nat) {
                            p2p_peers_.erase(source_record.SessionId);
                            p2p_virtual_ips_.erase(source_ip);
                        }
                        if (NULLPTR == destination_nat) {
                            p2p_peers_.erase(destination_record.SessionId);
                            p2p_virtual_ips_.erase(destination_ip);
                        }
                        return false;
                    }
                    if (NULLPTR == source_nat->Exchanger || NULLPTR == destination_nat->Exchanger) {
                        return false;
                    }
                    if (source_nat->Exchanger.get() != source_record.Exchanger.lock().get() ||
                        destination_nat->Exchanger.get() != destination_record.Exchanger.lock().get()) {
                        return false;
                    }
                }

                // NAT classification check: skip offer if both peers have
                // symmetric NAT or either is UDP-blocked.
                //
                // Authenticated static-echo datagrams feed real UDP source mappings.
                // TCP control endpoints remain excluded because they do not predict
                // UDP NAT behavior. A single server destination remains Unknown;
                // classification requires observations across multiple destinations.
                // Unknown still allows bounded probing.
                // Only Symmetric-Symmetric and UdpBlocked (based on real
                // observations) cause immediate skip.
                {
                    ppp::p2p::P2PNatClassification source_class = p2p_nat_classifier_.Classify(source_ip, now);
                    ppp::p2p::P2PNatClassification dest_class   = p2p_nat_classifier_.Classify(destination_ip, now);
                    if (!ppp::p2p::P2PNatClassifier::ShouldAttemptPunch(source_class, dest_class)) {
                        ppp::telemetry::Log(Level::kInfo, "p2p", "NAT classification skip offer source=%s(%d) dest=%s(%d)",
                            IPEndPoint::ToAddressString(source_ip).c_str(), static_cast<int>(source_class.type),
                            IPEndPoint::ToAddressString(destination_ip).c_str(), static_cast<int>(dest_class.type));
                        ppp::telemetry::Count("p2p.nat_skip", 1);
                        return false;
                    }
                    // Update peer records with classified NAT type.
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        auto src_it = p2p_peers_.find(source_record.SessionId);
                        if (src_it != p2p_peers_.end()) {
                            src_it->second.NatType = source_class.type;
                        }
                        auto dst_it = p2p_peers_.find(destination_record.SessionId);
                        if (dst_it != p2p_peers_.end()) {
                            dst_it->second.NatType = dest_class.type;
                        }
                    }
                }

                std::shared_ptr<VirtualEthernetExchanger> source_exchanger = source_record.Exchanger.lock();
                std::shared_ptr<VirtualEthernetExchanger> destination_exchanger = destination_record.Exchanger.lock();
                if (NULLPTR == source_exchanger || NULLPTR == destination_exchanger) {
                    // Fix #4: Clean up stale weak_ptr records.
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        if (NULLPTR == source_exchanger) {
                            p2p_peers_.erase(source_record.SessionId);
                            p2p_virtual_ips_.erase(source_ip);
                        }
                        if (NULLPTR == destination_exchanger) {
                            p2p_peers_.erase(destination_record.SessionId);
                            p2p_virtual_ips_.erase(destination_ip);
                        }
                    }
                    return false;
                }

                ITransmissionPtr source_transmission = source_exchanger->GetTransmission();
                ITransmissionPtr destination_transmission = destination_exchanger->GetTransmission();
                if (NULLPTR == source_transmission || NULLPTR == destination_transmission) {
                    return false;
                }

                const auto source_capability = ppp::p2p::P2PCapabilityGate::Evaluate(
                    configuration_->p2p.enabled,
                    configuration_->p2p.mode.c_str(),
                    source_transmission->HasAuthenticatedSessionExporter(),
                    true,
                    ppp::p2p::ProductionAuthenticatedControlV1Ready);
                const auto destination_capability = ppp::p2p::P2PCapabilityGate::Evaluate(
                    configuration_->p2p.enabled,
                    configuration_->p2p.mode.c_str(),
                    destination_transmission->HasAuthenticatedSessionExporter(),
                    true,
                    ppp::p2p::ProductionAuthenticatedControlV1Ready);
                if (!source_capability.allowed || !destination_capability.allowed) {
                    return false;
                }

                std::vector<ppp::p2p::P2PCandidateV1> canonical_candidates;
                ppp::p2p::P2POfferHash candidate_set_hash{};
                if (!P2PCollectPeerCandidates(
                        source_record, destination_record, canonical_candidates) ||
                    !ppp::p2p::HashP2PCandidateSet(
                        canonical_candidates, candidate_set_hash)) {
                    return false;
                }

                auto source_context = source_transmission->GetContext();
                auto source_strand = source_transmission->GetStrand();
                auto destination_context = destination_transmission->GetContext();
                auto destination_strand = destination_transmission->GetStrand();
                if (NULLPTR == source_context || NULLPTR == destination_context) {
                    return false;
                }

                // Reserve the pair before starting either exporter so concurrent packets
                // cannot launch duplicate offers while authenticated key export is pending.
                UInt64 offer_generation = 0;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto src_it = p2p_peers_.find(source_record.SessionId);
                    auto dst_it = p2p_peers_.find(destination_record.SessionId);
                    if (src_it == p2p_peers_.end() || dst_it == p2p_peers_.end() ||
                        src_it->second.VirtualIP != source_ip ||
                        dst_it->second.VirtualIP != destination_ip) {
                        return false;
                    }
                    if (now < src_it->second.LastOfferAt + OFFER_THROTTLE_MS &&
                        now < dst_it->second.LastOfferAt + OFFER_THROTTLE_MS) {
                        return false;
                    }
                    offer_generation = ++p2p_offer_generation_;
                    if (offer_generation == 0) {
                        offer_generation = ++p2p_offer_generation_;
                    }
                    src_it->second.LastOfferAt = now;
                    src_it->second.LastOfferGeneration = offer_generation;
                    dst_it->second.LastOfferAt = now;
                    dst_it->second.LastOfferGeneration = offer_generation;
                }

                ppp::p2p::P2PRelayOfferInput input;
                ppp::p2p::Int128ToBytes(source_record.SessionId, input.initiator_session_id.data());
                ppp::p2p::Int128ToBytes(destination_record.SessionId, input.responder_session_id.data());
                input.initiator_peer_id = P2PPeerIdFromVirtualIP(source_ip);
                input.responder_peer_id = P2PPeerIdFromVirtualIP(destination_ip);
                input.ttl_seconds = 10;
                input.candidate_set_hash = candidate_set_hash;

                const auto source_async_exporter = ppp::p2p::ScheduleP2PSessionExporter(
                    [source_context, source_strand](const ppp::p2p::P2PTask& task) noexcept {
                        return Executors::Post(source_context, source_strand, task);
                    },
                    [source_transmission](const char* label,
                        const std::uint8_t* context, std::size_t context_length,
                        std::uint8_t* output, std::size_t output_length) noexcept {
                        return source_transmission->ExportAuthenticatedSessionKey(
                            label, context, context_length, output, output_length);
                    });
                const auto destination_async_exporter = ppp::p2p::ScheduleP2PSessionExporter(
                    [destination_context, destination_strand](const ppp::p2p::P2PTask& task) noexcept {
                        return Executors::Post(destination_context, destination_strand, task);
                    },
                    [destination_transmission](const char* label,
                        const std::uint8_t* context, std::size_t context_length,
                        std::uint8_t* output, std::size_t output_length) noexcept {
                        return destination_transmission->ExportAuthenticatedSessionKey(
                            label, context, context_length, output, output_length);
                    });

                auto self = shared_from_this();
                const auto rollback_reservation = [self, offer_generation](const Int128& session_id) noexcept {
                    SynchronizedObjectScope scope(self->syncobj_);
                    auto it = self->p2p_peers_.find(session_id);
                    if (it != self->p2p_peers_.end() &&
                        it->second.LastOfferGeneration == offer_generation) {
                        it->second.LastOfferAt = 0;
                        it->second.LastOfferGeneration = 0;
                    }
                };

                const bool scheduled = ppp::p2p::CreateP2PRelayOfferBundleAsync(
                    input, source_async_exporter, destination_async_exporter,
                    [self, source_record, destination_record,
                        source_exchanger, destination_exchanger,
                        source_transmission, destination_transmission,
                        source_ip, destination_ip, rollback_reservation]
                    (bool ok, const ppp::p2p::P2PRelayOfferBundle& bundle) noexcept {
                        if (!ok || self->IsDisposed()) {
                            rollback_reservation(source_record.SessionId);
                            rollback_reservation(destination_record.SessionId);
                            return;
                        }

                        std::string source_encoded;
                        std::string destination_encoded;
                        if (!ppp::p2p::EncodeP2PRelayOfferRecipientHex(
                                bundle.offer, bundle.initiator_envelope, source_encoded) ||
                            !ppp::p2p::EncodeP2PRelayOfferRecipientHex(
                                bundle.offer, bundle.responder_envelope, destination_encoded)) {
                            rollback_reservation(source_record.SessionId);
                            rollback_reservation(destination_record.SessionId);
                            return;
                        }

                        ppp::app::protocol::P2PControlMessage source_offer;
                        source_offer.enabled = true;
                        source_offer.mode = "direct-preferred";
                        source_offer.action = "offer-v1";
                        source_offer.virtual_ip = source_ip;
                        source_offer.peer_virtual_ip = destination_ip;
                        source_offer.authenticated_offer_v1.assign(
                            source_encoded.data(), source_encoded.size());
                        source_offer.candidates = P2PBuildCandidates(destination_record);

                        ppp::app::protocol::P2PControlMessage destination_offer;
                        destination_offer.enabled = true;
                        destination_offer.mode = "direct-preferred";
                        destination_offer.action = "offer-v1";
                        destination_offer.virtual_ip = destination_ip;
                        destination_offer.peer_virtual_ip = source_ip;
                        destination_offer.authenticated_offer_v1.assign(
                            destination_encoded.data(), destination_encoded.size());
                        destination_offer.candidates = P2PBuildCandidates(source_record);

                        const auto send_offer = [self, rollback_reservation](
                            const std::shared_ptr<VirtualEthernetExchanger>& exchanger,
                            const ITransmissionPtr& transmission,
                            const ppp::app::protocol::P2PControlMessage& message,
                            const Int128& session_id) noexcept {
                            auto context = transmission->GetContext();
                            auto strand = transmission->GetStrand();
                            auto allocator = transmission->BufferAllocator;
                            if (NULLPTR == context) {
                                rollback_reservation(session_id);
                                return false;
                            }

                            InformationEnvelope envelope = P2PBuildEnvelope(message);
                            const bool spawned = YieldContext::Spawn(
                                allocator.get(), *context, strand.get(),
                                [self, exchanger, transmission, envelope,
                                    session_id, rollback_reservation](YieldContext& send_y) noexcept {
                                    if (!exchanger->DoInformation(transmission, envelope, send_y)) {
                                        rollback_reservation(session_id);
                                        return;
                                    }
                                    ppp::telemetry::Count("p2p.offer_v1_delivery", 1);
                                });
                            if (!spawned) {
                                rollback_reservation(session_id);
                            }
                            return spawned;
                        };

                        const bool source_spawned = send_offer(
                            source_exchanger, source_transmission,
                            source_offer, source_record.SessionId);
                        const bool destination_spawned = send_offer(
                            destination_exchanger, destination_transmission,
                            destination_offer, destination_record.SessionId);
                        if (source_spawned || destination_spawned) {
                            ppp::telemetry::Log(
                                Level::kInfo, "p2p",
                                "authenticated peer hints scheduled source=%s destination=%s",
                                IPEndPoint::ToAddressString(source_ip).c_str(),
                                IPEndPoint::ToAddressString(destination_ip).c_str());
                            ppp::telemetry::Count("p2p.offer_v1", 1);
                        }
                    });

                if (!scheduled) {
                    rollback_reservation(source_record.SessionId);
                    rollback_reservation(destination_record.SessionId);
                }
                (void)y;
                return scheduled;
            }

            /**
             * @brief Removes NAT mapping when owned by specified exchanger.
             * @param key Exchanger raw pointer owner key.
             * @param ip IPv4 address mapping key.
             * @return true when mapping is removed.
             */
            bool VirtualEthernetSwitcher::DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept {
                if (NULLPTR == key) {
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                NatInformationTable::iterator tail = nats_.find(ip);
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return false;
                }

                NatInformationPtr& nat = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;
                if (key != exchanger.get()) {
                    return false;
                }

                nats_.erase(tail);
                return true;
            }

            bool VirtualEthernetSwitcher::IsPeerRoutingEnabled() const noexcept {
                return NULLPTR != configuration_ &&
                    configuration_->server.peer_routing.enabled &&
                    configuration_->server.subnet;
            }

            void VirtualEthernetSwitcher::RebuildPeerPrefixRibLocked() noexcept {
                peer_prefix_rib_.Clear();
                for (const auto& kv : peer_prefix_gateways_) {
                    const PeerPrefixGatewayRecord& record = kv.second;
                    if (record.VirtualIP == 0) {
                        continue;
                    }

                    for (const auto& prefix : record.Prefixes) {
                        if (prefix.prefix <= 0 || prefix.prefix > net::native::MAX_PREFIX_VALUE_V4) {
                            continue;
                        }

                        uint32_t network = prefix.NetworkHost();
                        if (network == 0) {
                            continue;
                        }
                        peer_prefix_rib_.AddRoute(network, prefix.prefix, record.VirtualIP);
                    }
                }
            }

            void VirtualEthernetSwitcher::BuildPeerRouteTableSnapshot(ppp::app::protocol::PeerRouteTableMessage& table, const Int128* exclude_session_id) noexcept {
                table.Clear();
                if (!IsPeerRoutingEnabled()) {
                    return;
                }

                table.enabled = true;
                table.action = "snapshot";

                SynchronizedObjectScope scope(syncobj_);
                for (const auto& kv : peer_prefix_gateways_) {
                    if (NULLPTR != exclude_session_id && kv.first == *exclude_session_id) {
                        continue;
                    }

                    const PeerPrefixGatewayRecord& record = kv.second;
                    for (const auto& prefix : record.Prefixes) {
                        table.routes.emplace_back(BindPeerRouteGateway(prefix, record.VirtualIP));
                    }
                }
            }

            uint32_t VirtualEthernetSwitcher::FindGatewayVirtualIPForDestination(uint32_t destination) noexcept {
                if (!IsPeerRoutingEnabled()) {
                    return 0;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (!peer_prefix_rib_.IsAvailable()) {
                    return 0;
                }

                return net::native::ForwardInformationTable::GetNextHop(destination, peer_prefix_rib_.GetAllRoutes());
            }

            bool VirtualEthernetSwitcher::DeletePeerPrefixGateway(const Int128& session_id) noexcept {
                bool removed = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    removed = peer_prefix_gateways_.erase(session_id) > 0;
                    if (removed) {
                        RebuildPeerPrefixRibLocked();
                    }
                }

                if (removed && NULLPTR != configuration_ && configuration_->server.peer_routing.distribute) {
                    BroadcastPeerRouteTable(nullof<YieldContext>());
                }
                return removed;
            }

            bool VirtualEthernetSwitcher::UpdatePeerRouteAnnounce(
                const std::shared_ptr<VirtualEthernetExchanger>& exchanger,
                const VirtualEthernetInformationExtensions& request,
                VirtualEthernetInformationExtensions& response) noexcept {

                response.PeerRouteAnnounce = request.PeerRouteAnnounce;
                if (!IsPeerRoutingEnabled()) {
                    response.PeerRouteAnnounce.action = "reject";
                    response.PeerRouteAnnounce.enabled = false;
                    return false;
                }

                if (!request.PeerRouteAnnounce.enabled || request.PeerRouteAnnounce.action != "register") {
                    return false;
                }

                if (NULLPTR == exchanger || exchanger->IsDisposed()) {
                    return false;
                }

                Int128 session_id = exchanger->GetId();
                uint32_t virtual_ip = 0;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (const auto& kv : nats_) {
                        if (NULLPTR != kv.second && kv.second->Exchanger.get() == exchanger.get()) {
                            virtual_ip = kv.first;
                            break;
                        }
                    }
                }

                if (virtual_ip == 0 || IPEndPoint::IsInvalid(IPEndPoint(virtual_ip, IPEndPoint::MinPort))) {
                    response.PeerRouteAnnounce.action = "reject";
                    return false;
                }

                PeerPrefixGatewayRecord record;
                record.SessionId = session_id;
                record.VirtualIP = virtual_ip;
                record.Exchanger = exchanger;

                const ppp::string session_guid =
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                ppp::vector<PeerRouteAllowEntry> allowed_routes;
                if (NULLPTR != configuration_) {
                    allowed_routes.reserve(
                        configuration_->server.peer_routing.allowed_routes.size());
                    for (const auto& route : configuration_->server.peer_routing.allowed_routes) {
                        PeerRouteAllowEntry row;
                        row.network = route.network;
                        row.prefix = route.prefix;
                        row.guid = route.guid;
                        allowed_routes.emplace_back(std::move(row));
                    }
                }
                int dropped = 0;
                for (const auto& prefix : request.PeerRouteAnnounce.prefixes) {
                    if (!prefix.HasAny()) {
                        continue;
                    }
                    PeerRouteAnnounceEntry announced;
                    announced.network = prefix.network;
                    announced.prefix = prefix.prefix;
                    if (!IsPeerRouteAnnouncementAllowed(allowed_routes, session_guid, announced)) {
                        ++dropped;
                        continue;
                    }
                    record.Prefixes.emplace_back(prefix);
                }

                if (record.Prefixes.empty()) {
                    response.PeerRouteAnnounce.action = "reject";
                    response.PeerRouteAnnounce.prefixes.clear();
                    if (dropped > 0) {
                        ppp::telemetry::Count("server.peer_route.announce_rejected", dropped);
                    }
                    return false;
                }

                if (dropped > 0) {
                    ppp::telemetry::Count("server.peer_route.announce_rejected", dropped);
                }

                // Echo only accepted prefixes so the client cannot believe a
                // filtered announcement was fully installed.
                response.PeerRouteAnnounce.prefixes = record.Prefixes;
                response.PeerRouteAnnounce.action = "registered";

                {
                    SynchronizedObjectScope scope(syncobj_);
                    peer_prefix_gateways_[session_id] = std::move(record);
                    RebuildPeerPrefixRibLocked();
                }

                BuildPeerRouteTableSnapshot(response.PeerRouteTable, &session_id);

                if (NULLPTR != configuration_ && configuration_->server.peer_routing.distribute) {
                    BroadcastPeerRouteTable(nullof<YieldContext>());
                }

                return true;
            }

            void VirtualEthernetSwitcher::BroadcastPeerRouteTable(YieldContext& y) noexcept {
                if (!IsPeerRoutingEnabled() || NULLPTR == configuration_ || !configuration_->server.peer_routing.distribute) {
                    return;
                }

                VirtualEthernetInformation info;
                info.Clear();
                info.BandwidthQoS = 0;
                info.IncomingTraffic = std::numeric_limits<UInt64>::max();
                info.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                info.ExpiredTime = std::numeric_limits<UInt32>::max();

                ppp::vector<VirtualEthernetExchangerPtr> targets;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    targets.reserve(exchangers_.size());
                    for (const auto& kv : exchangers_) {
                        if (NULLPTR != kv.second && !kv.second->IsDisposed()) {
                            targets.emplace_back(kv.second);
                        }
                    }
                }

                InformationEnvelope envelope;
                envelope.Base = info;
                envelope.Extensions.Clear();
                for (const auto& target : targets) {
                    ITransmissionPtr transmission = target->GetTransmission();
                    if (NULLPTR == transmission) {
                        continue;
                    }
                    ppp::app::protocol::PeerRouteTableMessage table;
                    Int128 session_id = target->GetId();
                    BuildPeerRouteTableSnapshot(table, &session_id);

                    envelope.Extensions.PeerRouteTable = table;
                    envelope.ExtendedJson = envelope.Extensions.ToJson();
                    target->DoInformation(transmission, envelope, y);
                }
            }

            /**
             * @brief Returns number of currently registered exchangers.
             * @return Exchanger count.
             */
            int VirtualEthernetSwitcher::GetAllExchangerNumber() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return static_cast<int>(exchangers_.size());
            }
        }
    }
}
