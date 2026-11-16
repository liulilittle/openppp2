#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/app/client/udp/DirectDatagramFlow.h>

/**
 * @file ClientDatagramPortManager.cpp
 * @brief Client UDP relay session manager (P2-c). Owns the datagram session tables behind an
 *        independent lock and the SendTo/ReceiveFromDestination data-plane. Diagnostic
 *        telemetry stays on the exchanger side; the NAT-timeout GC lands in the next increment.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                ClientDatagramPortManager::ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept
                    : ports_(std::move(ports)) {

                }

                ClientDatagramPortManager::~ClientDatagramPortManager() noexcept = default;

                bool ClientDatagramPortManager::IsValid() const noexcept {
                    return ports_.IsValid();
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::AddNewDatagramPort(
                    const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        if (closed_) {
                            return NULLPTR;
                        }

                        VEthernetDatagramPortPtr winner =
                            ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                        if (NULLPTR != winner) {
                            return winner;
                        }
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return NULLPTR;
                    }

                    // Port creation may block or re-enter the host, so it stays outside the manager lock.
                    VEthernetDatagramPortPtr candidate = ports_.create_port(transmission, source);
                    if (NULLPTR == candidate) {
                        return NULLPTR;
                    }

                    VEthernetDatagramPortPtr winner;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        if (!closed_) {
                            winner = ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                            if (NULLPTR == winner) {
                                datagrams_.emplace(source, candidate);
                                return candidate;
                            }
                        }
                    }

                    // A candidate that lost publication must never finalize or erase the winner.
                    candidate->MarkFinalize();
                    candidate->Dispose();
                    return winner;
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::GetDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::ReleaseDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::ReleaseDatagramPortIf(
                    const boost::asio::ip::udp::endpoint& source,
                    const VEthernetDatagramPort* expected) noexcept {
                    if (NULLPTR == expected) {
                        return NULLPTR;
                    }

                    std::lock_guard<std::mutex> scope(syncobj_);
                    auto tail = datagrams_.find(source);
                    if (tail == datagrams_.end() || tail->second.get() != expected) {
                        return NULLPTR;
                    }

                    VEthernetDatagramPortPtr datagram = std::move(tail->second);
                    datagrams_.erase(tail);
                    return datagram;
                }

                bool ClientDatagramPortManager::SendTo(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, const void* packet, int packet_size) noexcept {
                    return SendTo(source, destination, packet, packet_size, routing::RoutingAction::Auto);
                }

                bool ClientDatagramPortManager::SendTo(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, const void* packet, int packet_size,
                    routing::RoutingAction action) noexcept {
#if defined(_ANDROID)
                    if (action == routing::RoutingAction::Auto && destination.address().is_v4() &&
                        ports_.is_bypass_ip && ports_.is_bypass_ip(destination.address())) {
                        return SendTo(source, destination, packet, packet_size, routing::RoutingAction::Direct, "", nullptr);
                    }
#endif
                    if (action == routing::RoutingAction::Direct) {
                        return SendTo(source, destination, packet, packet_size, action, "", nullptr);
                    }
                    if (NULLPTR == packet || packet_size < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    ITransmissionPtr transmission = ports_.get_transmission();
                    if (NULLPTR == transmission) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    VEthernetDatagramPortPtr datagram = AddNewDatagramPort(transmission, source);
                    if (NULLPTR == datagram) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpMappingFailed);
                    }

                    return datagram->SendTo(packet, packet_size, destination, action);
                }

                bool ClientDatagramPortManager::SendTo(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, const void* packet, int packet_size,
                    routing::RoutingAction action, const std::string& domain,
                    const std::shared_ptr<const policy::PolicySnapshot>& snapshot, bool resolve_domain) noexcept {
                    if (action != routing::RoutingAction::Direct && !resolve_domain && !snapshot) {
                        return SendTo(source, destination, packet, packet_size, action);
                    }
                    if (!packet || packet_size < 1 || packet_size > 65507 || !destination.address().is_v4() ||
                        !destination.port() || (ports_.is_disposed && ports_.is_disposed())) return false;
                    if (snapshot && source.address().is_v4() && UdpRelayIdentity::IsIdentity(source.address().to_v4().to_uint()))
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    try {
                        const auto normalized = NormalizeUdpFlowDomain(domain);
                        const auto key = FlowKey(source.address().to_string() + ":" + std::to_string(source.port()),
                            (normalized.empty() || resolve_domain ? destination.address().to_string() : normalized) + ":" + std::to_string(destination.port()),
                            normalized, snapshot ? -1 : static_cast<int>(action));
                        std::shared_ptr<DirectDatagramFlow> flow;
                        {
                            std::lock_guard<std::mutex> lock(syncobj_);
                            if (closed_) return false;
                            for (auto it = direct_flows_.begin(); it != direct_flows_.end();) {
                                if (it->second->IsClosed()) it = direct_flows_.erase(it);
                                else ++it;
                            }
                            auto found = direct_flows_.find(key);
                            if (found != direct_flows_.end()) {
                                if (!found->second->IsClosed()) flow = found->second;
                                else direct_flows_.erase(found);
                            }
                        }
                        if (!flow) {
                            auto context = ports_.get_context ? ports_.get_context() : nullptr;
                            auto owner = ports_.get_owner ? ports_.get_owner() : nullptr;
                            if (!context || !owner) return false;
                            auto address = !resolve_domain && ports_.rewrite_fakeip ? ports_.rewrite_fakeip(destination.address()) : destination.address();
                            if (!address.is_v4() || address.is_unspecified()) return false;
                            auto protector = ports_.get_direct_protector ? ports_.get_direct_protector() : ClientUnderlyingSocketProtector();
                            auto provider = ports_.create_direct_transport ? ports_.create_direct_transport() : nullptr;
                            if (!resolve_domain && action == routing::RoutingAction::Direct && !protector && !provider) return false;
                            auto config = ports_.get_configuration();
                            if (!config) return false;
                            auto relay = std::make_shared<boost::asio::ip::udp::endpoint>();
                            DirectDatagramFlow::Resolve resolve;
                            DirectDatagramFlow::TunnelSend tunnel_send = [this, owner, relay](const boost::asio::ip::udp::endpoint& target, const void* data, int length) {
                                return SendTo(*relay, target, data, length, routing::RoutingAction::Proxy);
                            };
                            if (resolve_domain) {
                                if (!snapshot || domain.empty() || !ports_.resolve_policy_destination) return false;
                                resolve = [this, owner, domain, snapshot](ppp::coroutines::YieldContext& y, boost::asio::ip::address& address) {
                                    return ports_.resolve_policy_destination(domain, snapshot, y, address);
                                };
                            }
                            auto candidate = std::make_shared<DirectDatagramFlow>(context, owner,
                                boost::asio::ip::udp::endpoint(address, destination.port()), destination,
                                protector, provider, snapshot, destination.port() == 53 ? config->udp.dns.timeout : config->udp.inactive.timeout,
                                [this, owner, source](const boost::asio::ip::udp::endpoint& remote, void* data, int length) {
                                    if (!TryHandleDatagram(source, remote, data, length))
                                        ports_.datagram_output(source, remote, nullptr, data, length, false);
                                }, resolve, tunnel_send, domain, action == routing::RoutingAction::Proxy,
                                [this, owner, relay]() { if (relay->port()) ReleaseDatagramHandler(*relay); }, config->udp.dns.timeout,
                                [this, owner]() { RecordPolicyReject(); });
                            {
                                std::lock_guard<std::mutex> lock(syncobj_);
                                if (closed_) return false;
                                // Globally bound outstanding direct sessions as well as per-flow buffers.
                                if (direct_flows_.size() >= 4096) return false;
                                auto inserted = direct_flows_.emplace(key, candidate);
                                flow = inserted.first->second;
                                if (inserted.second) {
                                    // Reserved internal identity is carried by the existing SENDTO
                                    // protocol only; it is never installed as a host address/route.
                                    std::uint32_t relay_address;
                                    std::uint16_t relay_port;
                                    if (!UdpRelayIdentity::Next(relay_sequence_, relay_address, relay_port)) {
                                        direct_flows_.erase(inserted.first); return false;
                                    }
                                    *relay = {boost::asio::ip::address_v4(relay_address), relay_port};
                                    auto weak = std::weak_ptr<DirectDatagramFlow>(flow);
                                    datagram_handlers_.emplace(*relay, [weak](const auto&, const auto& remote, void* data, int length) {
                                        if (auto locked = weak.lock()) locked->TunnelReply(remote, data, length);
                                        return true;
                                    });
                                }
                            }
                        }
                        return flow->Send(packet, packet_size);
                    } catch (...) { return false; }
                }

                bool ClientDatagramPortManager::TrySendPinned(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, const void* packet, int packet_size,
                    const std::string& domain, bool& accepted, bool original_is_fake) noexcept {
                    accepted = false;
                    try {
                        const auto normalized = NormalizeUdpFlowDomain(domain);
                        const auto key = FlowKey(source.address().to_string() + ":" + std::to_string(source.port()),
                            (normalized.empty() || original_is_fake ? destination.address().to_string() : normalized) + ":" + std::to_string(destination.port()), normalized, -1);
                        std::shared_ptr<DirectDatagramFlow> flow;
                        {
                            std::lock_guard<std::mutex> lock(syncobj_);
                            if (closed_) return false;
                            auto found = direct_flows_.find(key);
                            if (found == direct_flows_.end() || found->second->IsClosed()) return false;
                            flow = found->second;
                        }
                        accepted = flow->Send(packet, packet_size);
                        return true;
                    } catch (...) { return false; }
                }

                bool ClientDatagramPortManager::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length) noexcept {
                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return false;
                    }

                    if (NULLPTR != packet && packet_length > 0) {
                        if (TryHandleDatagram(source, destination, packet, packet_length)) {
                            return true;
                        }
                        if (source.address().is_v4() && UdpRelayIdentity::IsIdentity(source.address().to_v4().to_uint())) {
                            const auto identity = (static_cast<std::uint64_t>(source.address().to_v4().to_uint() & 0xffffu) << 16) | source.port();
                            std::lock_guard<std::mutex> lock(syncobj_);
                            if (identity > 1023 && identity <= relay_sequence_) return true;
                        }
                    }

                    VEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        if (NULLPTR != packet && packet_length > 0) {
                            datagram->OnMessage(nullptr, packet, packet_length, destination);
                        }
                        else {
                            datagram->MarkFinalize();
                            datagram->Dispose();
                        }
                    }
                    elif(NULLPTR != packet && packet_length > 0) {
                        ports_.datagram_output(source, destination, nullptr, packet, packet_length, false);
                    }

                    return true;
                }

                bool ClientDatagramPortManager::OnSendTo(const ITransmissionPtr& transmission,
                    const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                    ppp::Byte* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept {
                    (void)transmission;
                    (void)y;
                    return ReceiveFromDestination(source, destination, packet, packet_length);
                }

                bool ClientDatagramPortManager::TryHandleDatagram(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, void* packet, int packet_size) noexcept {
                    DatagramPacketHandler handler;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        auto tail = datagram_handlers_.find(source);
                        if (tail != datagram_handlers_.end()) {
                            handler = tail->second;
                        }
                    }

                    if (!handler) {
                        return false;
                    }

                    return handler(source, destination, packet, packet_size);
                }

                bool ClientDatagramPortManager::RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& source,
                    const DatagramPacketHandler& handler) noexcept {
                    if (!handler) {
                        return false;
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    std::lock_guard<std::mutex> scope(syncobj_);
                    if (closed_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }
                    datagram_handlers_[source] = handler;
                    return true;
                }

                bool ClientDatagramPortManager::ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& source) noexcept {
                    bool removed = false;
                    VEthernetDatagramPortPtr datagram;
                    std::vector<std::shared_ptr<DirectDatagramFlow>> direct;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        removed = datagram_handlers_.erase(source) > 0;
                        datagram = ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                        const auto identity = source.address().to_string() + ":" + std::to_string(source.port());
                        for (auto it = direct_flows_.begin(); it != direct_flows_.end();) {
                            if (std::get<0>(it->first) == identity) { direct.push_back(it->second); it = direct_flows_.erase(it); }
                            else ++it;
                        }
                    }
                    for (auto& flow : direct) flow->Close();

                    if (NULLPTR != datagram) {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                    }

                    return removed;
                }

                bool ClientDatagramPortManager::RebindTransmission(
                    const ITransmissionPtr& transmission) noexcept {
                    ppp::vector<VEthernetDatagramPortPtr> datagrams;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        datagrams.reserve(datagrams_.size());
                        for (auto&& kv : datagrams_) {
                            if (NULLPTR != kv.second) {
                                datagrams.emplace_back(kv.second);
                            }
                        }
                    }

                    for (auto&& datagram : datagrams) {
                        if (!datagram->RebindTransmission(transmission)) {
                            // Never leave a partially rebound flow table capable of using mixed carriers.
                            for (auto&& retained : datagrams) {
                                retained->RebindTransmission(NULLPTR);
                            }
                            return false;
                        }
                    }
                    return true;
                }

                void ClientDatagramPortManager::ResetPorts() noexcept {
                    ppp::vector<VEthernetDatagramPortPtr> stale;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        stale.reserve(datagrams_.size());
                        for (auto&& kv : datagrams_) {
                            if (NULLPTR != kv.second) {
                                stale.emplace_back(kv.second);
                            }
                        }
                        datagrams_.clear();
                    }

                    for (auto&& datagram : stale) {
                        datagram->MarkFinalize();
                        datagram->RebindTransmission(NULLPTR);
                        datagram->Dispose();
                    }
                }

                void ClientDatagramPortManager::Tick(UInt64 now) noexcept {
                    {
                        std::lock_guard<std::mutex> lock(syncobj_);
                        for (auto it = direct_flows_.begin(); it != direct_flows_.end();) {
                            if (it->second->IsClosed()) it = direct_flows_.erase(it);
                            else ++it;
                        }
                    }
                    // Phase 1: snapshot the table under the lock.
                    ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> candidates;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        candidates.reserve(datagrams_.size());
                        for (auto&& kv : datagrams_) {
                            candidates.emplace_back(kv.first, kv.second);
                        }
                    }

                    // Phase 2: decide aging outside the lock (IsPortAging is cheap and non-reentrant).
                    ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> stale_candidates;
                    for (auto&& kv : candidates) {
                        VEthernetDatagramPortPtr& datagram = kv.second;
                        if (NULLPTR == datagram || datagram->IsPortAging(now)) {
                            stale_candidates.emplace_back(kv.first, datagram);
                        }
                    }

                    // Phase 3: erase under the lock, but only if the entry is still the same object
                    // (identity check guards against a port replaced during the unlocked window).
                    ppp::vector<VEthernetDatagramPortPtr> stale;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        for (auto&& stale_candidate : stale_candidates) {
                            auto tail = datagrams_.find(stale_candidate.first);
                            auto endl = datagrams_.end();
                            if (tail == endl || tail->second != stale_candidate.second) {
                                continue;
                            }

                            VEthernetDatagramPortPtr datagram = std::move(tail->second);
                            datagrams_.erase(tail);
                            if (NULLPTR != datagram) {
                                stale.emplace_back(std::move(datagram));
                            }
                        }
                    }

                    // Phase 4: dispose outside the lock so Dispose->Finalize->Release cannot self-deadlock.
                    for (auto&& datagram : stale) {
                        datagram->Dispose();
                    }
                }

                void ClientDatagramPortManager::Release() noexcept {
                    ppp::vector<VEthernetDatagramPortPtr> stale;
                    std::vector<std::shared_ptr<DirectDatagramFlow>> direct;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        closed_ = true;
                        for (auto& item : direct_flows_) direct.push_back(item.second);
                        direct_flows_.clear();
                        for (auto&& kv : datagrams_) {
                            if (NULLPTR != kv.second) {
                                stale.emplace_back(kv.second);
                            }
                        }
                        datagrams_.clear();
                        datagram_handlers_.clear();
                    }
                    for (auto& flow : direct) flow->Close();

                    for (auto&& datagram : stale) {
                        datagram->Dispose();
                    }
                }

            }
        }
    }
}
