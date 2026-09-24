#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

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

                bool ClientDatagramPortManager::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length) noexcept {
                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return false;
                    }

                    if (NULLPTR != packet && packet_length > 0) {
                        if (TryHandleDatagram(source, destination, packet, packet_length)) {
                            return true;
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
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        removed = datagram_handlers_.erase(source) > 0;
                        datagram = ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                    }

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
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        closed_ = true;
                        for (auto&& kv : datagrams_) {
                            if (NULLPTR != kv.second) {
                                stale.emplace_back(kv.second);
                            }
                        }
                        datagrams_.clear();
                        datagram_handlers_.clear();
                    }

                    for (auto&& datagram : stale) {
                        datagram->Dispose();
                    }
                }

            }
        }
    }
}
