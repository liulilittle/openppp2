#include <ppp/app/server/udp/ServerDatagramPortManager.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/collections/Dictionary.h>

/**
 * @file ServerDatagramPortManager.cpp
 * @brief Server UDP relay session manager (P2-e). Owns the datagram session table on the single
 *        io_context thread (no lock) and the SendToDestination data-plane. Session logging stays
 *        on the exchanger side via the on_port_opened callback.
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                ServerDatagramPortManager::ServerDatagramPortManager(ServerUdpRelayHostPorts ports) noexcept
                    : ports_(std::move(ports)) {

                }

                ServerDatagramPortManager::~ServerDatagramPortManager() noexcept = default;

                bool ServerDatagramPortManager::IsValid() const noexcept {
                    return ports_.IsValid();
                }

                VirtualEthernetDatagramPortPtr ServerDatagramPortManager::GetDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    return ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                }

                VirtualEthernetDatagramPortPtr ServerDatagramPortManager::ReleaseDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    return ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                }

                VirtualEthernetDatagramPortPtr ServerDatagramPortManager::AddNewDatagramPort(
                    const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                    VirtualEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        return datagram;
                    }

                    // create_port (the exchanger's NewDatagramPort) validates the transmission and
                    // allocates the concrete port; a null result propagates the failure unchanged.
                    datagram = ports_.create_port(transmission, source);
                    if (NULLPTR == datagram) {
                        return NULLPTR;
                    }

                    // Publish into the table first, then open the socket; on open failure roll the
                    // table back and dispose, matching the exchanger's original emplace/erase order.
                    bool ok = false;
                    if (datagrams_.emplace(source, datagram).second) {
                        ok = datagram->Open();
                        if (!ok) {
                            datagrams_.erase(source);
                        }
                    }

                    if (!ok) {
                        datagram->Dispose();
                        return NULLPTR;
                    }

                    ports_.on_port_opened(transmission, datagram);
                    return datagram;
                }

                bool ServerDatagramPortManager::SendToDestination(const ITransmissionPtr& transmission,
                    const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                    ppp::Byte* packet, int packet_length, bool fin) noexcept {
                    VirtualEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        if (fin) {
                            datagram->MarkFinalize();
                            datagram->Dispose();
                            return true;
                        }

                        return datagram->SendTo(packet, packet_length, destination);
                    }

                    if (fin) {
                        return false;
                    }

                    datagram = AddNewDatagramPort(transmission, source);
                    if (NULLPTR == datagram) {
                        return false;
                    }

                    return datagram->SendTo(packet, packet_length, destination);
                }

                void ServerDatagramPortManager::RebindTransmission(
                    const ITransmissionPtr& transmission) noexcept {
                    // Lock-free by invariant: the resume carrier is pinned to the
                    // exchanger's own io_context (see VirtualEthernetSwitcher
                    // acceptor context pinning), so this walk and the per-port
                    // rebind always run on the manager's single context thread.
                    // If that pinning is ever relaxed, this needs a mutex.
                    for (const auto& entry : datagrams_) {
                        const VirtualEthernetDatagramPortPtr& datagram = entry.second;
                        if (NULLPTR != datagram) {
                            datagram->RebindTransmission(transmission);
                        }
                    }
                }

                void ServerDatagramPortManager::Tick(UInt64 now) noexcept {
                    // Single io_context thread: the library sweep (dispose-on-IsPortAging) is the exact
                    // GC the exchanger ran inline at UpdateAllObjects(datagrams_, now).
                    ppp::collections::Dictionary::UpdateAllObjects(datagrams_, now);
                }

                void ServerDatagramPortManager::Release() noexcept {
                    ppp::collections::Dictionary::ReleaseAllObjects(datagrams_);
                    datagrams_.clear();
                }

            }
        }
    }
}
