#include <ppp/app/server/udp/StaticDatagramPortManager.h>
#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/IDisposable.h>

/**
 * @file StaticDatagramPortManager.cpp
 * @brief Static-echo UDP relay session manager (P2-f). Owns the static_echo_datagram_ports_ table
 *        behind its own lock, reproducing the exchanger's open-outside-lock / recheck-under-lock /
 *        dispose-outside-lock discipline verbatim. Session logging stays exchanger-side via
 *        on_port_opened.
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                StaticDatagramPortManager::StaticDatagramPortManager(StaticUdpRelayHostPorts ports) noexcept
                    : ports_(std::move(ports)) {

                }

                StaticDatagramPortManager::~StaticDatagramPortManager() noexcept = default;

                bool StaticDatagramPortManager::IsValid() const noexcept {
                    return ports_.IsValid();
                }

                VirtualEthernetDatagramPortStaticPtr StaticDatagramPortManager::GetOrAddDatagramPort(
                    uint64_t key, uint32_t source_ip, int source_port) noexcept {
                    VirtualEthernetDatagramPortStaticPtr datagram_port;

                    // Fast path: a port for this key may already exist; check under the lock without
                    // allocating a socket.
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        if (ppp::collections::Dictionary::TryGetValue(static_echo_datagram_ports_, key, datagram_port)) {
                            return datagram_port;
                        }
                    }

                    // Slow path: create and Open() the socket BEFORE acquiring the lock, so the
                    // potentially blocking OS syscalls never run while the lock is held.
                    VirtualEthernetDatagramPortStaticPtr new_port = ports_.create_port(source_ip, source_port);
                    if (NULLPTR == new_port) {
                        return NULLPTR;
                    }

                    if (!new_port->Open()) {
                        new_port->Dispose();
                        return NULLPTR;
                    }

                    // Under the lock: another thread may have inserted a port for the same key during
                    // the Open() window; the recheck resolves the race and picks a single winner.
                    bool inserted = false;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        if (!ppp::collections::Dictionary::TryGetValue(static_echo_datagram_ports_, key, datagram_port)) {
                            inserted = ppp::collections::Dictionary::TryAdd(static_echo_datagram_ports_, key, new_port);
                            if (inserted) {
                                datagram_port = new_port;
                            }
                        }
                    }

                    if (inserted) {
                        ports_.on_port_opened(new_port);
                    }
                    else {
                        // Lost the insertion race (or the entry reappeared); dispose our redundant port.
                        new_port->Dispose();
                    }

                    return datagram_port;
                }

                VirtualEthernetDatagramPortStaticPtr StaticDatagramPortManager::ReleaseDatagramPort(uint64_t key) noexcept {
                    VirtualEthernetDatagramPortStaticPtr datagram_port;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        ppp::collections::Dictionary::TryRemove(static_echo_datagram_ports_, key, datagram_port);
                    }

                    if (NULLPTR != datagram_port) {
                        datagram_port->Dispose();
                    }

                    return datagram_port;
                }

                void StaticDatagramPortManager::Tick(UInt64 now) noexcept {
                    // Phase 1: collect stale ports and erase them from the map under the lock.
                    ppp::vector<VirtualEthernetDatagramPortStaticPtr> stale_ports;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        for (auto tail = static_echo_datagram_ports_.begin(); tail != static_echo_datagram_ports_.end();) {
                            const VirtualEthernetDatagramPortStaticPtr& port = tail->second;
                            if (NULLPTR == port || port->IsPortAging(now)) {
                                if (NULLPTR != port) {
                                    stale_ports.emplace_back(port);
                                }

                                tail = static_echo_datagram_ports_.erase(tail);
                            }
                            else {
                                ++tail;
                            }
                        }
                    }

                    // Phase 2: dispose outside the lock to avoid holding it across socket-close syscalls.
                    for (auto& port : stale_ports) {
                        ppp::IDisposable::Dispose(*port);
                    }
                }

                void StaticDatagramPortManager::Release() noexcept {
                    ppp::unordered_map<uint64_t, VirtualEthernetDatagramPortStaticPtr> static_echo_datagram_ports;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        static_echo_datagram_ports = std::move(static_echo_datagram_ports_);
                        static_echo_datagram_ports_.clear();
                    }

                    ppp::collections::Dictionary::ReleaseAllObjects(static_echo_datagram_ports);
                }

            }
        }
    }
}
