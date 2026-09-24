#pragma once

/**
 * @file StaticDatagramPortManager.h
 * @brief Self-contained static-echo UDP relay session manager (P2-f).
 *
 * Extracts the static_echo_datagram_ports_ session table and its dedicated lock out of the
 * God-Object VirtualEthernetExchanger. Unlike the dynamic datagram table (P2-e, single-thread
 * lock-free), the static-echo table is genuinely contended, so this manager keeps its OWN lock
 * and preserves the exact concurrency discipline the exchanger used: open the socket outside the
 * lock, re-check under the lock, and dispose aged/lost ports outside the lock. Consumes the
 * exchanger's port factory and session logger through an injected StaticUdpRelayHostPorts.
 */

#include <ppp/stdafx.h>
#include <ppp/app/server/udp/StaticUdpRelayHost.h>

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {

                class StaticDatagramPortManager final {
                public:
                    explicit StaticDatagramPortManager(StaticUdpRelayHostPorts ports) noexcept;
                    ~StaticDatagramPortManager() noexcept;

                    StaticDatagramPortManager(const StaticDatagramPortManager&) = delete;
                    StaticDatagramPortManager& operator=(const StaticDatagramPortManager&) = delete;

                    /** @brief Whether the injected ports surface is complete. */
                    bool IsValid() const noexcept;

                    /**
                     * @brief Find-or-create the static-echo port for key, opening its socket outside the lock.
                     * @param key         MAKE_QWORD(source_ip, source_port) session key.
                     * @param source_ip   Source IPv4 (network byte order) passed to the port factory.
                     * @param source_port Source UDP port passed to the port factory.
                     * @return The winning port (existing, freshly inserted, or the race winner); null on failure.
                     */
                    VirtualEthernetDatagramPortStaticPtr GetOrAddDatagramPort(uint64_t key, uint32_t source_ip, int source_port) noexcept;

                    /** @brief Remove, dispose, and return the static-echo port for key, or null. */
                    VirtualEthernetDatagramPortStaticPtr ReleaseDatagramPort(uint64_t key) noexcept;

                    /** @brief NAT-timeout sweep: collect aging ports under the lock, dispose them outside it. */
                    void Tick(UInt64 now) noexcept;

                    /** @brief Dispose every port and clear the table (exchanger teardown). */
                    void Release() noexcept;

                private:
                    StaticUdpRelayHostPorts                                              ports_;
                    /** @brief Dedicated lock guarding static_echo_datagram_ports_ (was exchanger::static_echo_syncobj_). */
                    std::mutex                                                          syncobj_;
                    /** @brief Active static-echo UDP relay ports keyed by source_ip:source_port hash. */
                    ppp::unordered_map<uint64_t, VirtualEthernetDatagramPortStaticPtr>  static_echo_datagram_ports_;
                };

            }
        }
    }
}
