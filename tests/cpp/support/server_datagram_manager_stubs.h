#pragma once

/**
 * @file server_datagram_manager_stubs.h
 * @brief Spy surface shared by server_datagram_manager_stubs.cpp and the manager unit test (P2-e).
 */

#include <atomic>

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    /** @brief Records VirtualEthernetDatagramPort method invocations for assertions.
                     *  Counters are atomic: stubbed port methods run on worker threads while the
                     *  test thread reads them for assertions. */
                    struct ServerDatagramPortSpy final {
                        std::atomic<int> construct{0};
                        std::atomic<int> destruct{0};
                        std::atomic<int> dispose{0};
                        std::atomic<int> open{0};
                        std::atomic<int> sendto{0};
                        std::atomic<int> rebind{0};

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed port. */
                    ServerDatagramPortSpy& ServerDatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
