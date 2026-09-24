#pragma once

/**
 * @file static_datagram_manager_stubs.h
 * @brief Spy surface shared by static_datagram_manager_stubs.cpp and the manager unit test (P2-f).
 */

#include <atomic>

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    /** @brief Records VirtualEthernetDatagramPortStatic method invocations for assertions.
                     *  Counters are atomic: stubbed port methods run on worker threads while the
                     *  test thread reads them for assertions. */
                    struct StaticDatagramPortSpy final {
                        std::atomic<int> construct{0};
                        std::atomic<int> destruct{0};
                        std::atomic<int> dispose{0};
                        std::atomic<int> open{0};
                        std::atomic<int> sendto{0};

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed static port. */
                    StaticDatagramPortSpy& StaticDatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
