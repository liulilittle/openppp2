#pragma once

/**
 * @file datagram_manager_stubs.h
 * @brief Spy surface shared by datagram_manager_stubs.cpp and the manager unit test (P2-c).
 */

#include <atomic>

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {
                namespace test {

                    /** @brief Records VEthernetDatagramPort method invocations for assertions.
                     *  Counters are atomic: stubbed port methods run on worker threads while the
                     *  test thread reads them for assertions. */
                    struct DatagramPortSpy final {
                        std::atomic<int> construct{0};
                        std::atomic<int> destruct{0};
                        std::atomic<int> dispose{0};
                        std::atomic<int> sendto{0};
                        std::atomic<int> onmessage{0};
                        std::atomic<int> finalize{0};
                        std::atomic<int> rebind{0};
                        std::atomic<int> last_action{-1};
                        std::atomic<const void*> transmission{nullptr};

                        void Reset() noexcept;
                    };

                    /** @brief Process-wide spy instance backing the stubbed port. */
                    DatagramPortSpy& DatagramPortSpyInstance() noexcept;

                }
            }
        }
    }
}
