#include "static_datagram_manager_stubs.h"

#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>

/**
 * @file static_datagram_manager_stubs.cpp
 * @brief Surgical VirtualEthernetDatagramPortStatic stub for StaticDatagramPortManager tests (P2-f).
 *
 * Replaces the real static-echo port (which drags in the exchanger, switcher, packet codec and a
 * live UDP socket) with a spyable no-op. The manager only shuffles/ages ports and calls their
 * public surface (Open/SendTo/Dispose/IsPortAging), so recording those calls here is enough to
 * assert the session-table, race-resolution and GC behaviour in isolation. socket_ still needs a
 * real io_context to construct, so a shared idle one is used; the stub never opens it.
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    void StaticDatagramPortSpy::Reset() noexcept {
                        construct = destruct = dispose = open = sendto = 0;
                    }

                    StaticDatagramPortSpy& StaticDatagramPortSpyInstance() noexcept {
                        static StaticDatagramPortSpy spy;
                        return spy;
                    }

                }
            }
        }
    }
}

namespace {
    std::shared_ptr<boost::asio::io_context> StubIoContext() noexcept {
        static std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
        return context;
    }
}

namespace ppp {
    namespace app {
        namespace server {

            VirtualEthernetDatagramPortStatic::VirtualEthernetDatagramPortStatic(const VirtualEthernetExchangerPtr& exchanger,
                const std::shared_ptr<boost::asio::io_context>& context, uint32_t source_ip, int source_port) noexcept
                : disposed_(false)
                , in_(false)
                , onlydns_(0)
                , source_ip_(source_ip)
                , source_port_(source_port)
                , timeout_(0)
                , socket_(*context)
                , exchanger_(exchanger)
                , context_(context) {
                udp::test::StaticDatagramPortSpyInstance().construct++;
            }

            VirtualEthernetDatagramPortStatic::~VirtualEthernetDatagramPortStatic() noexcept {
                udp::test::StaticDatagramPortSpyInstance().destruct++;
            }

            void VirtualEthernetDatagramPortStatic::Dispose() noexcept {
                disposed_ = true;
                udp::test::StaticDatagramPortSpyInstance().dispose++;
            }

            bool VirtualEthernetDatagramPortStatic::Open() noexcept {
                udp::test::StaticDatagramPortSpyInstance().open++;
                return true;
            }

            bool VirtualEthernetDatagramPortStatic::SendTo(const void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::StaticDatagramPortSpyInstance().sendto++;
                return true;
            }

        }
    }
}
