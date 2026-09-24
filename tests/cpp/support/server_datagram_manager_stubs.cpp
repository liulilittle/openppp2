#include "server_datagram_manager_stubs.h"

#include <ppp/app/server/VirtualEthernetDatagramPort.h>

/**
 * @file server_datagram_manager_stubs.cpp
 * @brief Surgical VirtualEthernetDatagramPort stub for ServerDatagramPortManager unit tests (P2-e).
 *
 * Replaces the real port implementation (which drags in the exchanger, switcher, transmissions,
 * DNS cache and a live UDP socket) with a spyable no-op. The manager only shuffles/ages ports and
 * calls their public surface (Open/SendTo/Dispose/MarkFinalize/IsPortAging), so recording those
 * calls here is enough to assert the session-table, data-plane and GC behaviour in isolation.
 * The socket_ member still needs a real io_context to construct, so a shared idle one is used;
 * the stub never opens it.
 */

namespace ppp {
    namespace app {
        namespace server {
            namespace udp {
                namespace test {

                    void ServerDatagramPortSpy::Reset() noexcept {
                        construct = destruct = dispose = open = sendto = rebind = 0;
                    }

                    ServerDatagramPortSpy& ServerDatagramPortSpyInstance() noexcept {
                        static ServerDatagramPortSpy spy;
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

            VirtualEthernetDatagramPort::VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger,
                udp::ServerUdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , in_(false)
                , finalize_(false)
                , timeout_(0)
                , context_(StubIoContext())
                , socket_(*context_)
                , ports_(std::move(ports))
                , exchanger_(exchanger)
                , transmission_(transmission)
                , sourceEP_(sourceEP) {
                udp::test::ServerDatagramPortSpyInstance().construct++;
            }

            VirtualEthernetDatagramPort::~VirtualEthernetDatagramPort() noexcept {
                udp::test::ServerDatagramPortSpyInstance().destruct++;
            }

            void VirtualEthernetDatagramPort::Dispose() noexcept {
                disposed_ = true;
                udp::test::ServerDatagramPortSpyInstance().dispose++;
            }

            bool VirtualEthernetDatagramPort::Open() noexcept {
                udp::test::ServerDatagramPortSpyInstance().open++;
                return true;
            }

            bool VirtualEthernetDatagramPort::RebindTransmission(const ITransmissionPtr& transmission) noexcept {
                transmission_ = transmission;
                udp::test::ServerDatagramPortSpyInstance().rebind++;
                return true;
            }

            bool VirtualEthernetDatagramPort::SendTo(const void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::ServerDatagramPortSpyInstance().sendto++;
                return true;
            }

        }
    }
}
