#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;

namespace ppp {
    namespace app {
        namespace client {
            VEthernetDatagramPort::VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , finalize_(false)
                , timeout_(0)
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(exchanger->GetConfiguration())
                , sourceEP_(sourceEP) {
                auto context = transmission->GetContext();
                buffer_ = Executors::GetCachedBuffer(context.get());
                Update();
            }

            VEthernetDatagramPort::~VEthernetDatagramPort() noexcept {
                Finalize();
            }

            void VEthernetDatagramPort::Finalize() noexcept {
                if (sendto_ && !finalize_) {
                    if (!exchanger_->DoSendTo(transmission_, sourceEP_, sourceEP_, NULL, 0, nullof<YieldContext>())) {
                        transmission_->Dispose();
                    }
                }

                disposed_ = true;
                sendto_ = false;
                finalize_ = true;
                exchanger_->ReleaseDatagramPort(sourceEP_);
            }

            void VEthernetDatagramPort::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(std::bind(&VEthernetDatagramPort::Finalize, self));
            }

            bool VEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    return false;
                }

                boost::asio::ip::address address = destinationEP.address();
                if (address.is_unspecified()) {
                    return false;
                }

                bool ok = exchanger_->DoSendTo(transmission_, sourceEP_, destinationEP, (Byte*)packet, packet_length, nullof<YieldContext>());
                if (ok) {
                    sendto_ = true;
                    if (destinationPort != PPP_DNS_DEFAULT_PORT) {
                        onlydns_ = false;
                    }

                    Update();
                }
                else {
                    transmission_->Dispose();
                }
                return ok;
            }

            std::shared_ptr<VEthernetDatagramPort> VEthernetDatagramPort::GetReference() noexcept {
                return shared_from_this();
            }

            VEthernetDatagramPort::VEthernetExchangerPtr VEthernetDatagramPort::GetExchanger() noexcept {
                return exchanger_;
            }

            VEthernetDatagramPort::ContextPtr VEthernetDatagramPort::GetContext() noexcept {
                return transmission_->GetContext();
            }

            VEthernetDatagramPort::AppConfigurationPtr VEthernetDatagramPort::GetConfiguration() noexcept {
                return configuration_;
            }

            boost::asio::ip::udp::endpoint& VEthernetDatagramPort::GetLocalEndPoint() noexcept {
                return sourceEP_;
            }

            void VEthernetDatagramPort::OnMessage(void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (exchanger) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = exchanger->GetSwitcher();
                    if (switcher) {
                        switcher->DatagramOutput(sourceEP_, destinationEP, packet, packet_length);
                    }
                }
            }
        }
    }
}