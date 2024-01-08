#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>

typedef ppp::coroutines::YieldContext               YieldContext;
typedef std::shared_ptr<boost::asio::io_context>    ContextPtr;
typedef ppp::net::packet::BufferSegment             BufferSegment;

namespace ppp {
    namespace app {
        namespace server {
            VirtualInternetControlMessageProtocol::VirtualInternetControlMessageProtocol(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission) noexcept
                : InternetControlMessageProtocol(transmission->BufferAllocator, exchanger->GetContext())
                , exchanger_(exchanger)
                , transmission_(transmission) {
                
            }

            VirtualInternetControlMessageProtocol::VirtualEthernetExchangerPtr VirtualInternetControlMessageProtocol::GetExchanger() noexcept {
                return exchanger_;
            }

            VirtualInternetControlMessageProtocol::AppConfigurationPtr VirtualInternetControlMessageProtocol::GetConfiguration() noexcept {
                return exchanger_->GetConfiguration();
            }

            bool VirtualInternetControlMessageProtocol::Output(const IPFrame* packet, const IPEndPoint& destinationEP) noexcept {
                if (NULL == packet) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                std::shared_ptr<BufferSegment> messages = const_cast<IPFrame*>(packet)->ToArray(allocator);
                if (NULL == messages) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();

                bool ok = exchanger_->DoEcho(transmission_, messages->Buffer.get(), messages->Length, nullof<YieldContext>());
                if (ok) {
                    return true;
                }

                transmission_->Dispose();
                return false;
            }
        }
    }
}