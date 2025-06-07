#include <ppp/app/server/VirtualInternetControlMessageProtocolStatic.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>

typedef ppp::coroutines::YieldContext               YieldContext;
typedef std::shared_ptr<boost::asio::io_context>    ContextPtr;
typedef ppp::net::packet::BufferSegment             BufferSegment;
typedef ppp::app::protocol::VirtualEthernetPacket   VirtualEthernetPacket;

namespace ppp {
    namespace app {
        namespace server {
            VirtualInternetControlMessageProtocolStatic::VirtualInternetControlMessageProtocolStatic(const VirtualEthernetExchangerPtr& exchanger, const AppConfigurationPtr& configuration, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : InternetControlMessageProtocol(configuration->GetBufferAllocator(), context)
                , exchanger_(exchanger) {
                switcher_ = exchanger->GetSwitcher();
            }

            VirtualInternetControlMessageProtocolStatic::AppConfigurationPtr VirtualInternetControlMessageProtocolStatic::GetConfiguration() noexcept {
                return exchanger_->GetConfiguration();
            }

            bool VirtualInternetControlMessageProtocolStatic::Output(const IPFrame* packet, const IPEndPoint& destinationEP) noexcept {
                if (NULL == packet) {
                    return false;
                }

                int session_id = exchanger_->static_echo_session_id_;
                if (session_id < 0) {
                    return false;
                }

                boost::asio::ip::udp::socket& socket = switcher_->static_echo_socket_;
                if (!socket.is_open()) {
                    return false;
                }

                int packet_length;
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                std::shared_ptr<Byte> packet_output = VirtualEthernetPacket::Pack(exchanger_->GetConfiguration(), allocator,
                    switcher_->static_echo_protocol_, switcher_->static_echo_transport_, session_id, packet, packet_length);

                if (NULL == packet_output) {
                    return false;
                }

                boost::system::error_code ec;
                socket.send_to(boost::asio::buffer(packet_output.get(), packet_length),
                    exchanger_->static_echo_source_ep_, boost::asio::socket_base::message_end_of_record, ec);

                if (ec) {
                    return false;
                }
                
                auto statistics = exchanger_->GetStatistics(); 
                if (NULL != statistics) {
                    statistics->AddOutgoingTraffic(packet_length);
                }
                
                return true;
            }
        }
    }
}