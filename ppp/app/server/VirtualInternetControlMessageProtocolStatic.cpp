#include <ppp/app/server/VirtualInternetControlMessageProtocolStatic.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualInternetControlMessageProtocolStatic.cpp
 * @brief Implements static-echo ICMP forwarding for virtual sessions.
 */

typedef ppp::coroutines::YieldContext               YieldContext;
typedef std::shared_ptr<boost::asio::io_context>    ContextPtr;
typedef ppp::net::packet::BufferSegment             BufferSegment;
typedef ppp::app::protocol::VirtualEthernetPacket   VirtualEthernetPacket;

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Creates static ICMP forwarder and caches switcher reference.
             * @param exchanger Exchanger providing static-echo session metadata.
             * @param configuration App configuration for allocator initialization.
             * @param context I/O context used by the protocol engine.
             */
            VirtualInternetControlMessageProtocolStatic::VirtualInternetControlMessageProtocolStatic(const VirtualEthernetExchangerPtr& exchanger, const AppConfigurationPtr& configuration, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : InternetControlMessageProtocol(configuration->GetBufferAllocator(), context)
                , exchanger_(exchanger) {
                switcher_ = exchanger->GetSwitcher();
            }

            /**
             * @brief Returns the current configuration from the owning exchanger.
             * @return Shared pointer to application configuration.
             */
            VirtualInternetControlMessageProtocolStatic::AppConfigurationPtr VirtualInternetControlMessageProtocolStatic::GetConfiguration() noexcept {
                return exchanger_->GetConfiguration();
            }

            /**
             * @brief Packs an IP frame and sends it via static echo UDP socket.
             * @param packet IP frame to transmit.
             * @param destinationEP Destination endpoint metadata.
             * @return true when packet is sent successfully; otherwise false.
             */
            bool VirtualInternetControlMessageProtocolStatic::Output(const IPFrame* packet, const IPEndPoint& destinationEP) noexcept {
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                int session_id = exchanger_->GetStaticEchoSessionId();
                if (session_id < 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                boost::asio::ip::udp::socket& socket = switcher_->static_echo_socket_;
                if (!socket.is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                auto allocated_context = exchanger_->GetStaticAllocatedContext();
                if (NULLPTR == allocated_context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                int packet_length = -1;
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;

                std::shared_ptr<Byte> packet_output = VirtualEthernetPacket::Pack(
                    exchanger_->GetConfiguration(), 
                    allocator,
                    [&allocated_context](int) noexcept { return allocated_context->protocol; },
                    [&allocated_context](int) noexcept { return allocated_context->transport; }, 
                    session_id, 
                    packet, 
                    packet_length);

                if (NULLPTR == packet_output) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    return false;
                }

                /**
                 * @brief Sends packed bytes with end-of-record semantics.
                 */
                boost::system::error_code ec;
                socket.send_to(boost::asio::buffer(packet_output.get(), packet_length),
                    exchanger_->GetStaticEchoSourceEndPoint(), boost::asio::socket_base::message_end_of_record, ec);

                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    return false;
                }
                
                auto statistics = exchanger_->GetStatistics(); 
                if (NULLPTR != statistics) {
                    statistics->AddOutgoingTraffic(packet_length);
                }
                
                return true;
            }
        }
    }
}
