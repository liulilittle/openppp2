#pragma once

/**
 * @file VirtualEthernetDatagramPortStatic.h
 * @brief Static-echo UDP relay port used for stateless datagram forwarding.
 */

namespace ppp::configurations { class AppConfiguration; }
#include <atomic>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetExchanger;
            class VirtualEthernetSwitcher;

            /**
             * @brief Represents a static UDP relay port identified by source IP/port.
             *
             * The static port can emit encapsulated packets through the switcher's static echo
             * channel and optionally serve DNS responses from namespace cache.
             */
            class VirtualEthernetDatagramPortStatic : public std::enable_shared_from_this<VirtualEthernetDatagramPortStatic> {
                friend class                                            VirtualEthernetExchanger;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                /**
                 * @brief Creates a static datagram relay port.
                 * @param exchanger Owner exchanger that manages this port.
                 * @param context io_context used for async socket operations.
                 * @param source_ip Source IPv4 address in network byte order.
                 * @param source_port Source UDP port.
                 */
                VirtualEthernetDatagramPortStatic(const VirtualEthernetExchangerPtr& exchanger, const std::shared_ptr<boost::asio::io_context>& context, uint32_t source_ip, int source_port) noexcept;
                /**
                 * @brief Finalizes resources and unregisters static mapping.
                 */
                virtual ~VirtualEthernetDatagramPortStatic() noexcept;

            public:
                std::shared_ptr<VirtualEthernetDatagramPortStatic>      GetReference() noexcept     { return shared_from_this(); }
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept     { return exchanger_; }
                ContextPtr                                              GetContext() noexcept       { return context_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept { return configuration_; }
                boost::asio::ip::udp::endpoint                          GetLocalEndPoint() noexcept { return localEP_; }
                /**
                 * @brief Converts stored source IP/port to UDP endpoint.
                 * @return Source endpoint represented by this static port.
                 */
                boost::asio::ip::udp::endpoint                          GetSourceEndPoint() noexcept;

            public:
                /**
                 * @brief Schedules asynchronous disposal on the owning io_context.
                 */
                virtual void                                            Dispose() noexcept;
                /**
                 * @brief Opens and configures the UDP socket, then starts receive loop.
                 * @return True if socket opening and loop startup succeed.
                 */
                virtual bool                                            Open() noexcept;
                /**
                 * @brief Sends one UDP datagram to the destination endpoint.
                 * @param packet Payload pointer.
                 * @param packet_length Payload size in bytes.
                 * @param destinationEP Target UDP endpoint.
                 * @return True on successful send or cache-hit short-circuit.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;
                /**
                 * @brief Checks whether the port is disposed or timeout-expired.
                 * @param now Current tick count in milliseconds.
                 * @return True if the port should be considered aging.
                 */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }
                /**
                 * @brief Outputs a payload through static echo using source endpoint object.
                 * @param switcher Switcher that owns static echo socket.
                 * @param exchanger Exchanger carrying static echo context.
                 * @param messages Payload pointer.
                 * @param message_length Payload size in bytes.
                 * @param sourceEP Source endpoint used for encapsulation.
                 * @param remoteEP Destination endpoint used for encapsulation.
                 * @return True if encapsulation and send succeed.
                 */
                static bool                                             Output(
                    VirtualEthernetSwitcher*                            switcher, 
                    VirtualEthernetExchanger*                           exchanger, 
                    const void*                                         messages, 
                    int                                                 message_length, 
                    const boost::asio::ip::udp::endpoint&               sourceEP,
                    const boost::asio::ip::udp::endpoint&               remoteEP) noexcept;
                /**
                 * @brief Outputs a payload through static echo using raw source IP/port.
                 * @param switcher Switcher that owns static echo socket.
                 * @param exchanger Exchanger carrying static echo context.
                 * @param source_ip Source IPv4 in network byte order.
                 * @param source_port Source UDP port.
                 * @param messages Payload pointer.
                 * @param message_length Payload size in bytes.
                 * @param remoteEP Destination endpoint used for encapsulation.
                 * @return True if encapsulation and send succeed.
                 */
                static bool                                             Output(
                    VirtualEthernetSwitcher*                            switcher, 
                    VirtualEthernetExchanger*                           exchanger, 
                    uint32_t                                            source_ip,
                    int                                                 source_port,
                    const void*                                         messages, 
                    int                                                 message_length, 
                    const boost::asio::ip::udp::endpoint&               remoteEP) noexcept;

            private:
                /**
                 * @brief Releases socket and static-echo mapping resources.
                 */
                void                                                    Finalize() noexcept;
                /**
                 * @brief Starts one asynchronous receive cycle.
                 * @return True if receive operation is scheduled.
                 */
                bool                                                    Loopback() noexcept;
                /**
                 * @brief Refreshes timeout according to DNS-only or inactive policy.
                 */
                void                                                    Update() noexcept;
                /**
                 * @brief Outputs payload using the instance source IP/port.
                 * @param messages Payload pointer.
                 * @param message_length Payload size in bytes.
                 * @param remoteEP Destination endpoint.
                 * @return True if output succeeds.
                 */
                bool                                                    Output(const void* messages, int message_length, const boost::asio::ip::udp::endpoint& remoteEP) noexcept;
                /**
                 * @brief Tries to serve a DNS query from namespace cache.
                 * @param destinationEP DNS destination endpoint.
                 * @param packet DNS query packet.
                 * @param packet_length Query packet size in bytes.
                 * @return Positive on cache hit/output success, 0 on deny, -1 otherwise.
                 */
                int                                                     NamespaceQuery(
                    const boost::asio::ip::udp::endpoint&               destinationEP,
                    const void*                                         packet,
                    int                                                 packet_length) noexcept; 

            private:
                // Lifecycle state is read by the manager GC thread (IsPortAging) while
                // SendTo()/Finalize() run on the owning io_context thread; keep it atomic.
                std::atomic<bool>                                       disposed_{false};
                std::atomic<bool>                                       in_{false};
                std::atomic<bool>                                       onlydns_{false};
                uint32_t                                                source_ip_   = 0;
                int                                                     source_port_ = 0;
                std::atomic<UInt64>                                     timeout_{0};
                boost::asio::ip::udp::socket                            socket_;
                std::shared_ptr<VirtualEthernetSwitcher>                switcher_;
                VirtualEthernetExchangerPtr                             exchanger_;
                AppConfigurationPtr                                     configuration_;
                std::shared_ptr<Byte>                                   buffer_;
                std::shared_ptr<boost::asio::io_context>                context_;
                boost::asio::ip::udp::endpoint                          localEP_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
            };
        }
    }
}
