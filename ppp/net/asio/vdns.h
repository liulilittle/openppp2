#pragma once 

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <common/dnslib/message.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace vdns {
                typedef ppp::vector<boost::asio::ip::udp::endpoint>                             IPEndPointVector;
                typedef std::shared_ptr<IPEndPointVector>                                       IPEndPointVectorPtr;

                extern IPEndPointVectorPtr                                                      servers;
                extern int                                                                      ttl;
                extern bool                                                                     enabled;

                enum AddressFamily {
                    kNone = 0,
                    kA    = 1,
                    kAAAA = 2
                };
                bool                                                                            QueryCache(const char* hostname, boost::asio::ip::address& address) noexcept;
                
                ppp::string                                                                     QueryCache2(const char* hostname, ::dns::Message& messsage, AddressFamily af) noexcept;

                bool                                                                            AddCache(const Byte* packet, int packet_size) noexcept;

                bool                                                                            IsReverseQuery(const char* hostname) noexcept;

                bool                                                                            ResolveAsync(
                    boost::asio::io_context&                                                    context, 
                    const char*                                                                 hostname, 
                    int                                                                         timeout, 
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                          destinations,
                    const ppp::function<void(const boost::asio::ip::address&)>&                 cb) noexcept;

                bool                                                                            ResolveAsync2(
                    boost::asio::io_context&                                                    context, 
                    const char*                                                                 hostname, 
                    int                                                                         timeout, 
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                          destinations,
                    const ppp::function<void(const ppp::vector<boost::asio::ip::address>&)>&    cb) noexcept;

                void                                                                            UpdateAsync() noexcept;
            }
        }
    }
}