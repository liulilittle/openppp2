#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp 
{
    namespace unix__ 
    {
        class UnixAfx final
        {
        public:
            typedef ppp::function<bool(void)>                                   ShutdownApplicationEventHandler;

        public:
            static ppp::string                                                  GetDnsResolveConfiguration() noexcept;
            static bool                                                         SetDnsResolveConfiguration(const ppp::string& configuration) noexcept;
            static int                                                          GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept;
            static int                                                          GetDnsAddresses(const ppp::string& in, ppp::vector<boost::asio::ip::address>& addresses) noexcept;
            static bool                                                         SetDnsAddresses(const ppp::vector<uint32_t>& addresses) noexcept;
            static bool                                                         SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept;
            static bool                                                         SetDnsAddresses(const ppp::vector<boost::asio::ip::address>& addresses) noexcept;

        public:
            static ppp::string                                                  GetInterfaceName(const ppp::net::IPEndPoint& address) noexcept;
            static UInt32                                                       GetDefaultNetworkInterface() noexcept;
            static UInt32                                                       GetDefaultNetworkInterface(const char* address_string) noexcept;

        public:
            static bool                                                         GetLocalNetworkInterface(ppp::string& ifrName, UInt32& address, UInt32& gw, UInt32& mask, const ppp::function<bool(ppp::string&)>& predicate) noexcept;
            static bool                                                         GetLocalNetworkInterface2(ppp::string& ifrName, UInt32& address, UInt32& gw, UInt32& mask, const ppp::string& nic, const ppp::function<bool(ppp::string&)>& predicate) noexcept;

        public:
            static bool                                                         AddShutdownApplicationEventHandler(ShutdownApplicationEventHandler e) noexcept;
            static bool                                                         set_fd_cloexec(int fd) noexcept;                                    

        public:
            static bool                                                         CloseHandle(const void* handle) noexcept;
        };
    }
}