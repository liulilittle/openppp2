#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/rib.h>

#include <darwin/ppp/tun/utun.h>

namespace ppp 
{
    namespace tap 
    {
        class TapDarwin final : public ppp::tap::ITap
        {
        public:
            struct NetworkInterface final
            {
            public:
                ppp::string                                 Name;
                int                                         Index = -1;
                ppp::string                                 GatewayServer;
                ppp::string                                 IPAddress;
                ppp::string                                 SubnetmaskAddress;
                ppp::unordered_map<uint32_t, uint32_t>      GatewayAddresses;

            public:
                typedef std::shared_ptr<NetworkInterface>   Ptr;
            };
            typedef ppp::unordered_map<uint32_t, uint32_t>  RouteInformationTable;

        public:
            TapDarwin(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network) noexcept;
            
        public:
            ppp::vector<boost::asio::ip::address>&          GetDnsAddresses() noexcept { return dns_addresses_; }
            bool&                                           IsPromisc() noexcept       { return promisc_; } 
            virtual bool                                    Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool                                    Output(const void* packet, int packet_size) noexcept override;
            virtual bool                                    SetInterfaceMtu(int mtu) noexcept override;

        public:
            static bool                                     GetAllNetworkInterfaces(ppp::vector<NetworkInterface::Ptr>& interfaces) noexcept;
            static bool                                     GetInterfaceName(int interface_index, ppp::string& ifrName) noexcept;
            static int                                      GetInterfaceIndex(const ppp::string& ifrName) noexcept;
            static NetworkInterface::Ptr                    GetPreferredNetworkInterface(const ppp::vector<NetworkInterface::Ptr>& interfaces) noexcept;
            static NetworkInterface::Ptr                    GetPreferredNetworkInterface2(const ppp::vector<NetworkInterface::Ptr>& interfaces, const ppp::string& nic) noexcept;
            static std::shared_ptr<TapDarwin>               Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;

        public:
            static bool                                     AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;    
            static bool                                     DeleteAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept; 
            static std::shared_ptr<RouteInformationTable>   FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept;

        private:
            static std::shared_ptr<TapDarwin>               CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept;
            virtual void                                    OnInput(PacketInputEventArgs& e) noexcept override;

        private:
            bool                                            promisc_ = false;
            ppp::vector<boost::asio::ip::address>           dns_addresses_;
        };
    }
}