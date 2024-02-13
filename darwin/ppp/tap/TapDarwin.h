#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/rib.h>

namespace ppp 
{
    namespace tap 
    {
        class TapDarwin final : public ppp::tap::ITap
        {
        public:
            struct NetworkInterface
            {
            public:
                ppp::string                                 Name;
                int                                         Index;
                ppp::string                                 GatewayServer;
                ppp::string                                 IPAddress;
                ppp::string                                 SubnetmaskAddress;
                ppp::unordered_map<uint32_t, uint32_t>      GatewayAddresses;

            public:
                typedef std::shared_ptr<NetworkInterface>   Ptr;
            };

        public:
            TapDarwin(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network) noexcept;
            
        public:
            ppp::vector<boost::asio::ip::address>&          GetDnsAddresses() noexcept { return dns_addresses_; }
            bool&                                           IsPromisc() noexcept { return promisc_; } 
            virtual bool                                    Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool                                    Output(const void* packet, int packet_size) noexcept override;

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

        private:
            static std::shared_ptr<TapDarwin>               CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept;
            virtual void                                    OnInput(PacketInputEventArgs& e) noexcept override;

        private:
            bool                                            promisc_;
            ppp::vector<boost::asio::ip::address>           dns_addresses_;
        };

        void                                                utun_close(int fd) noexcept;
        bool                                                utun_set_mac(int tun, const ppp::string& mac) noexcept;
        int                                                 utun_utunnum(const ppp::string& dev) noexcept;
        bool                                                utun_set_cloexec(int fd) noexcept;
        int                                                 utun_open(int utunnum) noexcept;
        int                                                 utun_open(int utunnum, uint32_t ip, uint32_t gw, uint32_t mask) noexcept;
        bool                                                utun_set_mtu(int tun, int mtu) noexcept;
        bool                                                utun_get_if_name(int tun, ppp::string& ifrName) noexcept;
        bool                                                utun_set_if_ip_gw_and_mask(int tun, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask) noexcept;
        bool                                                utun_add_route(UInt32 address, UInt32 gw) noexcept;
        bool                                                utun_del_route(UInt32 address, UInt32 gw) noexcept;
        bool                                                utun_add_route(UInt32 address, int prefix, UInt32 gw) noexcept;
        bool                                                utun_del_route(UInt32 address, int prefix, UInt32 gw) noexcept;
        bool                                                utun_add_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept;
        bool                                                utun_del_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept;
    }
}