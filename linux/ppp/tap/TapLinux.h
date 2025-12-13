#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

namespace ppp
{
    namespace tap
    {
        class TapLinux final : public ppp::tap::ITap
        {
        private:
            typedef std::mutex                                                      SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;

        public:
            TapLinux(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network);
            virtual ~TapLinux() noexcept;
            
        public:
            static bool                                                             AddRoute2(UInt32 address, int prefix, UInt32 gw) noexcept;
            static bool                                                             DeleteRoute2(UInt32 address, int prefix, UInt32 gw) noexcept;
            static bool                                                             AddAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            static bool                                                             DeleteAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            bool                                                                    AddRoute(UInt32 address, int prefix, UInt32 gw) noexcept;
            bool                                                                    DeleteRoute(UInt32 address, int prefix, UInt32 gw) noexcept;
            static bool                                                             AddRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept;
            static bool                                                             DeleteRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept;

        public: 
            bool&                                                                   IsPromisc() noexcept       { return promisc_; } 
            ppp::vector<boost::asio::ip::address>&                                  GetDnsAddresses() noexcept { return dns_addresses_; }
            static std::shared_ptr<TapLinux>                                        Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;
            virtual void                                                            Dispose() noexcept override;
            virtual bool                                                            SetInterfaceMtu(int mtu) noexcept override;

        public: 
            bool                                                                    Ssmt() noexcept { return tun_ssmt_fds_size_ > 0; }
            bool                                                                    Ssmt(const std::shared_ptr<boost::asio::io_context>& context) noexcept;

        public: 
            virtual bool                                                            Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool                                                            Output(const void* packet, int packet_size) noexcept override;

        public: 
            static bool                                                             GetDefaultGateway(char* ifrName, UInt32* address) noexcept;
            static bool                                                             GetDefaultGateway(UInt32* address, const ppp::function<bool(const char*, uint32_t ip, uint32_t gw, uint32_t mask, int metric)>& predicate) noexcept;
            static void                                                             CompatibleRoute(bool compatible) noexcept;
            static bool                                                             SetIPAddress(
                const ppp::string&                                                  ifrName,
                const ppp::string&                                                  addressIP,
                const ppp::string&                                                  mask) noexcept;
            static ppp::string                                                      GetDeviceId(const ppp::string& ifrName) noexcept;
            static bool                                                             GetPreferredNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& mask, UInt32& gw, const ppp::string& nic) noexcept;

        public: 
            static bool                                                             SetNextHop(const ppp::string& ip) noexcept;
            static ppp::string                                                      GetIPAddress(const ppp::string& ifrName) noexcept;
            static ppp::string                                                      GetMaskAddress(const ppp::string& ifrName) noexcept;
            static int                                                              GetInterfaceIndex(const ppp::string& ifrName) noexcept;
            static bool                                                             GetInterfaceName(int dev_handle, ppp::string& ifrName) noexcept;
            static bool                                                             SetInterfaceName(int dev_handle, const ppp::string& ifrName) noexcept;
            static ppp::string                                                      GetHardwareAddress(const ppp::string& ifrName) noexcept;

        public:
            static int                                                              GetLastHandle() noexcept;
            static int                                                              SetLastHandle(int fd) noexcept;

        public: 
            static bool                                                             AddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            static bool                                                             DeleteAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            static std::shared_ptr<ppp::net::native::RouteInformationTable>         FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept;
#if defined(_ANDROID)   
            static std::shared_ptr<ITap>                                            From(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network) noexcept;
#endif  

        private:    
            static void                                                             InitialSockAddrIn(struct sockaddr* sa, in_addr_t addr) noexcept;
            static int                                                              SetRoute(int action, const ppp::string& ifrName, struct in_addr dst, int prefix, struct in_addr gw) noexcept;
            static bool                                                             GetLocalNetworkInterface(ppp::string& ifrName, UInt32& address, UInt32& gw, UInt32& mask) noexcept;
            bool                                                                    SetNetifUp(bool up) noexcept;
            static std::shared_ptr<TapLinux>                                        CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept;

        private:    
            static int                                                              OpenDriver(const char* ifrName) noexcept;
            void                                                                    Finalize() noexcept;
            bool                                                                    Ssmt(const std::shared_ptr<boost::asio::io_context>& context, int fd, const std::shared_ptr<Byte>& buffer, const std::shared_ptr<boost::asio::posix::stream_descriptor>& sd) noexcept;

        private:    
            SynchronizedObject                                                      syncobj_;
            bool                                                                    promisc_            = false;
            std::atomic<int>                                                        disposed_           = FALSE; 
            ppp::vector<boost::asio::ip::address>                                   dns_addresses_;
            ppp::vector<std::shared_ptr<boost::asio::posix::stream_descriptor>/**/> tun_ssmt_sds_;
            int                                                                     tun_ssmt_fds_size_  = 0;
        };
    }
}