#pragma once

#include <ppp/stdafx.h>
#include <array>
#include <ppp/tap/ITap.h>
#include <ppp/tap/TapRuntimeStats.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>
#include <linux/ppp/tap/TapGsoCoalescer.h>

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
            enum class RouteMutationResult
            {
                Failed,
                Unchanged,
                Changed,
            };

            enum class NeighborMutationResult
            {
                Failed,
                Unchanged,
                Changed,
            };

            static RouteMutationResult                                              ClassifyRouteAddResult(int error, bool query_succeeded, bool exact_exists) noexcept
            {
                if (error == 0)
                {
                    return RouteMutationResult::Changed;
                }
                if (error == EEXIST && query_succeeded && exact_exists)
                {
                    return RouteMutationResult::Unchanged;
                }
                return RouteMutationResult::Failed;
            }

            static NeighborMutationResult                                           ClassifyPermanentNeighborAddResult(int error, bool query_succeeded, bool exact_exists) noexcept
            {
                if (error == 0)
                {
                    return NeighborMutationResult::Changed;
                }
                if (error == EEXIST && query_succeeded && exact_exists)
                {
                    return NeighborMutationResult::Unchanged;
                }
                return NeighborMutationResult::Failed;
            }

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
            static RouteMutationResult                                              AddRouteStatus(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept;
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
            bool                                                                    GetRuntimeStats(ppp::tap::TapRuntimeStats& stats) const noexcept;

        public: 
            virtual bool                                                            Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool                                                            Output(const void* packet, int packet_size) noexcept override;
            virtual bool                                                            SupportsTxGso() const noexcept override;
            virtual bool                                                            OutputGso(const std::shared_ptr<Byte>& packet, int packet_size, TxGsoMetadata metadata) noexcept override;

        protected:
            virtual void                                                            OnInput(PacketInputEventArgs& e) noexcept override;
            virtual bool                                                            AsynchronousReadPacketLoops() noexcept override;

        public: 
            static bool                                                             GetDefaultGateway(char* ifrName, UInt32* address) noexcept;
            static bool                                                             GetDefaultGateway(UInt32* address, const ppp::function<bool(const char*, uint32_t ip, uint32_t gw, uint32_t mask, int metric)>& predicate, bool* query_succeeded = NULLPTR) noexcept;
            static void                                                             CompatibleRoute(bool compatible) noexcept;
            static bool                                                             SetIPAddress(
                const ppp::string&                                                  ifrName,
                const ppp::string&                                                  addressIP,
                const ppp::string&                                                  mask) noexcept;
            static bool                                                             SetIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept;
            static bool                                                             SetMtu(const ppp::string& ifrName, int mtu) noexcept;
            static bool                                                             DeleteIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept;
            static bool                                                             AddRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept;
            static bool                                                             DeleteRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept;
            static bool                                                             EnableIPv6NeighborProxy(const ppp::string& ifrName) noexcept;
            static bool                                                             QueryIPv6NeighborProxy(const ppp::string& ifrName, bool& enabled) noexcept;
            static bool                                                             DisableIPv6NeighborProxy(const ppp::string& ifrName) noexcept;
            static bool                                                             AddIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept;
            static bool                                                             DeleteIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept;
            static NeighborMutationResult                                           AddIPv6PermanentNeighbor(const ppp::string& ifrName, const ppp::string& addressIP) noexcept;
            static bool                                                             DeleteIPv6PermanentNeighbor(const ppp::string& ifrName, const ppp::string& addressIP) noexcept;
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
            static bool                                                             TryFindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws, std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept;
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
            ssize_t                                                                 WriteTunFrame(int fd, const uint8_t* frame, size_t frame_size) noexcept;
            ssize_t                                                                 WriteGsoFrameLocked(const uint8_t* frame, size_t frame_size) noexcept;
            enum class TunWriteFailureSource : uint8_t { BareWrite, GsoDisableFlush, GsoHoldTimerFlush, GsoOrdinaryWrite, GsoCoalescerPush, DirectGsoWrite };
            void                                                                    FailTunWrite(TunWriteFailureSource source) noexcept;
            void                                                                    DisableGsoMergeLocked(int write_fd, TunGsoCoalescer::FlushReason reason = TunGsoCoalescer::FlushReason::Terminate) noexcept;
            void                                                                    ArmGsoHoldTimerLocked() noexcept;
            void                                                                    CancelGsoHoldTimerLocked() noexcept;

        private:    
            SynchronizedObject                                                      syncobj_;
            bool                                                                    promisc_            = false;
            std::atomic<int>                                                        disposed_           = FALSE; 
            std::atomic<int>                                                        tun_write_failed_   = FALSE;
            ppp::vector<boost::asio::ip::address>                                   dns_addresses_;
            ppp::vector<std::shared_ptr<boost::asio::posix::stream_descriptor>/**/> tun_ssmt_sds_;
            int                                                                     tun_ssmt_fds_size_  = 0;
            // Synchronizes only the optional VNET/GSO feature. The bare TUN
            // output path deliberately does not acquire this mutex.
            mutable std::mutex                                                      gso_mutex_;
            int                                                                     gso_write_fd_       = -1;
            bool                                                                    vnet_header_        = false;
            bool                                                                    tx_gso_supported_    = false;
            std::atomic<uint64_t>                                                   direct_gso_packets_{0};
            std::atomic<uint64_t>                                                   direct_gso_bytes_{0};
            std::atomic<uint64_t>                                                   direct_gso_rejected_{0};
            size_t                                                                  vnet_header_size_   = 0;
            size_t                                                                  read_capacity_      = ITap::Mtu;
            std::shared_ptr<Byte>                                                   vnet_read_buffer_;
            bool                                                                    gso_merge_active_   = false;
            bool                                                                    gso_timer_armed_    = false;
            bool                                                                    gso_ssmt_disabled_  = false;
            bool                                                                    gso_observer_hooked_ = false;
            bool                                                                    gso_push_observation_active_ = false;
            uint64_t                                                                gso_timer_generation_ = 0;
            boost::asio::steady_timer                                               gso_hold_timer_;
            TunGsoCoalescer                                                        gso_coalescer_;
        };
    }
}
