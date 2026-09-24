#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>

#include <mutex>

class WintunAdapter;

namespace ppp
{
    namespace tap
    {
        class TapWindows final : public ppp::tap::ITap
        {
            friend struct                           WintunAdapterDriver;

        public:
            TapWindows(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network);
            virtual ~TapWindows() noexcept = default;

        public:
            virtual bool                            SetInterfaceMtu(int mtu) noexcept override;
            virtual void                            Dispose() noexcept override;

        public:
            static bool                             DnsFlushResolverCache() noexcept;
            static bool                             SetAddresses(int interface_index, uint32_t ip, uint32_t mask, uint32_t gw) noexcept;
            static bool                             SetDnsAddresses(int interface_index, ppp::vector<uint32_t>& servers) noexcept;
            static bool                             SetDnsAddresses(int interface_index, ppp::vector<ppp::string>& servers) noexcept;
            static std::shared_ptr<ITap>            Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& componentId, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses);
            static bool                             InstallDriver(const ppp::string& path, const ppp::string& declareTapName) noexcept;
            static bool                             UninstallDriver(const ppp::string& path) noexcept;

        public:
            static bool                             IsWintun() noexcept;
            bool                                    IsWintunBackend() noexcept;
            static ppp::string                      FindComponentId() noexcept;
            static ppp::string                      FindComponentId(const ppp::string& key) noexcept;
            static bool                             FindAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept;
            static int                              GetNetworkInterfaceIndex(const ppp::string& componentId) noexcept;
            
        protected:
            virtual bool                            Output(const void* packet, int packet_size) noexcept override;
            virtual bool                            Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            virtual bool                            AsynchronousReadPacketLoops() noexcept override;

        private:
            static void*                            OpenDriver(const ppp::string& componentId) noexcept;
            static bool                             ConfigureDriver_SetDhcpMASQ(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds) noexcept;
            static bool                             ConfigureDriver_SetTunModeWithAddress(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask) noexcept;
            static bool                             ConfigureDriver_SetNetifUp(const void* handle, bool up) noexcept;
            static bool                             ConfigureDriver_SetDhcpOptionData(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t dhcp, const ppp::vector<uint32_t>& dns_addresses) noexcept;

        private:
            // ITap retains a raw backend handle for compatibility. This typed owner
            // keeps that handle valid until TapWindows itself is destroyed.
            std::mutex                              wintun_mutex_;
            std::shared_ptr<::WintunAdapter>        wintun_adapter_;
        };
    }
}