#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>

namespace ppp
{
    namespace tap
    {
        class TapWindows final : public ppp::tap::ITap
        {
        public:
            TapWindows(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network);
            virtual ~TapWindows() noexcept = default;

        public:
            static bool                             DnsFlushResolverCache() noexcept;
            static bool                             SetAddresses(int interface_index, uint32_t ip, uint32_t mask, uint32_t gw) noexcept;
            static bool                             SetDnsAddresses(int interface_index, ppp::vector<uint32_t>& servers) noexcept;
            static bool                             SetDnsAddresses(int interface_index, ppp::vector<ppp::string>& servers) noexcept;
            static std::shared_ptr<ITap>            Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& componentId, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses);
            static bool                             InstallDriver(const ppp::string& path, const ppp::string& declareTapName) noexcept;
            static bool                             UninstallDriver(const ppp::string& path) noexcept;

        public:
            static ppp::string                      FindComponentId() noexcept;
            static ppp::string                      FindComponentId(const ppp::string& key) noexcept;
            static bool                             FindAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept;
            static int                              GetNetworkInterfaceIndex(const ppp::string& componentId) noexcept;
            
        private:
            static void*                            OpenDriver(const ppp::string& componentId) noexcept;
            static bool                             ConfigureDriver_SetDhcpMASQ(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds) noexcept;
            static bool                             ConfigureDriver_SetNetifTunMode(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask) noexcept;
            static bool                             ConfigureDriver_SetNetifUp(const void* handle, bool up) noexcept;
            static bool                             ConfigureDriver_SetDhcpOptionData(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t dhcp, const ppp::vector<uint32_t>& dns_addresses) noexcept;
        };
    }
}