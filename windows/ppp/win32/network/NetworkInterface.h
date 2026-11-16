#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/rib.h>

#include <Windows.h>
#include <wchar.h>
#include <tchar.h>
#include <setupapi.h>

/* MAX_DEVICE_ID_LEN */
#include <devguid.h> /* DDK/Inc/api/devguid.h */
#include <Iphlpapi.h>
#include <netioapi.h>

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            typedef enum
            {
                OperationalStatus_Unknown,
                OperationalStatus_Up,
                OperationalStatus_Down,
            } OperationalStatus;

            typedef struct
            {
                ppp::string                                     Driver;
                ppp::string                                     Guid;
                // Stable kernel identity. InterfaceIndex can be reused after
                // an adapter is removed, so lifecycle snapshots retain both.
                ppp::string                                     InterfaceLuid;
                ppp::string                                     MacAddress;
                int                                             Index;
                int                                             InterfaceIndex;
                ppp::vector<ppp::string>                        IPSubnet;
                ppp::vector<ppp::string>                        DnsAddresses;
                ppp::vector<ppp::string>                        IPAddresses;
                ppp::vector<ppp::string>                        DefaultIPGateway;
                bool                                            DhcpEnabled;
                int                                             Metric;
                bool                                            IPEnabled;
                ppp::string                                     ConnectionId;
                ppp::string                                     ScopeId;
                ppp::string                                     Caption;
                ppp::string                                     Description;
                OperationalStatus                               Status;
            } NetworkInterface;

            // A DNS snapshot carries the identity and mode needed to restore
            // one adapter without writing a stale snapshot to a replacement
            // adapter that happens to reuse its interface index.
            struct NetworkDnsSnapshot
            {
                int                                             InterfaceIndex = -1;
                ppp::string                                     InterfaceLuid;
                ppp::string                                     Guid;
                ppp::vector<boost::asio::ip::address>           DnsAddresses;
                // DNS values written by OpenPPP2.  Restore uses this as an
                // ownership check so a later user or service change is not
                // overwritten blindly.
                ppp::vector<boost::asio::ip::address>           AppliedDnsAddresses;
                // The WMI call may fail after the operating system has
                // applied the value. Keep that ambiguity explicit so retry
                // can distinguish an unchanged adapter from a conflict.
                bool                                            DnsApplyAttempted = false;
                bool                                            DnsApplied = false;
                // True when DNS is supplied automatically (NameServer is
                // empty); this is deliberately separate from WMI's
                // IP-address DhcpEnabled property.
                bool                                            DnsAutomatic = false;
            };

            typedef struct
            {
                ppp::string                                     Id;
                ppp::string                                     Name;
                ppp::string                                     Address;
                ppp::string                                     Mask;
                ppp::string                                     GatewayServer;
                ppp::string                                     DhcpServer;
                ppp::string                                     PrimaryWinsServer;
                ppp::string                                     SecondaryWinsServer;
                ppp::string                                     MacAddress;
                int                                             IfIndex;
                int                                             IfType;
                OperationalStatus                               Status;
            } AdapterInterface;

            typedef std::shared_ptr<NetworkInterface>           NetworkInterfacePtr;
            typedef std::shared_ptr<AdapterInterface>           AdapterInterfacePtr;

            bool                                                SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& servers) noexcept;
            bool                                                SetDnsAddressesV6(int interface_index, const ppp::vector<ppp::string>& servers) noexcept;
            bool                                                SetDefaultIPGateway(int interface_index, const ppp::vector<ppp::string>& servers) noexcept;
            bool                                                SetDefaultIPGateway(int interface_index, const ppp::vector<boost::asio::ip::address>& servers) noexcept;
            bool                                                SetIPAddresses(const ppp::string& interface_name, const ppp::string& ip, const ppp::string& mask) noexcept;
            bool                                                SetIPv6Address(int interface_index, const ppp::string& ip, int prefix_length) noexcept;
            bool                                                DeleteIPv6Address(int interface_index, const ppp::string& ip) noexcept;
            bool                                                SetIPv6DefaultRoute(int interface_index, int metric) noexcept;
            bool                                                SetIPv6DefaultGateway(int interface_index, const ppp::string& gateway, int metric) noexcept;
            bool                                                DeleteIPv6DefaultGateway(int interface_index, const ppp::string& gateway) noexcept;
            bool                                                AddIPv6Route(int interface_index, const ppp::string& prefix, int prefix_length, const ppp::string& gateway, int metric) noexcept;
            bool                                                DeleteIPv6Route(int interface_index, const ppp::string& prefix, int prefix_length, const ppp::string& gateway) noexcept;
            bool                                                SetIPAddresses(int interface_index, const ppp::vector<ppp::string>& ips, const ppp::vector<ppp::string>& masks) noexcept;
            bool                                                DhcpEnabled(int interface_index) noexcept;
            bool                                                CaptureDnsSnapshot(int interface_index, NetworkDnsSnapshot& snapshot) noexcept;
            // Captures the original state before writing one explicitly
            // authorized adapter.  The snapshot remains usable for rollback
            // when the write itself fails.
            bool                                                SetDnsAddressesWithSnapshot(int interface_index, const ppp::vector<ppp::string>& servers, NetworkDnsSnapshot& snapshot) noexcept;
            bool                                                RestoreDnsSnapshot(const NetworkDnsSnapshot& snapshot) noexcept;
            bool                                                ResetNetworkEnvironment() noexcept;
            ppp::string                                         GetInterfaceName(int interface_index) noexcept;
            bool                                                SetInterfaceName(int interface_index, const ppp::string& interface_name) noexcept;

            OperationalStatus                                   GetOperationalStatus(int interface_index) noexcept;
            OperationalStatus                                   GetOperationalStatus(INTERNAL_IF_OPER_STATUS status) noexcept;
            bool                                                GetAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept;
            int                                                 GetInterfaceMtu(int interface_index) noexcept;
            bool                                                SetInterfaceMtu(int interface_index, int mtu) noexcept;
            bool                                                SetInterfaceMtuIpSubInterface(int interface_index, int mtu) noexcept;

            NetworkInterfacePtr                                 GetNetworkInterfaceByIndex(int index) noexcept;
            NetworkInterfacePtr                                 GetNetworkInterfaceByInterfaceIndex(int interface_index) noexcept;
            AdapterInterfacePtr                                 GetNetworkInterfaceByIndex2(int interface_index) noexcept;
            int                                                 GetIfIndexByFriendlyName(const std::wstring& adapter_name) noexcept;
            bool                                                GetAllNetworkInterfaces(ppp::vector<NetworkInterfacePtr>& interfaces) noexcept;
            bool                                                GetAllAdapterInterfaces(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept;
            bool                                                GetAllAdapterInterfaces2(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept;

            std::shared_ptr<MIB_IFTABLE>                        GetIfTable() noexcept;
            std::shared_ptr<MIB_IFROW>                          GetIfEntry(int interface_index) noexcept;

            /**
             * Applies DNS to the interfaces represented by the supplied
             * snapshot map. The return value is the number of successful
             * interface operations; failed snapshots remain in the map for a
             * later retry.
             */
            int                                                 SetAllNicsDnsAddresses(ppp::unordered_map<int, ppp::vector<boost::asio::ip::address>>& addresses) noexcept;

            /**
             * Captures the DNS state of eligible interfaces before applying
             * the requested servers. The captured map is also the exact
             * authorization set used by the apply operation.
             */
            int                                                 SetAllNicsDnsAddresses(ppp::vector<boost::asio::ip::address>& servers, ppp::unordered_map<int, ppp::vector<boost::asio::ip::address>>& addresses) noexcept;

            bool                                                AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            bool                                                AddAllRoutes(ppp::vector<MIB_IPFORWARDROW>& routes) noexcept;
            bool                                                DeleteAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            bool                                                DeleteAllDefaultGatewayRoutes(boost::asio::ip::address gw) noexcept;
            bool                                                DeleteAllDefaultGatewayRoutes(ppp::vector<MIB_IPFORWARDROW>& routes, const ppp::unordered_set<uint32_t>& bypass_gws) noexcept;

            int                                                 GetNetworkInterfaceIndexByDefaultRoute() noexcept;
            AdapterInterfacePtr                                 GetUnderlyingNetworkInterface(const ppp::string& id) noexcept;
            std::pair<AdapterInterfacePtr, NetworkInterfacePtr> GetUnderlyingNetowrkInterface2(const ppp::string& id, const ppp::string& nic) noexcept;
        }
    }
}
