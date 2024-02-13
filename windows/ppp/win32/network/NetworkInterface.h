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
                ppp::string                                     Driver;                 // 驱动
                ppp::string                                     Guid;                   // GUID
                ppp::string                                     MacAddress;             // MAC地址
                int                                             Index;                  // 索引
                int                                             InterfaceIndex;         // 网卡索引
                ppp::vector<ppp::string>                        IPSubnet;               // 子网    
                ppp::vector<ppp::string>                        DnsAddresses;           // DNS服务器
                ppp::vector<ppp::string>                        IPAddresses;            // IP地址
                ppp::vector<ppp::string>                        DefaultIPGateway;       // 默认网关服务器
                bool                                            DhcpEnabled;            // 启用DHCP
                int                                             Metric;                 // 跃点
                bool                                            IPEnabled;              // IP启用
                ppp::string                                     ConnectionId;           // 链接ID
                ppp::string                                     ScopeId;                // 域ID
                ppp::string                                     Caption;                // 标题
                ppp::string                                     Description;            // 描述信息
                OperationalStatus                               Status;                 // 操作状态
            } NetworkInterface;

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
                int                                             IfType; // MIB_IF_TYPE
                OperationalStatus                               Status;
            } AdapterInterface;

            typedef std::shared_ptr<NetworkInterface>           NetworkInterfacePtr;
            typedef std::shared_ptr<AdapterInterface>           AdapterInterfacePtr;

            bool                                                SetInterfaceName(int interface_index, const ppp::string& interface_name) noexcept;
            bool                                                SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& servers) noexcept;
            bool                                                SetDefaultIPGateway(int interface_index, const ppp::vector<ppp::string>& servers) noexcept;
            bool                                                SetDefaultIPGateway(int interface_index, const ppp::vector<boost::asio::ip::address>& servers) noexcept;
            bool                                                SetIPAddresses(const ppp::string& interface_name, const ppp::string& ip, const ppp::string& mask) noexcept;
            bool                                                SetIPAddresses(int interface_index, const ppp::vector<ppp::string>& ips, const ppp::vector<ppp::string>& masks) noexcept;
            bool                                                DhcpEnabled(int interface_index) noexcept;
            ppp::string                                         BytesToMacAddress(const void* data, int size) noexcept;
            ppp::string                                         GetInterfaceName(int interface_index) noexcept;
            bool                                                SetInterfaceName(int interface_index, const ppp::string& interface_name) noexcept;

            OperationalStatus                                   GetOperationalStatus(int interface_index) noexcept;
            OperationalStatus                                   GetOperationalStatus(INTERNAL_IF_OPER_STATUS status) noexcept;
            bool                                                GetAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept;

            NetworkInterfacePtr                                 GetNetworkInterfaceByIndex(int index) noexcept;
            NetworkInterfacePtr                                 GetNetworkInterfaceByInterfaceIndex(int interface_index) noexcept;
            AdapterInterfacePtr                                 GetNetworkInterfaceByIndex2(int interface_index) noexcept;
            bool                                                GetAllNetworkInterfaces(ppp::vector<NetworkInterfacePtr>& interfaces) noexcept;
            bool                                                GetAllAdapterInterfaces(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept;
            bool                                                GetAllAdapterInterfaces2(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept;

            std::shared_ptr<MIB_IFTABLE>                        GetIfTable() noexcept;
            std::shared_ptr<MIB_IFROW>                          GetIfEntry(int interface_index) noexcept;

            int                                                 SetAllNicsDnsAddresses(ppp::unordered_map<int, ppp::unordered_set<boost::asio::ip::address>>& addresses) noexcept;
            int                                                 SetAllNicsDnsAddresses(ppp::vector<boost::asio::ip::address>& servers, ppp::unordered_map<int, ppp::unordered_set<boost::asio::ip::address>>& addresses) noexcept;

            bool                                                AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            bool                                                AddAllRoutes(ppp::vector<MIB_IPFORWARDROW>& routes) noexcept;
            bool                                                DeleteAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept;
            void                                                DeleteAllDefaultGatewayRoutes(boost::asio::ip::address gw) noexcept;
            bool                                                DeleteAllDefaultGatewayRoutes(ppp::vector<MIB_IPFORWARDROW>& routes, const ppp::unordered_set<uint32_t>& bypass_gws) noexcept;

            int                                                 GetNetworkInterfaceIndexByDefaultRoute() noexcept;
            AdapterInterfacePtr                                 GetUnderlyingNetowrkInterface(const ppp::string& id) noexcept;
            std::pair<AdapterInterfacePtr, NetworkInterfacePtr> GetUnderlyingNetowrkInterface2(const ppp::string& id, const ppp::string& nic) noexcept;
        }
    }
}