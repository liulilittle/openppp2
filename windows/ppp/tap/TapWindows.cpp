#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/tap/tap-windows.h>

#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <iostream>
#include <Windows.h>
#include <process.h>
#include <Shlwapi.h>
#include <Shellapi.h>

typedef ppp::net::IPEndPoint IPEndPoint;
typedef ppp::net::Ipep       Ipep;

namespace ppp
{
    namespace tap
    {
        TapWindows::TapWindows(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network)
            : ITap(context, id, tun, address, gw, mask, hosted_network)
        {

        }

        /* Refer: https://github.com/liulilittle/SkylakeNAT/blob/master/SkylakeNAT/tap.cpp */
        static uint32_t dhcp_masq_addr(const uint32_t local, const uint32_t netmask, const int offset) noexcept
        {
            int dsa; /* DHCP server addr */

            if (offset < 0)
            {
                dsa = (local | (~netmask)) + offset;
            }
            else
            {
                dsa = (local & netmask) + offset;
            }

            if (dsa == local)
            {
                fprintf(stdout, "There is a clash between the --ifconfig local address and the internal DHCP server address"
                    "-- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the"
                    " --ifconfig subnet for the internal DHCP server\n", ppp::net::Ipep::ToAddress(dsa).to_string().data());
            }

            if ((local & netmask) != (dsa & netmask))
            {
                fprintf(stdout, "--ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet\n");
            }

            return htonl(dsa);
        }

        bool TapWindows::DnsFlushResolverCache() noexcept
        {
            return ppp::win32::Win32Native::DnsFlushResolverCache();
        }

        bool TapWindows::SetDnsAddresses(int interface_index, ppp::vector<ppp::string>& servers) noexcept
        {
            return ppp::win32::network::SetDnsAddresses(interface_index, servers);
        }

        bool TapWindows::SetDnsAddresses(int interface_index, ppp::vector<uint32_t>& servers) noexcept
        {
            ppp::vector<ppp::string> addresses;
            for (uint32_t server : servers)
            {
                IPEndPoint ip(server, 0);
                if (IPEndPoint::IsInvalid(ip))
                {
                    continue;
                }

                ppp::string address = ip.ToAddressString();
                addresses.emplace_back(address);
            }
            return SetDnsAddresses(interface_index, addresses);
        }

        bool TapWindows::SetAddresses(int interface_index, uint32_t ip, uint32_t mask, uint32_t gw) noexcept
        {
            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return false;
            }

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return false;
            }

            IPEndPoint gwEP(gw, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                ppp::string interface_name = ppp::win32::network::GetInterfaceName(interface_index);
                if (interface_name.empty())
                {
                    return false;
                }

                return ppp::win32::network::SetIPAddresses(interface_name, ipEP.ToAddressString(), maskEP.ToAddressString());
            }

            if (!ppp::win32::network::SetIPAddresses(interface_index, { ipEP.ToAddressString() }, { maskEP.ToAddressString() }))
            {
                return false;
            }

            return ppp::win32::network::SetDefaultIPGateway(interface_index, { gwEP.ToAddressString() });
        }

        bool TapWindows::FindAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept
        {
            return ppp::win32::network::GetAllComponentIds(componentIds);
        }

        std::shared_ptr<ITap> TapWindows::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& componentId, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses)
        {
            if (NULL == context)
            {
                return NULL;
            }

            if (componentId.empty())
            {
                return NULL;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return NULL;
            }

            IPEndPoint gwEP(ip, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return NULL;
            }

            IPEndPoint maskEP(ip, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return NULL;
            }

            if (lease_time_in_seconds < 1)
            {
                lease_time_in_seconds = 86400;
            }

            int interface_index = GetNetworkInterfaceIndex(componentId);
            if (interface_index < -1)
            {
                return NULL;
            }

            void* tun = OpenDriver(componentId.data());
            if (NULL == tun || tun == INVALID_HANDLE_VALUE)
            {
                return NULL;
            }

            bool ok = ConfigureDriver_SetNetifUp(tun, true) &&
                ConfigureDriver_SetNetifTunMode(tun, ip, gw, mask) &&
                ConfigureDriver_SetDhcpMASQ(tun, ip, gw, mask, lease_time_in_seconds) &&
                ConfigureDriver_SetDhcpOptionData(tun, ip, mask, gw, gw, dns_addresses);
            if (!ok)
            {
                CloseHandle(tun);
                return NULL;
            }

            std::shared_ptr<TapWindows> tap = make_shared_object<TapWindows>(context, componentId, tun, ip, gw, mask, hosted_network);
            if (NULL == tap)
            {
                CloseHandle(tun);
                return NULL;
            }
            else 
            {
                tap->GetInterfaceIndex() = interface_index;
            }
            
            ppp::vector<ppp::string> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            ppp::vector<ppp::string> ips_stloc;
            Ipep::ToAddresses({ ip }, ips_stloc);

            ppp::vector<ppp::string> gw_stloc;
            Ipep::ToAddresses({ gw }, gw_stloc);

            ppp::vector<ppp::string> mask_stloc;
            Ipep::ToAddresses({ mask }, mask_stloc);

            if (hosted_network)
            {
                ok = ok && SetAddresses(interface_index, ip, mask, gw);
            }
            else
            {
                ok = ok && SetAddresses(interface_index, ip, mask, IPEndPoint::NoneAddress);
            }

            ok = ok && SetDnsAddresses(interface_index, dns_addresses_stloc);
            if (!ok)
            {
                tap->Dispose();
                tap.reset();
            }

            return tap;
        }

        void* TapWindows::OpenDriver(const ppp::string& componentId) noexcept
        {
            char szDeviceName[MAX_PATH];
            if (snprintf(szDeviceName, sizeof(szDeviceName), "\\\\.\\Global\\%s.tap", componentId.data()) < 1)
            {
                return NULL;
            }

            HANDLE handle = CreateFileA(szDeviceName,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
                NULL);
            if (NULL == handle || handle == INVALID_HANDLE_VALUE)
            {
                handle = NULL;
            }

            return handle;
        }

        int TapWindows::GetNetworkInterfaceIndex(const ppp::string& componentId) noexcept
        {
            using NetworkInterface = ppp::win32::network::AdapterInterfacePtr;

            if (componentId.empty())
            {
                return -1;
            }

            ppp::vector<NetworkInterface> interfaces;
            if (!ppp::win32::network::GetAllAdapterInterfaces(interfaces))
            {
                return -1;
            }

            boost::uuids::uuid reft_id = StringToGuid(componentId);
            for (NetworkInterface& ni : interfaces)
            {
                boost::uuids::uuid left_id = StringToGuid(ni->Id);
                if (left_id == reft_id)
                {
                    return ni->IfIndex;
                }
            }
            return -1;
        }

        bool TapWindows::ConfigureDriver_SetNetifUp(const void* handle, bool up) noexcept
        {
            if (NULL == handle || handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            Byte media_status[] = { 1, 0, 0, 0 };
            if (!up)
            {
                media_status[0] = 0;
            }

            return ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, media_status, sizeof(media_status));
        }

        bool TapWindows::ConfigureDriver_SetDhcpMASQ(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds) noexcept
        {
            if (NULL == handle || handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            uint32_t dhcp[] =
            {
                ip,
                mask,
                gw,
                lease_time_in_seconds, /* lease time in seconds */
            };
            return ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, dhcp, sizeof(dhcp));
        }

        bool TapWindows::ConfigureDriver_SetNetifTunMode(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask) noexcept
        {
            if (NULL == handle || handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            uint32_t address[3] = 
            {
                ip,
                gw,
                mask,
            };
            return ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN, address, sizeof(address));
        }

        bool TapWindows::ConfigureDriver_SetDhcpOptionData(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t dhcp, const ppp::vector<uint32_t>& dns_addresses) noexcept
        {
            if (NULL == handle || handle == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            ppp::vector<BYTE> dhcpOptionData;
            BYTE* ip_bytes = (BYTE*)&ip;
            BYTE* gw_bytes = (BYTE*)&gw;
            BYTE* mask_bytes = (BYTE*)&mask;
            BYTE* dhcp_bytes = (BYTE*)&dhcp;

            // IP地址
            dhcpOptionData.emplace_back(0x32);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(*mask_bytes); i++)
            {
                dhcpOptionData.emplace_back(mask_bytes[i]);
            }

            // 子网地址
            dhcpOptionData.emplace_back(0x01);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(*mask_bytes); i++)
            {
                dhcpOptionData.emplace_back(mask_bytes[i]);
            }

            // 网关服务器
            dhcpOptionData.emplace_back(0x03);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(*gw_bytes); i++)
            {
                dhcpOptionData.emplace_back(gw_bytes[i]);
            }

            // DNS服务器
            {
                uint32_t dnsAddressesSize = 0;
                uint32_t dnsAddressesLocal[] = { 0, 0 };
                if (dns_addresses.size() > 1)
                {
                    dnsAddressesSize = sizeof(dnsAddressesLocal);
                    dnsAddressesLocal[0] = dns_addresses[0];
                    dnsAddressesLocal[1] = dns_addresses[1];
                }
                elif(dns_addresses.size() > 0)
                {
                    dnsAddressesSize = sizeof(*dnsAddressesLocal);
                    dnsAddressesLocal[0] = dns_addresses[0];
                }

                dhcpOptionData.emplace_back(0x06);
                dhcpOptionData.emplace_back(dnsAddressesSize);
                for (uint32_t i = 0; i < dnsAddressesSize; i++)
                {
                    BYTE* dnsAddressesBytes = (BYTE*)&dnsAddressesLocal[0];
                    dhcpOptionData.emplace_back(dnsAddressesBytes[i]);
                }
            }

            // DHCP服务器
            dhcpOptionData.emplace_back(0x36);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(*dhcp_bytes); i++)
            {
                dhcpOptionData.emplace_back(dhcp_bytes[i]);
            }

            return ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, dhcpOptionData.data(), (int)dhcpOptionData.size());
        }

        ppp::string TapWindows::FindComponentId() noexcept
        {
            ppp::unordered_set<ppp::string> componentIds;
            if (TapWindows::FindAllComponentIds(componentIds))
            {
                auto tail = componentIds.begin();
                auto endl = componentIds.end();
                if (tail != endl)
                {
                    return *tail;
                }
            }
            return ppp::string();
        }

        static ppp::string TapWindows_FindComponentId(const ppp::string& key, ppp::win32::network::NetworkInterfacePtr& network_interface) noexcept
        {
            ppp::string componentId = key;
            if (key.size() > 0)
            {
                componentId = LTrim<ppp::string>(componentId);
                componentId = RTrim<ppp::string>(componentId);
            }

            if (componentId.size() > 0)
            {
                using NetworkInterfacePtr = ppp::win32::network::NetworkInterfacePtr;

                ppp::vector<NetworkInterfacePtr> interfaces;
                if (ppp::win32::network::GetAllNetworkInterfaces(interfaces))
                {
                    bool component_uuid_sgen = false;
                    boost::uuids::uuid component_uuid;
                    boost::uuids::string_generator sgen;
                    try
                    {
                        component_uuid = sgen(componentId);
                        component_uuid_sgen = true;
                    }
                    catch (const std::exception&)
                    {
                        component_uuid_sgen = false;
                    }

                    ppp::string component_id = ToLower<ppp::string>(componentId);
                    std::size_t interfaces_size = interfaces.size();
                    for (std::size_t i = 0; i < interfaces_size; i++)
                    {
                        NetworkInterfacePtr& ni = interfaces[i];
                        if (component_uuid_sgen)
                        {
                            if (StringToGuid(ni->Guid) == component_uuid)
                            {
                                network_interface = ni;
                                return ni->Guid;
                            }
                        }

                        ppp::string connection_id = ToLower<ppp::string>(ni->ConnectionId);
                        connection_id = LTrim<ppp::string>(connection_id);
                        connection_id = RTrim<ppp::string>(connection_id);
                        if (connection_id == component_id)
                        {
                            network_interface = ni;
                            return ni->Guid;
                        }
                    }
                }
                return ppp::string();
            }
            else
            {
                return TapWindows::FindComponentId();
            }
        }

        ppp::string TapWindows::FindComponentId(const ppp::string& key) noexcept
        {
            ppp::win32::network::NetworkInterfacePtr ni;
            return TapWindows_FindComponentId(key, ni);
        }

        bool TapWindows::InstallDriver(const ppp::string& path, const ppp::string& declareTapName) noexcept
        {
            if (path.empty() || declareTapName.empty())
            {
                return false;
            }

            ppp::string installPath = ppp::io::File::RewritePath((path + "tapinstall.exe").data());
            if (!PathFileExistsA(installPath.data()))
            {
                return false;
            }

            ppp::string driverPath = path + "OemVista.inf";
            ppp::string argumentsText = "install \"" + driverPath + "\" tap0901";

            int dwExitCode = INFINITE;
            if (!ppp::win32::Win32Native::Execute(false, installPath.data(), argumentsText.data(), &dwExitCode))
            {
                return false;
            }

            if (dwExitCode != ERROR_SUCCESS)
            {
                return false;
            }

            ppp::string componentId = FindComponentId();
            if (componentId.empty())
            {
                return false;
            }

            ppp::win32::network::NetworkInterfacePtr network_interface;
            TapWindows_FindComponentId(componentId, network_interface);

            if (NULL == network_interface)
            {
                return false;
            }

            return ppp::win32::network::SetInterfaceName(network_interface->InterfaceIndex, declareTapName);
        }

        bool TapWindows::UninstallDriver(const ppp::string& path) noexcept
        {
            if (path.empty())
            {
                return false;
            }

            ppp::string installPath = ppp::io::File::RewritePath((path + "tapinstall.exe").data());
            if (!PathFileExistsA(installPath.data()))
            {
                return false;
            }

            int dwExitCode = INFINITE;
            if (!ppp::win32::Win32Native::Execute(false, installPath.data(), "remove tap0901", &dwExitCode))
            {
                return false;
            }

            return dwExitCode == ERROR_SUCCESS;
        }

        bool TapWindows::SetInterfaceMtu(int mtu) noexcept
        {
            int interface_index = GetInterfaceIndex();
            if (interface_index == -1)
            {
                return false;
            }

            return ppp::win32::network::SetInterfaceMtuIpSubInterface(interface_index, mtu);
        }
    }
}