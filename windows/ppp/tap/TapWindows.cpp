#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/tap/tap-windows.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/text/Encoding.h>

#include <windows/ppp/tap/WintunAdapter.h>

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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return false;
            }

            IPEndPoint gwEP(gw, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                ppp::string interface_name = ppp::win32::network::GetInterfaceName(interface_index);
                if (interface_name.empty())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return false;
                }

                if (!ppp::win32::network::SetIPAddresses(interface_name, ipEP.ToAddressString(), maskEP.ToAddressString()))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                    return false;
                }

                return true;
            }

            if (!ppp::win32::network::SetIPAddresses(interface_index, { ipEP.ToAddressString() }, { maskEP.ToAddressString() }))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            if (!ppp::win32::network::SetDefaultIPGateway(interface_index, { gwEP.ToAddressString() }))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        bool TapWindows::FindAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept
        {
            return ppp::win32::network::GetAllComponentIds(componentIds);
        }

        static bool SetAdapterInterface(int interface_index, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
        {
            ppp::vector<ppp::string> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            ppp::vector<ppp::string> ips_stloc;
            Ipep::ToAddresses({ ip }, ips_stloc);

            ppp::vector<ppp::string> gw_stloc;
            Ipep::ToAddresses({ gw }, gw_stloc);

            ppp::vector<ppp::string> mask_stloc;
            Ipep::ToAddresses({ mask }, mask_stloc);

            bool ok = true;
            if (hosted_network)
            {
                ok = ok && TapWindows::SetAddresses(interface_index, ip, mask, gw);
            }
            else
            {
                ok = ok && TapWindows::SetAddresses(interface_index, ip, mask, IPEndPoint::NoneAddress);
            }

            ok = ok && TapWindows::SetDnsAddresses(interface_index, dns_addresses_stloc);
            return ok;
        }

        struct WintunAdapterDriver final
        {
        public:
            static std::shared_ptr<ITap> CreateWintunAdapter(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& nic, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
            {
                GUID* NULL_GUID = NULLPTR;
                std::shared_ptr<WintunAdapter> wintun = make_shared_object<WintunAdapter>(
                    ppp::text::Encoding::ascii_to_wstring(stl::transform<std::string>(nic)), L"PPP PRIVATE NETWORK 2", NULL_GUID, WintunAdapter::MAX_RING_BUFFER_SIZE);
                if (NULL == wintun)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                if (!wintun->Open())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
                    wintun->Stop();
                    return NULLPTR;
                }

                int interface_index = TapWindows::GetNetworkInterfaceIndex(nic);
                if (interface_index < -1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    wintun->Stop();
                    return NULLPTR;
                }

                if (!SetAdapterInterface(interface_index, ip, gw, mask, hosted_network, dns_addresses))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                    wintun->Stop();
                    return NULLPTR;
                }

                if (!wintun->Start())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunSessionStartFailed);
                    wintun->Stop();
                    return NULLPTR;
                }

                std::shared_ptr<TapWindows> tap = make_shared_object<TapWindows>(context, nic, wintun.get(), ip, gw, mask, hosted_network);
                if (NULL == tap)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    wintun->Stop();
                    return NULLPTR;
                }

                {
                    std::lock_guard<std::mutex> lock(tap->wintun_mutex_);
                    tap->wintun_adapter_ = wintun;
                }
                tap->GetInterfaceIndex() = interface_index;
                return tap;
            }
        };

        std::shared_ptr<ITap> TapWindows::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& componentId, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses)
        {
            if (NULLPTR == context)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return NULLPTR;
            }

            if (componentId.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapWindowsCreateComponentIdEmpty);
                return NULLPTR;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return NULLPTR;
            }

            IPEndPoint gwEP(ip, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return NULLPTR;
            }

            IPEndPoint maskEP(ip, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return NULLPTR;
            }

            if (lease_time_in_seconds < 1)
            {
                lease_time_in_seconds = 86400;
            }

            if (WintunAdapter::Ready())
            {
                return WintunAdapterDriver::CreateWintunAdapter(context, componentId, ip, gw, mask, hosted_network, dns_addresses);
            }

            int interface_index = GetNetworkInterfaceIndex(componentId);
            if (interface_index < -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return NULLPTR;
            }

            void* tun = OpenDriver(componentId.data());
            if (NULLPTR == tun || tun == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                return NULLPTR;
            }

            bool ok = ConfigureDriver_SetNetifUp(tun, true) &&
                (ConfigureDriver_SetTunModeWithAddress(tun, ip, gw, mask) || 
                    ConfigureDriver_SetTunModeWithAddress(tun, ip, (ip & mask), mask)) &&
                ConfigureDriver_SetDhcpMASQ(tun, ip, gw, mask, lease_time_in_seconds) &&
                ConfigureDriver_SetDhcpOptionData(tun, ip, gw, mask, gw, dns_addresses);

            if (!ok)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                CloseHandle(tun);
                return NULLPTR;
            }

            std::shared_ptr<TapWindows> tap = make_shared_object<TapWindows>(context, componentId, tun, ip, gw, mask, hosted_network);
            if (NULLPTR == tap)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                CloseHandle(tun);
                return NULLPTR;
            }
            else 
            {
                tap->GetInterfaceIndex() = interface_index;
            }
            
            ok = SetAdapterInterface(interface_index, ip, gw, mask, hosted_network, dns_addresses);
            if (ok)
            {
                return tap;
            }

            tap->Dispose();
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
            return NULLPTR;
        }

        void* TapWindows::OpenDriver(const ppp::string& componentId) noexcept
        {
            char szDeviceName[MAX_PATH];
            if (snprintf(szDeviceName, sizeof(szDeviceName), "\\\\.\\Global\\%s.tap", componentId.data()) < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                return NULLPTR;
            }

            HANDLE handle = CreateFileA(szDeviceName,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULLPTR,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
                NULLPTR);
            if (NULLPTR == handle || handle == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                handle = NULLPTR;
            }

            return handle;
        }

        int TapWindows::GetNetworkInterfaceIndex(const ppp::string& componentId) noexcept
        {
            using NetworkInterface = ppp::win32::network::AdapterInterfacePtr;

            if (WintunAdapter::Ready())
            {
                return ppp::win32::network::GetIfIndexByFriendlyName(ppp::text::Encoding::ascii_to_wstring(stl::transform<std::string>(componentId)));
            }

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

        bool TapWindows::Output(const void* packet, int packet_size) noexcept
        {
            if (WintunAdapter::Ready())
            {
                if (NULLPTR == packet || packet_size < 1)
                {
                    return true;
                }

                std::shared_ptr<WintunAdapter> wintun;
                {
                    std::lock_guard<std::mutex> lock(wintun_mutex_);
                    wintun = wintun_adapter_;
                }
                if (NULLPTR == wintun)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                if (!wintun->IsOpen())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                return wintun->SendPacket((uint8_t*)packet, packet_size);
            }

            return ITap::Output(packet, packet_size);
        }

        bool TapWindows::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept
        {
            if (WintunAdapter::Ready())
            {
                if (NULLPTR == packet || packet_size < 1)
                {
                    return true;
                }

                std::shared_ptr<WintunAdapter> wintun;
                {
                    std::lock_guard<std::mutex> lock(wintun_mutex_);
                    wintun = wintun_adapter_;
                }
                if (NULLPTR == wintun)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                if (!wintun->IsOpen())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                return wintun->SendPacket((uint8_t*)packet.get(), packet_size);
            }

            return ITap::Output(packet, packet_size);
        }

        bool TapWindows::AsynchronousReadPacketLoops() noexcept
        {
            if (WintunAdapter::Ready())
            {
                std::shared_ptr<WintunAdapter> wintun;
                {
                    std::lock_guard<std::mutex> lock(wintun_mutex_);
                    wintun = wintun_adapter_;
                }
                if (NULLPTR == wintun)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                if (!wintun->IsOpen())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return false;
                }

                auto packet_input = make_shared_object<WintunAdapter::PacketHandler>();
                if (NULLPTR == packet_input)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                auto self = std::static_pointer_cast<TapWindows>(shared_from_this());
                *packet_input =
                    [self](const uint8_t* data, uint32_t len) noexcept
                    {
                        int packet_length = std::max<int>(len, -1);
                        if (packet_length > 0)
                        {
                            PacketInputEventArgs e{ (char*)data, packet_length };
                            self->OnInput(e);
                        }
                    };
                wintun->SetPacketInput(packet_input);
                return true;
            }
            
            return ITap::AsynchronousReadPacketLoops();
        }

        bool TapWindows::ConfigureDriver_SetNetifUp(const void* handle, bool up) noexcept
        {
            if (NULLPTR == handle || handle == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                return false;
            }

            Byte media_status[] = { 1, 0, 0, 0 };
            if (!up)
            {
                media_status[0] = 0;
            }

            if (!ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, media_status, sizeof(media_status)))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        bool TapWindows::ConfigureDriver_SetDhcpMASQ(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds) noexcept
        {
            if (NULLPTR == handle || handle == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                return false;
            }

            uint32_t dhcp[] =
            {
                ip,
                mask,
                gw,
                lease_time_in_seconds, /* lease time in seconds */
            };
            if (!ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, dhcp, sizeof(dhcp)))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        // Configures TAP-Windows driver for TUN mode operation (NOT TAP mode).
        // CRITICAL: In TUN mode, the driver requires the "gateway" parameter to be the NETWORK ADDRESS (ip & mask),
        // NOT the actual gateway IP (e.g., 10.0.0.1). This serves as the TUN interface's peer address per driver specification.
        //
        // Why this is necessary:
        //   - TAP-Windows driver in TUN mode expects network address (e.g., 10.0.0.0 for 10.0.0.0/24) as the peer endpoint
        //   - Actual gateway configuration is handled separately by SetAddresses():
        //        * hosted_network mode: Sets OS interface gateway to intended gw (e.g., 10.0.0.1)
        //        * non-hosted_network mode: Sets gateway to 0.0.0.0 (no gateway)
        //   - This separation resolves the historical inconsistency:
        //        * Driver layer: Uses network address (required by TAP-Windows TUN implementation)
        //        * OS network layer: Uses standard gateway (10.0.0.1) for cross-platform consistency
        //        * Other platforms (Linux/Unix): Configure gateway directly at OS layer without driver quirks
        //
        // Parameter note:
        //   gw MUST be (ip & mask) - passing actual gateway IP here will break TUN mode operation.
        //   See Create() implementation: ConfigureDriver_SetTunModeWithAddress(tun, ip, (ip & mask), mask)
        //
        // This function is essential for TUN mode initialization on Windows and MUST be called
        // with correctly computed network address. Do not confuse with OS-level gateway configuration.
        bool TapWindows::ConfigureDriver_SetTunModeWithAddress(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask) noexcept
        {
            if (NULLPTR == handle || handle == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                return false;
            }

            uint32_t address[3] =
            {
                ip,
                gw,      // MUST be network address (ip & mask), NOT actual gateway
                mask,
            };
            if (!ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_TUN, address, sizeof(address)))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        bool TapWindows::ConfigureDriver_SetDhcpOptionData(const void* handle, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t dhcp, const ppp::vector<uint32_t>& dns_addresses) noexcept
        {
            if (NULLPTR == handle || handle == INVALID_HANDLE_VALUE)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
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
            for (uint32_t i = 0; i < sizeof(ip); i++)
            {
                dhcpOptionData.emplace_back(ip_bytes[i]);
            }

            // 子网地址
            dhcpOptionData.emplace_back(0x01);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(mask); i++)
            {
                dhcpOptionData.emplace_back(mask_bytes[i]);
            }

            // 网关服务器
            dhcpOptionData.emplace_back(0x03);
            dhcpOptionData.emplace_back(0x04);
            for (uint32_t i = 0; i < sizeof(gw); i++)
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
            for (uint32_t i = 0; i < sizeof(dhcp); i++)
            {
                dhcpOptionData.emplace_back(dhcp_bytes[i]);
            }

            if (!ppp::win32::Win32Native::DeviceIoControl(handle, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, dhcpOptionData.data(), (int)dhcpOptionData.size()))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        bool TapWindows::IsWintun() noexcept
        {
            return WintunAdapter::Ready();
        }

        bool TapWindows::IsWintunBackend() noexcept
        {
            std::lock_guard<std::mutex> lock(wintun_mutex_);
            return NULLPTR != wintun_adapter_;
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
            if (WintunAdapter::Ready())
            {
                return key;
            }

            ppp::win32::network::NetworkInterfacePtr ni;
            return TapWindows_FindComponentId(key, ni);
        }

        bool TapWindows::InstallDriver(const ppp::string& path, const ppp::string& declareTapName) noexcept
        {
            if (path.empty() || declareTapName.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapWindowsInstallDriverInvalidArguments);
                return false;
            }

            ppp::string installPath = ppp::io::File::RewritePath((path + "tapinstall.exe").data());
            if (!PathFileExistsA(installPath.data()))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileOpenFailed);
                return false;
            }

            ppp::string driverPath = path + "OemVista.inf";
            ppp::string argumentsText = "install \"" + driverPath + "\" tap0901";

            ppp::unordered_set<ppp::string> olds;
            TapWindows::FindAllComponentIds(olds);

            int dwExitCode = INFINITE;
            if (!ppp::win32::Win32Native::Execute(false, installPath.data(), argumentsText.data(), &dwExitCode))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsServiceStartFailed);
                return false;
            }

            if (dwExitCode != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsServiceStartFailed);
                return false;
            }

            ppp::unordered_set<ppp::string> news;
            TapWindows::FindAllComponentIds(news);

            for (ppp::string key : olds)
            {
                auto tail = news.find(key);
                auto endl = news.end();
                if (tail != endl)
                {
                    news.erase(tail);
                }
            }

            if (news.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

            ppp::win32::network::NetworkInterfacePtr network_interface;
            TapWindows_FindComponentId(*news.begin(), network_interface);

            if (NULLPTR == network_interface)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

            bool ok = ppp::win32::network::SetInterfaceName(network_interface->InterfaceIndex, declareTapName);
            if (false == ok)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }
            return true;
        }

        bool TapWindows::UninstallDriver(const ppp::string& path) noexcept
        {
            if (path.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapWindowsUninstallDriverPathEmpty);
                return false;
            }

            ppp::string installPath = ppp::io::File::RewritePath((path + "tapinstall.exe").data());
            if (!PathFileExistsA(installPath.data()))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileOpenFailed);
                return false;
            }

            int dwExitCode = INFINITE;
            if (!ppp::win32::Win32Native::Execute(false, installPath.data(), "remove tap0901", &dwExitCode))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsServiceStopFailed);
                return false;
            }

            if (ERROR_SUCCESS != dwExitCode)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsServiceStopFailed);
                return false;
            }
            return true;
        }

        bool TapWindows::SetInterfaceMtu(int mtu) noexcept
        {
            int interface_index = GetInterfaceIndex();
            if (interface_index == -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

            if (!ppp::win32::network::SetInterfaceMtuIpSubInterface(interface_index, mtu))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return false;
            }

            return true;
        }

        void TapWindows::Dispose() noexcept
        {
            if (WintunAdapter::Ready())
            {
                std::shared_ptr<WintunAdapter> wintun;
                {
                    std::lock_guard<std::mutex> lock(wintun_mutex_);
                    wintun = wintun_adapter_;
                }
                if (wintun)
                {
                    wintun->ClearPacketInput();
                    wintun->Stop();
                }
            }

            ITap::Dispose();
        }
    }
}
