// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/setdnsserversearchorder-method-in-class-win32-networkadapterconfiguration
// https://learn.microsoft.com/zh-cn/windows/win32/wmisdk/example--calling-a-provider-method?source=recommendations

#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/Win32Variant.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/tap/tap-windows.h>

#include <ppp/Int128.h>
#include <ppp/text/Encoding.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/eth.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <Windows.h>
#include <netcfgx.h>
#include <comutil.h>
#include <initguid.h>

// Need to link with Iphlpapi.lib
#pragma comment(lib, "iphlpapi.lib")

// Need to link with Ole32.lib to print GUID
#pragma comment(lib, "ole32.lib")

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "setupapi.lib")

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            static ppp::string NETWORK_INTERFACE_STRING_TEXT(const TCHAR* s, int sz) noexcept
            {
                if (NULLPTR != s)
                {
                    std::string result;
                    if (sz > 0)
                    {
#ifdef UNICODE
                        result = ppp::text::Encoding::wstring_to_utf8(std::wstring((WCHAR*)s, sz));
#else
                        result = ppp::string(((CHAR*))s, sz);
#endif
                    }
                    else
                    {
#ifdef UNICODE
                        result = ppp::text::Encoding::wstring_to_utf8(std::wstring((WCHAR*)s)).data();
#else
                        result = ppp::string(((CHAR*))s);
#endif
                    }
                    return stl::transform<ppp::string>(result);
                }
                return ppp::string();
            }

            static TCHAR* tcschr(const TCHAR* s, TCHAR ch) noexcept
            {
                if (NULLPTR == s)
                {
                    return NULLPTR;
                }

#ifdef UNICODE
                TCHAR* p = (WCHAR*)wcschr((WCHAR*)s, (WCHAR)ch);
#else
                TCHAR* p = (TCHAR*)strchr((CHAR*)s, (CHAR)ch);
#endif
                return p;
            }

            static int64_t ttoll(const TCHAR* s) noexcept
            {
                if (NULLPTR == s)
                {
                    return 0;
                }

#ifdef UNICODE
                int64_t index = _wtoll((WCHAR*)s);
#else
                int64_t index = atoll((CHAR*)s);
#endif
                return index;
            }

            static ppp::string GetInterfaceLuidString(int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return ppp::string();
                }

                NET_LUID luid{};
                if (ConvertInterfaceIndexToLuid(static_cast<NET_IFINDEX>(interface_index), &luid) != NO_ERROR)
                {
                    return ppp::string();
                }

                return stl::transform<ppp::string>(
                    std::to_string(static_cast<unsigned long long>(luid.Value)));
            }

            static bool GetDnsAutomaticByGuid(const ppp::string& guid, bool& automatic) noexcept
            {
                automatic = false;
                if (guid.empty())
                {
                    return false;
                }

                ppp::string path(
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\");
                path.append(guid);
                HKEY key = NULL;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
                {
                    return false;
                }

                char value[4096] = {};
                DWORD type = 0;
                DWORD size = sizeof(value);
                const LONG result = RegQueryValueExA(
                    key, "NameServer", NULL, &type, reinterpret_cast<LPBYTE>(value), &size);
                RegCloseKey(key);
                if (result == ERROR_FILE_NOT_FOUND)
                {
                    // No static NameServer value means the adapter uses the
                    // DHCP supplied DNS servers.
                    automatic = true;
                    return true;
                }
                if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
                {
                    return false;
                }

                automatic = size <= sizeof(char) || value[0] == '\0';
                return true;
            }

            static bool RegistryEditGetValue(HKEY hSubKey, const TCHAR* key, ppp::string& value) noexcept
            {
                TCHAR szBuffer[MAX_PATH];
                DWORD dwSize = sizeof(szBuffer);
                if (RegQueryValueEx(hSubKey, key, NULLPTR, NULLPTR, reinterpret_cast<LPBYTE>(szBuffer), &dwSize) == ERROR_SUCCESS)
                {
                    if (dwSize > 0)
                    {
                        value = NETWORK_INTERFACE_STRING_TEXT(szBuffer, -1);
                    }
                    else
                    {
                        value.clear();
                    }
                    return true;
                }
                return false;
            }

            template <typename InternalCall>
            static bool SetNetifAddressesInternal(int interface_index, InternalCall&& internal_call) noexcept
            {
                IWbemLocator* pLoc = NULLPTR;
                HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
                if (FAILED(hr))
                {
                    return false;
                }

                IWbemServices* pSvc = NULLPTR;
                hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULLPTR, NULLPTR, 0, NULL, 0, 0, &pSvc);
                if (FAILED(hr))
                {
                    pLoc->Release();
                    return false;
                }

                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULLPTR, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULLPTR, EOAC_NONE);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                WCHAR wsql[256];
                if (_snwprintf(wsql, sizeof(wsql), L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE InterfaceIndex = '%d'", interface_index) < 1)
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                IEnumWbemClassObject* pEnumerator = NULLPTR;
                hr = pSvc->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(wsql),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULLPTR,
                    &pEnumerator);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                bool ok = false;
                while (pEnumerator)
                {
                    IWbemClassObject* pclsObj = NULLPTR;
                    ULONG uReturn = 0;
                    BOOL bBreak = FALSE;
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (FAILED(hr) || 0 == uReturn)
                    {
                        bBreak = TRUE;
                        goto pclsObj_Release;
                    }

                    if (pclsObj)
                    {
                        ok |= internal_call(pSvc, pclsObj);
                    }

                pclsObj_Release:
                    if (pclsObj)
                    {
                        pclsObj->Release();
                    }

                    if (bBreak)
                    {
                        break;
                    }
                }

                pEnumerator->Release();
                pSvc->Release();
                pLoc->Release();

                return ok;
            }

            class MOF_Win32_NetworkAdapter
            {
            public:
                ppp::string NetConnectionID;
                ppp::string GUID;
                int InterfaceIndex;
            };

            static ppp::string GetAdapterNameByIndexWMI(int iIndex, ppp::map<int, MOF_Win32_NetworkAdapter>& adapters) noexcept
            {
                IWbemLocator* pLocator = NULLPTR;
                HRESULT hRes = CoCreateInstance(CLSID_WbemLocator, NULLPTR, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLocator);
                if (FAILED(hRes) || !pLocator)
                {
                    return ppp::string();
                }

                IWbemServices* pServices = NULLPTR;
                hRes = pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULLPTR, NULLPTR, NULLPTR, 0, NULLPTR, NULLPTR, &pServices);
                if (FAILED(hRes) || !pServices)
                {
                    pLocator->Release();
                    return ppp::string();
                }

                hRes = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULLPTR, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULLPTR, EOAC_NONE);
                if (FAILED(hRes))
                {
                    pServices->Release();
                    pLocator->Release();
                    return ppp::string();
                }

                WCHAR wszQuery[512];
                if (iIndex < 0)
                {
                    swprintf_s(wszQuery, _countof(wszQuery), L"SELECT * FROM Win32_NetworkAdapter");
                }
                else
                {
                    swprintf_s(wszQuery, _countof(wszQuery), L"SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex='%u'", iIndex);
                }

                IEnumWbemClassObject* pEnumerator = NULLPTR;
                hRes = pServices->ExecQuery(_bstr_t("WQL"), _bstr_t(wszQuery), WBEM_FLAG_FORWARD_ONLY, NULLPTR, &pEnumerator);
                if (FAILED(hRes) || !pEnumerator)
                {
                    pServices->Release();
                    pLocator->Release();
                    return ppp::string();
                }

                IWbemClassObject* pObject = NULLPTR;
                ULONG uReturn = 0;
                ppp::string szNetConnectionID = {};
                while (pEnumerator)
                {
                    IWbemClassObject* pclsObj = NULLPTR;
                    ULONG uReturn = 0;
                    BOOL bBreak = FALSE;
                    hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (FAILED(hRes) || 0 == uReturn)
                    {
                        bBreak = TRUE;
                        goto pclsObj_Release;
                    }

                    if (pclsObj)
                    {
                        szNetConnectionID = VARIANT_string(pclsObj, L"NetConnectionID");
                        if (iIndex < 0)
                        {
                            MOF_Win32_NetworkAdapter network_adapter;
                            int interface_index = VARIANT_value(pclsObj, L"InterfaceIndex", -1);
                            network_adapter.NetConnectionID = szNetConnectionID;
                            network_adapter.InterfaceIndex = interface_index;
                            network_adapter.GUID = VARIANT_string(pclsObj, L"GUID");
                            adapters[interface_index] = network_adapter;
                        }
                        else
                        {
                            bBreak = TRUE;
                        }
                    }

                pclsObj_Release:
                    if (pclsObj)
                    {
                        pclsObj->Release();
                    }

                    if (bBreak)
                    {
                        break;
                    }
                }

                pEnumerator->Release();
                pServices->Release();
                pLocator->Release();
                return szNetConnectionID;
            }

            static bool GetAllNetworkInterfacesInternal(bool is_network_index, int index, ppp::vector<NetworkInterfacePtr>& interfaces) noexcept
            {
                IWbemLocator* pLoc = NULLPTR;
                HRESULT hr = CoCreateInstance(
                    CLSID_WbemLocator,
                    0,
                    CLSCTX_INPROC_SERVER,
                    IID_IWbemLocator,
                    (LPVOID*)&pLoc);
                if (FAILED(hr))
                {
                    return false;
                }

                IWbemServices* pSvc = NULLPTR;
                hr = pLoc->ConnectServer(
                    _bstr_t(L"ROOT\\CIMV2"),
                    NULLPTR,
                    NULLPTR,
                    0,
                    NULL,
                    0,
                    0,
                    &pSvc);
                if (FAILED(hr))
                {
                    pLoc->Release();
                    return false;
                }

                hr = CoSetProxyBlanket(
                    pSvc,
                    RPC_C_AUTHN_WINNT,
                    RPC_C_AUTHZ_NONE,
                    NULLPTR,
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    NULLPTR,
                    EOAC_NONE);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                WCHAR wsql[256] = L"SELECT * FROM Win32_NetworkAdapterConfiguration";
                if (index > -1)
                {
                    LPCWSTR format = L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = '%d'";
                    if (is_network_index)
                    {
                        format = L"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE InterfaceIndex = '%d'";
                    }

                    if (_snwprintf(wsql, sizeof(wsql), format, index) < 1)
                    {
                        pSvc->Release();
                        pLoc->Release();
                        return false;
                    }
                }

                IEnumWbemClassObject* pEnumerator = NULLPTR;
                hr = pSvc->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(wsql), /*  WHERE IPEnabled = TRUE */
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULLPTR,
                    &pEnumerator);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                bool ok = false;
                while (pEnumerator)
                {
                    IWbemClassObject* pclsObj = NULLPTR;
                    ULONG uReturn = 0;
                    BOOL bBreak = FALSE;
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (FAILED(hr) || 0 == uReturn)
                    {
                        bBreak = TRUE;
                        goto pclsObj_Release;
                    }

                    if (pclsObj)
                    {
                        NetworkInterfacePtr networkInterface = make_shared_object<NetworkInterface>();
                        if (NULLPTR != networkInterface)
                        {
                            networkInterface->Description = VARIANT_string(pclsObj, L"Description");
                            networkInterface->Driver = VARIANT_string(pclsObj, L"ServiceName");
                            networkInterface->Guid = VARIANT_string(pclsObj, L"SettingID");
                            networkInterface->Index = VARIANT_value(pclsObj, L"Index", -1);
                            networkInterface->InterfaceIndex = VARIANT_value(pclsObj, L"InterfaceIndex", -1);
                            networkInterface->InterfaceLuid = GetInterfaceLuidString(networkInterface->InterfaceIndex);
                            networkInterface->Metric = VARIANT_value(pclsObj, L"IPConnectionMetric", -1);
                            networkInterface->MacAddress = VARIANT_string(pclsObj, L"MacAddress");
                            networkInterface->IPEnabled = VARIANT_value(pclsObj, L"IPEnabled", false);
                            networkInterface->DhcpEnabled = VARIANT_value(pclsObj, L"DhcpEnabled", false);
                            networkInterface->Caption = VARIANT_string(pclsObj, L"Caption");
                            networkInterface->ScopeId = VARIANT_string(pclsObj, L"WINSScopeID");
                            networkInterface->ConnectionId = VARIANT_string(pclsObj, L"NetConnectionID");
                            networkInterface->Status = GetOperationalStatus(networkInterface->InterfaceIndex);

                            VARIANT_strings(pclsObj, L"IPAddress", networkInterface->IPAddresses);
                            VARIANT_strings(pclsObj, L"IPSubnet", networkInterface->IPSubnet);
                            VARIANT_strings(pclsObj, L"DefaultIPGateway", networkInterface->DefaultIPGateway);
                            VARIANT_strings(pclsObj, L"DNSServerSearchOrder", networkInterface->DnsAddresses);

                            ok |= true;
                            interfaces.emplace_back(networkInterface);
                        }
                    }

                pclsObj_Release:
                    if (pclsObj)
                    {
                        pclsObj->Release();
                    }

                    if (bBreak)
                    {
                        break;
                    }
                }

                pEnumerator->Release();
                pSvc->Release();
                pLoc->Release();
                return ok;
            }

            static NetworkInterfacePtr GetAllNetworkInterfacesInternal(bool is_network_index, int index) noexcept
            {
                if (index < 0)
                {
                    return NULLPTR;
                }

                ppp::vector<NetworkInterfacePtr> network_interfaces;
                if (!GetAllNetworkInterfacesInternal(is_network_index, index, network_interfaces))
                {
                    return NULLPTR;
                }

                if (network_interfaces.empty())
                {
                    return NULLPTR;
                }
                else
                {
                    NetworkInterfacePtr network_interface = network_interfaces[0];
                    if (NULLPTR != network_interface)
                    {
                        int network_index = network_interface->InterfaceIndex;
                        if (network_index > -1)
                        {
                            ppp::map<int, MOF_Win32_NetworkAdapter> network_adapters;
                            network_interface->ConnectionId = GetAdapterNameByIndexWMI(network_index, network_adapters);
                        }
                    }
                    return network_interface;
                }
            }

            static bool SetNetifAddressesInternal(IWbemServices* services, IWbemClassObject* obj, const _bstr_t& method, LPCWSTR parameter, const ppp::vector<ppp::string>& addresses) noexcept
            {
                const _bstr_t Win32_NetworkAdapterConfiguration(L"Win32_NetworkAdapterConfiguration");

                return Callvirt(services, obj, Win32_NetworkAdapterConfiguration, method,
                    [&addresses, parameter](IWbemClassObject* pClassInstance) noexcept
                    {
                        VARIANT vt;
                        VariantInit(&vt);

                        HRESULT hr = VARIANT_create_safe_array(vt, addresses);
                        if (SUCCEEDED(hr))
                        {
                            hr = pClassInstance->Put(parameter, 0, &vt, 0);
                        }

                        VariantClear(&vt);
                        return hr;
                    });
            }

            static bool SetDnsAddressesInternal(IWbemServices* services, IWbemClassObject* obj, const ppp::vector<ppp::string>& servers) noexcept
            {
                const _bstr_t SetDNSServerSearchOrder(L"SetDNSServerSearchOrder");

                return SetNetifAddressesInternal(services, obj, SetDNSServerSearchOrder, L"DNSServerSearchOrder", servers);
            }

            static bool SetNetifIPAddressInternal(IWbemServices* services, IWbemClassObject* obj, const ppp::vector<ppp::string>& ips, const ppp::vector<ppp::string>& masks) noexcept
            {
                const _bstr_t Win32_NetworkAdapterConfiguration(L"Win32_NetworkAdapterConfiguration");
                const _bstr_t EnableStatic(L"EnableStatic");

                return Callvirt(services, obj, Win32_NetworkAdapterConfiguration, EnableStatic,
                    [&ips, &masks](IWbemClassObject* pClassInstance) noexcept
                    {
                        VARIANT vtIPAddress;
                        VARIANT vtSubnetMask;

                        VariantInit(&vtIPAddress);
                        VariantInit(&vtSubnetMask);

                        HRESULT hr = VARIANT_create_safe_array(vtIPAddress, ips);
                        if (SUCCEEDED(hr))
                        {
                            hr = pClassInstance->Put(L"IPAddress", 0, &vtIPAddress, 0);
                            if (SUCCEEDED(hr))
                            {
                                hr = VARIANT_create_safe_array(vtSubnetMask, masks);
                                if (SUCCEEDED(hr))
                                {
                                    hr = pClassInstance->Put(L"SubnetMask", 0, &vtSubnetMask, 0);
                                }
                            }
                        }

                        VariantClear(&vtIPAddress);
                        VariantClear(&vtSubnetMask);
                        return hr;
                    });
                return false;
            }

            static bool SetDefaultIPGatewayInternal(IWbemServices* services, IWbemClassObject* obj, const ppp::vector<ppp::string>& gateways) noexcept
            {
                const _bstr_t SetGateways(L"SetGateways");

                return SetNetifAddressesInternal(services, obj, SetGateways, L"DefaultIPGateway", gateways);
            }

            static bool DhcpEnabledInternal(IWbemServices* services, IWbemClassObject* obj) noexcept
            {
                const _bstr_t Win32_NetworkAdapterConfiguration(L"Win32_NetworkAdapterConfiguration");
                const _bstr_t EnableDHCP(L"EnableDHCP");

                VARIANT vtDHCPEnabled;
                VariantInit(&vtDHCPEnabled);

                VARIANT vtPATH;
                VariantInit(&vtPATH);

                vtDHCPEnabled.vt = VT_BOOL;
                vtDHCPEnabled.boolVal = VARIANT_TRUE;

                HRESULT hr = obj->Put(L"DHCPEnabled", 0, &vtDHCPEnabled, 0);
                if (SUCCEEDED(hr))
                {
                    hr = obj->Get(L"__PATH", 0, &vtPATH, NULLPTR, NULLPTR);
                    if (SUCCEEDED(hr))
                    {
                        hr = services->ExecMethod(vtPATH.bstrVal, EnableDHCP, 0, NULLPTR, obj, NULLPTR, NULLPTR);
                    }
                }

                if (vtPATH.vt & VT_BSTR)
                {
                    SysFreeString(vtPATH.bstrVal);
                }

                VariantClear(&vtPATH);
                VariantClear(&vtDHCPEnabled);
                return SUCCEEDED(hr);
            }

            static bool GetAllComponentIdsByRegistryEdit(ppp::unordered_set<ppp::string>& componentIds) noexcept
            {
                HKEY hKey;
                TCHAR szSubKeyName[MAX_PATH];
                DWORD dwSubKeyNameLength = MAX_PATH;

                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(ADAPTER_KEY), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
                {
                    DWORD dwIndex = 0;
                    while (RegEnumKeyEx(hKey, dwIndex++, szSubKeyName, &dwSubKeyNameLength, NULLPTR, NULLPTR, NULLPTR, NULLPTR) != ERROR_NO_MORE_ITEMS)
                    {
                        HKEY hSubKey;
                        if (RegOpenKeyEx(hKey, szSubKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                        {
                            ppp::string strComponentId;
                            if (RegistryEditGetValue(hSubKey, _T("ComponentId"), strComponentId))
                            {
                                if (strcmp(strComponentId.data(), "tap0901") == 0)
                                {
                                    ppp::string strNetCfgInstanceId;
                                    if (RegistryEditGetValue(hSubKey, _T("NetCfgInstanceId"), strNetCfgInstanceId))
                                    {
                                        componentIds.emplace(strNetCfgInstanceId);
                                    }
                                }
                            }

                            RegCloseKey(hSubKey);
                        }

                        dwSubKeyNameLength = MAX_PATH;
                    }

                    RegCloseKey(hKey);
                    return true;
                }
                return false;
            }

            static bool GetAllComponentIdsByDeviceInterfaces(ppp::unordered_set<ppp::string>& componentIds) noexcept
            {
                HDEVINFO devInfoSet = SetupDiGetClassDevs(NULLPTR, /*_T("Net")*/NULLPTR, NULLPTR, DIGCF_ALLCLASSES | DIGCF_PRESENT);
                if (devInfoSet == INVALID_HANDLE_VALUE)
                {
                    return false;
                }

                for (DWORD index = 0;; index++)
                {
                    SP_DEVINFO_DATA devInfoData;
                    devInfoData.cbSize = sizeof(devInfoData);
                    if (!SetupDiEnumDeviceInfo(devInfoSet, index, &devInfoData))
                    {
                        break;
                    }

                    DWORD requiredSize;
                    TCHAR deviceInstanceId[LINE_LEN];
                    BOOL b = SetupDiGetDeviceInstanceId(devInfoSet, &devInfoData, deviceInstanceId, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        continue;
                    }

                    TCHAR classGuid[LINE_LEN];
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_CLASSGUID, NULLPTR, (PBYTE)classGuid, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        continue;
                    }

                    if (_tcsicmp(classGuid, _T("{4d36e972-e325-11ce-bfc1-08002be10318}")) != 0)
                    {
                        continue;
                    }

                    TCHAR hardwareId[LINE_LEN];
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_HARDWAREID, NULLPTR, (PBYTE)hardwareId, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_SERVICE, NULLPTR, (PBYTE)hardwareId, LINE_LEN, &requiredSize);
                        if (!b)
                        {
                            continue;
                        }
                    }

                    if (_tcsicmp(hardwareId, _T("tap0901")) != 0)
                    {
                        continue;
                    }

                    TCHAR driver[LINE_LEN];
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_DRIVER, NULLPTR, (PBYTE)driver, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        continue;
                    }
                    else
                    {
                        TCHAR* networkIndex = tcschr(driver, '\\');
                        if (NULLPTR == networkIndex)
                        {
                            continue;
                        }

                        NetworkInterfacePtr network_interface = GetNetworkInterfaceByIndex(ttoll(++networkIndex));
                        if (NULLPTR == network_interface)
                        {
                            continue;
                        }
                        else
                        {
                            componentIds.emplace(network_interface->Guid);
                        }
                    }
                }

                SetupDiDestroyDeviceInfoList(devInfoSet);
                return true;
            }

            /* https://devops-collective-inc.gitbook.io/windows-powershell-networking-guide/renaming-the-network-adapter */
            static bool RenameAdapterByIndexWMI(DWORD dwIndex, LPCWSTR lpNewName) noexcept
            {
                IWbemLocator* pLoc = NULLPTR;
                HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
                if (FAILED(hr))
                {
                    return false;
                }

                IWbemServices* pSvc = NULLPTR;
                hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULLPTR, NULLPTR, 0, NULL, 0, 0, &pSvc);
                if (FAILED(hr))
                {
                    pLoc->Release();
                    return false;
                }

                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULLPTR, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULLPTR, EOAC_NONE);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                WCHAR wszQuery[512];
                swprintf_s(wszQuery, _countof(wszQuery), L"SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex='%u'", dwIndex);

                IEnumWbemClassObject* pEnumerator = NULLPTR;
                hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wszQuery), WBEM_FLAG_FORWARD_ONLY, NULLPTR, &pEnumerator);
                if (FAILED(hr) || NULLPTR == pEnumerator)
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                IWbemClassObject* pNetAdapter = NULLPTR;
                ULONG uReturned = 0;
                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pNetAdapter, &uReturned);
                if (FAILED(hr) || NULLPTR == pNetAdapter || uReturned == 0)
                {
                    pEnumerator->Release();
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                VARIANT vtName;
                memset(&vtName, 0, sizeof(vtName));

                WCHAR* pName = _wcsdup(lpNewName);
                vtName.vt = VT_BSTR;
                vtName.bstrVal = SysAllocString(pName);
                if (NULLPTR != pName)
                {
                    free(pName);
                }

                hr = pNetAdapter->Put(L"NetConnectionID", 0, &vtName, CIM_STRING);
                if (FAILED(hr))
                {
                    VariantClear(&vtName);
                    pEnumerator->Release();
                    pNetAdapter->Release();
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                hr = pSvc->PutInstance(pNetAdapter, WBEM_FLAG_UPDATE_ONLY, NULLPTR, NULLPTR);
                if (FAILED(hr))
                {
                    VariantClear(&vtName);
                    pEnumerator->Release();
                    pNetAdapter->Release();
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                VariantClear(&vtName);
                pEnumerator->Release();
                pNetAdapter->Release();
                pSvc->Release();
                pLoc->Release();
                return true;
            }

            NetworkInterfacePtr GetNetworkInterfaceByIndex(int index) noexcept
            {
                return GetAllNetworkInterfacesInternal(false, index);
            }

            NetworkInterfacePtr GetNetworkInterfaceByInterfaceIndex(int interface_index) noexcept
            {
                return GetAllNetworkInterfacesInternal(true, interface_index);
            }

            bool GetAllNetworkInterfaces(ppp::vector<NetworkInterfacePtr>& interfaces) noexcept
            {
                interfaces.clear();

                if (!GetAllNetworkInterfacesInternal(false, -1, interfaces))
                {
                    return false;
                }

                ppp::map<int, MOF_Win32_NetworkAdapter> network_adapters;
                GetAdapterNameByIndexWMI(-1, network_adapters);

                for (NetworkInterfacePtr ni : interfaces)
                {
                    auto tail = network_adapters.find(ni->InterfaceIndex);
                    auto endl = network_adapters.end();
                    if (tail != endl)
                    {
                        auto& na = tail->second;
                        ni->ConnectionId = na.NetConnectionID;
                    }
                }
                return true;
            }

            bool SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& servers) noexcept
            {
                return SetNetifAddressesInternal(interface_index,
                    [&servers](IWbemServices* pSvc, IWbemClassObject* pclsObj) noexcept
                    {
                        return SetDnsAddressesInternal(pSvc, pclsObj, servers);
                    });
            }

            bool SetDefaultIPGateway(int interface_index, const ppp::vector<boost::asio::ip::address>& servers) noexcept
            {
                ppp::vector<ppp::string> addresses;
                for (const boost::asio::ip::address& ip : servers)
                {
                    if (ip.is_v4() || ip.is_v6())
                    {
                        if (ppp::net::IPEndPoint::IsInvalid(ip))
                        {
                            continue;
                        }

                        std::string ips = ip.to_string();
                        if (ips.empty())
                        {
                            continue;
                        }

                        addresses.emplace_back(ppp::string(ips.data(), ips.size()));
                    }
                }

                if (addresses.empty())
                {
                    addresses.emplace_back("0.0.0.0");
                }

                return SetDefaultIPGateway(interface_index, addresses);
            }

            bool SetDefaultIPGateway(int interface_index, const ppp::vector<ppp::string>& servers) noexcept
            {
                return SetNetifAddressesInternal(interface_index,
                    [&servers](IWbemServices* pSvc, IWbemClassObject* pclsObj) noexcept
                    {
                        return SetDefaultIPGatewayInternal(pSvc, pclsObj, servers);
                    });
            }

            bool SetIPAddresses(int interface_index, const ppp::vector<ppp::string>& ips, const ppp::vector<ppp::string>& masks) noexcept
            {
                return SetNetifAddressesInternal(interface_index,
                    [&ips, &masks](IWbemServices* pSvc, IWbemClassObject* pclsObj) noexcept
                    {
                        return SetNetifIPAddressInternal(pSvc, pclsObj, ips, masks);
                    });
            }

            bool DhcpEnabled(int interface_index) noexcept
            {
                return SetNetifAddressesInternal(interface_index,
                    [](IWbemServices* pSvc, IWbemClassObject* pclsObj) noexcept
                    {
                        return DhcpEnabledInternal(pSvc, pclsObj);
                    });
            }

            bool CaptureDnsSnapshot(int interface_index, NetworkDnsSnapshot& snapshot) noexcept
            {
                snapshot = NetworkDnsSnapshot();
                NetworkInterfacePtr current = GetNetworkInterfaceByInterfaceIndex(interface_index);
                if (!current || current->InterfaceIndex < 0 || current->Guid.empty())
                {
                    return false;
                }

                snapshot.InterfaceIndex = current->InterfaceIndex;
                snapshot.InterfaceLuid = current->InterfaceLuid;
                snapshot.Guid = current->Guid;
                if (!GetDnsAutomaticByGuid(snapshot.Guid, snapshot.DnsAutomatic))
                {
                    return false;
                }
                for (const ppp::string& value : current->DnsAddresses)
                {
                    boost::system::error_code ec;
                    const boost::asio::ip::address address = StringToAddress(value.data(), ec);
                    if (!ec && !address.is_unspecified() && !address.is_multicast() &&
                        !ppp::net::IPEndPoint::IsInvalid(address))
                    {
                        snapshot.DnsAddresses.emplace_back(address);
                    }
                }
                return true;
            }

            bool SetDnsAddressesWithSnapshot(int interface_index, const ppp::vector<ppp::string>& servers, NetworkDnsSnapshot& snapshot) noexcept
            {
                // Capture before the write.  This deliberately leaves a
                // populated snapshot behind when WMI rejects the write, so
                // teardown can still retry the original state.
                if (snapshot.InterfaceIndex < 0 || snapshot.Guid.empty()) {
                    if (!CaptureDnsSnapshot(interface_index, snapshot)) {
                        return false;
                    }
                } else if (snapshot.InterfaceIndex != interface_index) {
                    return false;
                }

                // Revalidate the stable adapter identity immediately before
                // the WMI mutation.  InterfaceIndex values can be reused
                // between capture and apply; writing by index alone could
                // otherwise alter an unrelated replacement adapter.
                NetworkInterfacePtr current =
                    GetNetworkInterfaceByInterfaceIndex(interface_index);
                if (!current || current->Guid.empty() ||
                    _stricmp(current->Guid.data(), snapshot.Guid.data()) != 0 ||
                    (!snapshot.InterfaceLuid.empty() &&
                     (current->InterfaceLuid.empty() ||
                      current->InterfaceLuid != snapshot.InterfaceLuid)))
                {
                    return false;
                }

                snapshot.AppliedDnsAddresses.clear();
                snapshot.AppliedDnsAddresses.reserve(servers.size());
                for (const ppp::string& value : servers)
                {
                    boost::system::error_code ec;
                    const boost::asio::ip::address address = StringToAddress(value.data(), ec);
                    if (!ec && !address.is_unspecified() && !address.is_multicast() &&
                        !ppp::net::IPEndPoint::IsInvalid(address))
                    {
                        snapshot.AppliedDnsAddresses.emplace_back(address);
                    }
                }
                snapshot.DnsApplyAttempted = true;
                snapshot.DnsApplied = SetDnsAddresses(interface_index, servers);
                return snapshot.DnsApplied;
            }

            bool RestoreDnsSnapshot(const NetworkDnsSnapshot& snapshot) noexcept
            {
                if (snapshot.InterfaceIndex < 0 || snapshot.Guid.empty())
                {
                    return false;
                }

                // Interface indexes are reusable. Require the stable WMI GUID
                // and, when available, the kernel LUID to still match before
                // changing any adapter state.
                NetworkInterfacePtr current = GetNetworkInterfaceByInterfaceIndex(snapshot.InterfaceIndex);
                if (!current || current->Guid.empty() ||
                    _stricmp(current->Guid.data(), snapshot.Guid.data()) != 0)
                {
                    return false;
                }
                if (!snapshot.InterfaceLuid.empty() &&
                    (current->InterfaceLuid.empty() || current->InterfaceLuid != snapshot.InterfaceLuid))
                {
                    return false;
                }

                ppp::vector<boost::asio::ip::address> current_dns;
                for (const ppp::string& value : current->DnsAddresses)
                {
                    boost::system::error_code ec;
                    const boost::asio::ip::address address = StringToAddress(value.data(), ec);
                    if (!ec && !address.is_unspecified() && !address.is_multicast() &&
                        !ppp::net::IPEndPoint::IsInvalid(address))
                    {
                        current_dns.emplace_back(address);
                    }
                }

                // The resolver list alone does not identify the Windows DNS
                // mode.  A static NameServer value and an automatic/DHCP
                // configuration can expose the same servers, so keep the
                // registry mode in the ownership comparison as well.
                bool current_automatic = false;
                if (!GetDnsAutomaticByGuid(current->Guid, current_automatic))
                {
                    return false;
                }

                // Compare-and-restore: after OpenPPP2 has written DNS, only
                // restore if the current values still match what it wrote.
                // If WMI reported failure, accept an unchanged original value
                // or a value that was applied despite the error; any other
                // value belongs to another actor and must remain untouched.
                if (snapshot.DnsApplyAttempted)
                {
                    // DHCP can refresh resolver addresses while the VPN is
                    // active.  When the captured state was automatic and the
                    // adapter is automatic again, there is no OpenPPP2
                    // static ownership left to restore, even if the server
                    // list changed naturally.
                    if (snapshot.DnsAutomatic && current_automatic)
                    {
                        return true;
                    }
                    if (current_dns == snapshot.DnsAddresses &&
                        current_automatic == snapshot.DnsAutomatic)
                    {
                        return true;
                    }
                    if (current_dns != snapshot.AppliedDnsAddresses)
                    {
                        return false;
                    }
                    // SetDnsAddresses writes a static resolver list.  An
                    // automatic mode with the same values belongs to a
                    // different actor and must not be overwritten.
                    if (current_automatic && !snapshot.AppliedDnsAddresses.empty())
                    {
                        return false;
                    }
                }

                ppp::vector<ppp::string> servers;
                servers.reserve(snapshot.DnsAddresses.size());
                for (const boost::asio::ip::address& address : snapshot.DnsAddresses)
                {
                    if (!address.is_unspecified() && !address.is_multicast() &&
                        !ppp::net::IPEndPoint::IsInvalid(address))
                    {
                        servers.emplace_back(address.to_string());
                    }
                }
                // Passing an empty list clears NameServer and returns DNS
                // ownership to the automatic/DHCP source. Static snapshots
                // restore the exact captured server list.
                if (snapshot.DnsAutomatic)
                {
                    servers.clear();
                }
                if (!SetDnsAddresses(snapshot.InterfaceIndex, servers))
                {
                    return false;
                }

                // WMI can report success before a provider has committed the
                // requested values, and it can also partially apply a write.
                // Re-read both the adapter and registry mode before allowing
                // callers to remove the durable recovery record.
                NetworkInterfacePtr restored =
                    GetNetworkInterfaceByInterfaceIndex(snapshot.InterfaceIndex);
                if (!restored || restored->Guid.empty() ||
                    _stricmp(restored->Guid.data(), snapshot.Guid.data()) != 0 ||
                    (!snapshot.InterfaceLuid.empty() &&
                     (restored->InterfaceLuid.empty() ||
                      restored->InterfaceLuid != snapshot.InterfaceLuid)))
                {
                    return false;
                }

                bool restored_automatic = false;
                if (!GetDnsAutomaticByGuid(restored->Guid, restored_automatic) ||
                    restored_automatic != snapshot.DnsAutomatic)
                {
                    return false;
                }

                if (snapshot.DnsAutomatic)
                {
                    // DHCP-provided resolver addresses may legitimately
                    // change while the VPN is down; mode restoration is the
                    // stable invariant for an automatic snapshot.
                    return true;
                }

                ppp::vector<boost::asio::ip::address> restored_dns;
                for (const ppp::string& value : restored->DnsAddresses)
                {
                    boost::system::error_code ec;
                    const boost::asio::ip::address address = StringToAddress(value.data(), ec);
                    if (!ec && !address.is_unspecified() && !address.is_multicast() &&
                        !ppp::net::IPEndPoint::IsInvalid(address))
                    {
                        restored_dns.emplace_back(address);
                    }
                }
                return restored_dns == snapshot.DnsAddresses;
            }

            bool GetAllComponentIds(ppp::unordered_set<ppp::string>& componentIds) noexcept
            {
                if (!GetAllComponentIdsByRegistryEdit(componentIds))
                {
                    if (!GetAllComponentIdsByDeviceInterfaces(componentIds))
                    {
                        return false;
                    }
                }
                return true;
            }

            OperationalStatus GetOperationalStatus(int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return OperationalStatus_Unknown;
                }

                MIB_IFROW m;
                m.dwIndex = interface_index;

                DWORD err = GetIfEntry(&m);
                if (err == ERROR_SUCCESS)
                {
                    if (m.dwOperStatus == IF_OPER_STATUS_OPERATIONAL)
                    {
                        return OperationalStatus_Up;
                    }
                    return OperationalStatus_Down;
                }
                return OperationalStatus_Unknown;
            }

            int GetIfIndexByFriendlyName(const std::wstring& adapter_name) noexcept
            {
                if (adapter_name.empty())
                {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkInterfaceGetIfIndexEmptyFriendlyName);
                }

                ULONG dwSize = 0;
                DWORD dwRetVal = ERROR_BUFFER_OVERFLOW;
                PIP_ADAPTER_ADDRESSES pAddresses = NULL;
                PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

                // The adapter list can grow between the size probe and the fetch,
                // so retry a bounded number of times on ERROR_BUFFER_OVERFLOW.
                for (int attempt = 0; attempt < 5 && dwRetVal == ERROR_BUFFER_OVERFLOW; attempt++)
                {
                    if (pAddresses != NULL)
                    {
                        free(pAddresses);
                        pAddresses = NULL;
                    }

                    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &dwSize);
                    if (dwRetVal != ERROR_BUFFER_OVERFLOW)
                    {
                        break;
                    }

                    pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(dwSize);
                    if (pAddresses == NULL)
                    {
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                            "windows_network", "GetIfIndexByFriendlyName memory allocation failed");
                        return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &dwSize);
                }

                if (dwRetVal != NO_ERROR)
                {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                        "windows_network", "GetAdaptersAddresses failed: win32_error=%lu",
                        static_cast<unsigned long>(dwRetVal));
                    if (pAddresses != NULL)
                    {
                        free(pAddresses);
                    }
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                DWORD ifIndex = -1;
                pCurrAddresses = pAddresses;

                while (pCurrAddresses)
                {
                    if (pCurrAddresses->FriendlyName && adapter_name == pCurrAddresses->FriendlyName)
                    {
                        ifIndex = pCurrAddresses->IfIndex;
                        break;
                    }

                    pCurrAddresses = pCurrAddresses->Next;
                }

                free(pAddresses);
                return ifIndex;
            }

            bool GetAllAdapterInterfaces(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept
            {
                ULONG structSize = sizeof(IP_ADAPTER_INFO);
                std::shared_ptr<IP_ADAPTER_INFO> pArray = std::shared_ptr<IP_ADAPTER_INFO>((IP_ADAPTER_INFO*)Malloc(structSize),
                    [](IP_ADAPTER_INFO* p) noexcept
                    {
                        Mfree(p);
                    });

                int err = GetAdaptersInfo(pArray.get(), &structSize);
                if (err == ERROR_BUFFER_OVERFLOW) // ERROR_BUFFER_OVERFLOW == 111
                {
                    // Buffer was too small, reallocate the correct size for the buffer.
                    pArray = std::shared_ptr<IP_ADAPTER_INFO>((IP_ADAPTER_INFO*)Malloc(structSize),
                        [](IP_ADAPTER_INFO* p) noexcept
                        {
                            Mfree(p);
                        });

                    err = GetAdaptersInfo(pArray.get(), &structSize);
                } // if

                ppp::string any = "0.0.0.0";
                if (err == ERROR_SUCCESS)
                {
                    // Call Succeeded
                    IP_ADAPTER_INFO* pEntry = pArray.get();
                    do
                    {
                        // Retrieve the adapter info from the memory address
                        IP_ADAPTER_INFO& entry = *pEntry;
                        AdapterInterfacePtr interfacex = make_shared_object<AdapterInterface>();
                        if (NULLPTR != interfacex)
                        {
                            interfacex->Id = entry.AdapterName;
                            interfacex->IfIndex = entry.Index;
                            interfacex->Name = entry.Description;
                            interfacex->Address = entry.IpAddressList.IpAddress.String;
                            interfacex->Mask = entry.IpAddressList.IpMask.String;
                            interfacex->GatewayServer = entry.GatewayList.IpAddress.String;
                            interfacex->IfType = entry.Type;
                            interfacex->Status = GetOperationalStatus(entry.Index);
                            interfacex->MacAddress = ppp::net::native::eth_addr::BytesToMacAddress(entry.Address, (int)entry.AddressLength);

                            interfaces.emplace_back(interfacex);
                            if (entry.DhcpEnabled != 0)
                            {
                                interfacex->DhcpServer = entry.DhcpServer.IpAddress.String;
                            }

                            if (entry.HaveWins)
                            {
                                interfacex->PrimaryWinsServer = entry.PrimaryWinsServer.IpAddress.String;
                                interfacex->SecondaryWinsServer = entry.SecondaryWinsServer.IpAddress.String;
                            }

                            if (interfacex->Address.empty()) interfacex->Address = any;
                            if (interfacex->Mask.empty()) interfacex->Mask = any;
                            if (interfacex->GatewayServer.empty()) interfacex->GatewayServer = any;
                            if (interfacex->DhcpServer.empty()) interfacex->DhcpServer = any;
                            if (interfacex->PrimaryWinsServer.empty()) interfacex->PrimaryWinsServer = any;
                            if (interfacex->SecondaryWinsServer.empty()) interfacex->SecondaryWinsServer = any;
                        }

                        // Get next adapter (if any)
                        pEntry = entry.Next;
                    } while (NULLPTR != pEntry);
                }
                return err == ERROR_SUCCESS;
            }

            bool GetAllAdapterInterfaces2(ppp::vector<AdapterInterfacePtr>& interfaces) noexcept
            {
                ppp::vector<AdapterInterfacePtr> ais;
                if (!GetAllAdapterInterfaces(ais))
                {
                    return false;
                }

                static LPCSTR filters[] =
                {
                    "VMWARE",
                    "VIRTUAL PORT", /* VIRTUALBOX, VIRTUAL PORT */
                    "VIRTIO",
                    "TAP", /* TAP-WINDOWS */
                    "TUN",
                    "VPN",
                    "VNIC",
                    "PCAP",
                    "LIEBAO",
                    "MICROSOFT LOOPBACK",
                    "MICROSOFT KM-TEST",
                    "MICROSOFT WI-FI DIRECT",
                    "WAN MINIPORT(PPTP)",
                    "WAN MINIPORT(L2TP)",
                    "WAN MINIPORT(SSTP)",
                    "WAN MINIPORT(IKEV2)",
                    "WAN MINIPORT(IPSEC)",
                    "TEREDO TUNNELING PSEUDO-INTERFACE"
                };

                for (AdapterInterfacePtr ai : ais)
                {
                    ppp::string description = ppp::ToUpper(ai->Name);
                    if (description.empty())
                    {
                        continue;
                    }

                    bool f = false;
                    for (int i = 0; i < arraysizeof(filters); i++)
                    {
                        if (description.find(filters[i]) != ppp::string::npos)
                        {
                            f = true;
                            break;
                        }
                    }

                    if (f)
                    {
                        continue;
                    }

                    interfaces.emplace_back(ai);
                }
                return true;
            }

            AdapterInterfacePtr GetNetworkInterfaceByIndex2(int interface_index) noexcept
            {
                ppp::vector<AdapterInterfacePtr> ais;
                if (!GetAllAdapterInterfaces(ais))
                {
                    return NULLPTR;
                }

                for (AdapterInterfacePtr ai : ais)
                {
                    if (ai->IfIndex == interface_index)
                    {
                        return ai;
                    }
                }
                return NULLPTR;
            }

            std::shared_ptr<MIB_IFTABLE> GetIfTable() noexcept
            {
                DWORD dwSize = 0;
                if (::GetIfTable(NULLPTR, &dwSize, FALSE) != ERROR_INSUFFICIENT_BUFFER)
                {
                    return NULLPTR;
                }

                std::shared_ptr<MIB_IFTABLE> pIfTable = std::shared_ptr<MIB_IFTABLE>((MIB_IFTABLE*)Malloc(dwSize),
                    [](MIB_IFTABLE* p) noexcept
                    {
                        Mfree(p);
                    });
                if (pIfTable == NULLPTR)
                {
                    return NULLPTR;
                }

                if (::GetIfTable(pIfTable.get(), &dwSize, FALSE) != NO_ERROR)
                {
                    return NULLPTR;
                }

                return pIfTable;
            }

            std::shared_ptr<MIB_IFROW> GetIfEntry(int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return NULLPTR;
                }

                std::shared_ptr<MIB_IFROW> pIfRow = std::shared_ptr<MIB_IFROW>((MIB_IFROW*)Malloc(sizeof(MIB_IFROW)),
                    [](MIB_IFROW* p) noexcept
                    {
                        Mfree(p);
                    });
                if (NULLPTR == pIfRow)
                {
                    return NULLPTR;
                }

                pIfRow->dwIndex = interface_index;
                if (::GetIfEntry(pIfRow.get()) != NO_ERROR)
                {
                    return NULLPTR;
                }

                return pIfRow;
            }

            OperationalStatus GetOperationalStatus(INTERNAL_IF_OPER_STATUS status) noexcept
            {
                if (status == IF_OPER_STATUS_CONNECTING ||
                    status == IF_OPER_STATUS_CONNECTED ||
                    status == IF_OPER_STATUS_OPERATIONAL)
                {
                    return OperationalStatus_Up;
                }

                if (status == IF_OPER_STATUS_NON_OPERATIONAL ||
                    status == IF_OPER_STATUS_UNREACHABLE ||
                    status == IF_OPER_STATUS_DISCONNECTED)
                {
                    return OperationalStatus_Down;
                }

                return OperationalStatus_Unknown;
            }

            bool SetInterfaceName(int interface_index, const ppp::string& interface_name) noexcept
            {
                if (interface_index < 0 || interface_name.empty())
                {
                    return false;
                }

                _bstr_t bstr_interface_name = interface_name.data();
                return RenameAdapterByIndexWMI(interface_index, bstr_interface_name.GetBSTR());
            }

            ppp::string GetInterfaceName(int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return ppp::string();
                }

                ppp::map<int, MOF_Win32_NetworkAdapter> network_adapters;
                return GetAdapterNameByIndexWMI(interface_index, network_adapters);
            }

            bool SetIPAddresses(const ppp::string& interface_name, const ppp::string& ip, const ppp::string& mask) noexcept
            {
                if (interface_name.empty() || ip.empty() || mask.empty())
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceSetIpAddressesInvalidArguments);
                }

                PROCESS_INFORMATION pi;
                ZeroMemory(&pi, sizeof(pi));

                STARTUPINFOA si;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);

                char command[1000];
                snprintf(command, sizeof(command), "netsh interface ipv4 set address name=\"%s\" static %s %s", interface_name.data(), ip.data(), mask.data());

                if (!CreateProcessA(NULLPTR, command,
                    NULLPTR, NULLPTR, FALSE, CREATE_NO_WINDOW, NULLPTR, NULLPTR, &si, &pi))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }

                DWORD dwExitCode = INFINITE;
                if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0)
                {
                    if (!GetExitCodeProcess(pi.hProcess, &dwExitCode))
                    {
                        dwExitCode = INFINITE;
                    }
                }
                else
                {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                if (dwExitCode != ERROR_SUCCESS)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }

                return true;
            }

            static bool ExecuteNetshCommand(const ppp::string& command_line, ppp::diagnostics::ErrorCode error_code, bool publish_error) noexcept {
                if (command_line.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceExecuteNetshCommandEmpty);
                }

                PROCESS_INFORMATION pi;
                ZeroMemory(&pi, sizeof(pi));

                STARTUPINFOA si;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);

                char command[1200];
                strncpy(command, command_line.data(), sizeof(command) - 1);
                command[sizeof(command) - 1] = '\0';

                if (!CreateProcessA(NULLPTR, command, NULLPTR, NULLPTR, FALSE, CREATE_NO_WINDOW, NULLPTR, NULLPTR, &si, &pi)) {
                    if (publish_error) {
                        return ppp::diagnostics::SetLastError(error_code);
                    }
                    return false;
                }

                DWORD dwExitCode = INFINITE;
                if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0) {
                    if (!GetExitCodeProcess(pi.hProcess, &dwExitCode)) {
                        dwExitCode = INFINITE;
                    }
                }
                else {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    if (publish_error) {
                        return ppp::diagnostics::SetLastError(error_code);
                    }
                    return false;
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                if (dwExitCode != ERROR_SUCCESS) {
                    if (publish_error) {
                        return ppp::diagnostics::SetLastError(error_code);
                    }
                    return false;
                }

                return true;
            }

            static bool ExecuteNetshCommand(const ppp::string& command_line) noexcept {
                return ExecuteNetshCommand(command_line, ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed, true);
            }

            static bool IsSafeNetshInterfaceName(const ppp::string& value) noexcept {
                if (value.empty()) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ' ' || ch == '_' || ch == '-' || ch == '.' || ch == ':' || ch == '(' || ch == ')' || ch == '[' || ch == ']';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            static bool IsSafeNetshToken(const ppp::string& value) noexcept {
                if (value.empty()) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            bool SetIPv6Address(int interface_index, const ppp::string& ip, int prefix_length) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                if (!IsSafeNetshToken(ip)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                }

                char command[1200];
                snprintf(command, sizeof(command), "netsh interface ipv6 set address interface=\"%s\" address=%s/%d store=active", interface_name.data(), ip.data(), prefix_length);
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed, true);
            }

            bool DeleteIPv6Address(int interface_index, const ppp::string& ip) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                if (!IsSafeNetshToken(ip)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                }

                char command[1200];
                snprintf(command, sizeof(command), "netsh interface ipv6 delete address interface=\"%s\" address=%s", interface_name.data(), ip.data());
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed, true);
            }

            bool SetIPv6DefaultRoute(int interface_index, int metric) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                char command[1200];
                snprintf(command, sizeof(command), "netsh interface ipv6 add route ::/0 interface=\"%s\" metric=%d store=active", interface_name.data(), std::max<int>(1, metric));
                if (ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false)) {
                    return true;
                }

                char cleanup_command[1200];
                snprintf(cleanup_command, sizeof(cleanup_command), "netsh interface ipv6 delete route prefix=::/0 interface=\"%s\" store=active", interface_name.data());
                ExecuteNetshCommand(cleanup_command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false);
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, true);
            }

            bool SetIPv6DefaultGateway(int interface_index, const ppp::string& gateway, int metric) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                if (!IsSafeNetshToken(gateway)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayInvalid);
                }

                char command[1200];
                snprintf(command, sizeof(command), "netsh interface ipv6 add route ::/0 interface=\"%s\" nexthop=%s metric=%d store=active", interface_name.data(), gateway.data(), std::max<int>(1, metric));
                if (ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false)) {
                    return true;
                }

                char cleanup_command[1200];
                snprintf(cleanup_command, sizeof(cleanup_command), "netsh interface ipv6 delete route prefix=::/0 interface=\"%s\" nexthop=%s store=active", interface_name.data(), gateway.data());
                ExecuteNetshCommand(cleanup_command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false);
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, true);
            }

            bool DeleteIPv6DefaultGateway(int interface_index, const ppp::string& gateway) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                if (!gateway.empty() && !IsSafeNetshToken(gateway)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayInvalid);
                }

                char command[1200];
                if (gateway.empty()) {
                    snprintf(command, sizeof(command), "netsh interface ipv6 delete route prefix=::/0 interface=\"%s\" store=active", interface_name.data());
                }
                else {
                    snprintf(command, sizeof(command), "netsh interface ipv6 delete route prefix=::/0 interface=\"%s\" nexthop=%s store=active", interface_name.data(), gateway.data());
                }
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, true);
            }

            bool AddIPv6Route(int interface_index, const ppp::string& prefix, int prefix_length, const ppp::string& gateway, int metric) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                if (!IsSafeNetshToken(prefix)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
                }
                if (!gateway.empty() && !IsSafeNetshToken(gateway)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayInvalid);
                }

                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                char command[1200];
                if (gateway.empty()) {
                    snprintf(command, sizeof(command), "netsh interface ipv6 add route %s/%d interface=\"%s\" metric=%d store=active", prefix.data(), prefix_length, interface_name.data(), std::max<int>(1, metric));
                }
                else {
                    snprintf(command, sizeof(command), "netsh interface ipv6 add route %s/%d interface=\"%s\" nexthop=%s metric=%d store=active", prefix.data(), prefix_length, interface_name.data(), gateway.data(), std::max<int>(1, metric));
                }

                if (ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false)) {
                    return true;
                }

                char cleanup_command[1200];
                if (gateway.empty()) {
                    snprintf(cleanup_command, sizeof(cleanup_command), "netsh interface ipv6 delete route prefix=%s/%d interface=\"%s\" store=active", prefix.data(), prefix_length, interface_name.data());
                }
                else {
                    snprintf(cleanup_command, sizeof(cleanup_command), "netsh interface ipv6 delete route prefix=%s/%d interface=\"%s\" nexthop=%s store=active", prefix.data(), prefix_length, interface_name.data(), gateway.data());
                }

                ExecuteNetshCommand(cleanup_command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, false);
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, true);
            }

            bool DeleteIPv6Route(int interface_index, const ppp::string& prefix, int prefix_length, const ppp::string& gateway) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                if (!IsSafeNetshToken(prefix)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
                }
                if (!gateway.empty() && !IsSafeNetshToken(gateway)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayInvalid);
                }

                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                char command[1200];
                if (gateway.empty()) {
                    snprintf(command, sizeof(command), "netsh interface ipv6 delete route prefix=%s/%d interface=\"%s\" store=active", prefix.data(), prefix_length, interface_name.data());
                }
                else {
                    snprintf(command, sizeof(command), "netsh interface ipv6 delete route prefix=%s/%d interface=\"%s\" nexthop=%s store=active", prefix.data(), prefix_length, interface_name.data(), gateway.data());
                }
                return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed, true);
            }

            bool SetDnsAddressesV6(int interface_index, const ppp::vector<ppp::string>& servers) noexcept {
                ppp::string interface_name = GetInterfaceName(interface_index);
                if (!IsSafeNetshInterfaceName(interface_name)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                if (servers.empty()) {
                    char command[1200];
                    snprintf(command, sizeof(command), "netsh interface ipv6 delete dnsservers name=\"%s\" all validate=no", interface_name.data());
                    return ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed, false);
                }

                bool any = false;
                bool all = true;
                int index = 1;
                for (const ppp::string& server : servers) {
                    if (server.empty()) {
                        continue;
                    }
                    if (!IsSafeNetshToken(server)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                    }

                    char command[1200];
                    if (index == 1) {
                        snprintf(command, sizeof(command), "netsh interface ipv6 set dnsservers name=\"%s\" static %s primary validate=no", interface_name.data(), server.data());
                    }
                    else {
                        snprintf(command, sizeof(command), "netsh interface ipv6 add dnsservers name=\"%s\" %s index=%d validate=no", interface_name.data(), server.data(), index);
                    }

                    bool ok = ExecuteNetshCommand(command, ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed, false);
                    any |= ok;
                    all &= ok;
                    index++;
                }

                if (!(any && all)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                }

                return true;
            }

            static bool FixGatewayServerAddress(const ppp::win32::network::AdapterInterfacePtr& ai) noexcept
            {
                boost::system::error_code ec;
                boost::asio::ip::address nx = StringToAddress(ai->GatewayServer.data(), ec);
                if (ec == boost::system::errc::success)
                {
                    bool b = nx.is_loopback() || nx.is_multicast() || nx.is_unspecified() || ppp::net::IPEndPoint::IsInvalid(nx);
                    if (!b)
                    {
                        return true;
                    }
                }

                boost::asio::ip::address ip = StringToAddress(ai->Address.data(), ec);
                if (ec)
                {
                    return false;
                }

                boost::asio::ip::address mask = StringToAddress(ai->Mask.data(), ec);
                if (ec)
                {
                    return false;
                }

                boost::asio::ip::address gw = ppp::net::Ipep::FixedIPAddress(ip, mask);
                if (gw.is_loopback() || gw.is_multicast() || gw.is_unspecified() || ppp::net::IPEndPoint::IsInvalid(gw))
                {
                    return false;
                }

                ai->GatewayServer = gw.to_string();
                return true;
            }

            static ppp::win32::network::AdapterInterfacePtr SelectBaseNetowrkInterface(std::vector<ppp::win32::network::AdapterInterfacePtr>& adapters, bool fix) noexcept
            {
                // Try to fix the gateway IP address first. choose an ok network.
                if (fix)
                {
                    for (auto&& ai : adapters)
                    {
                        if (FixGatewayServerAddress(ai))
                        {
                            return ai;
                        }
                    }
                }
                else
                {
                    // If one of the current IN4 networks has a direct choice of default gateway servers!
                    for (auto&& ai : adapters)
                    {
                        boost::system::error_code ec;
                        boost::asio::ip::address gw = StringToAddress(ai->GatewayServer.data(), ec);
                        if (ec)
                        {
                            continue;
                        }

                        if (gw.is_unspecified())
                        {
                            continue;
                        }

                        return ai;
                    }
                }
                return NULLPTR;
            }

            int GetNetworkInterfaceIndexByDefaultRoute() noexcept
            {
                // Quickly test the default routing list for these IP addresses through the Windows operating system API.
                std::unordered_map<int, int> bests;
                for (const char* address_string : PPP_PUBLIC_DNS_SERVER_LIST)
                {
                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(address_string, ec);
                    if (ec)
                    {
                        continue;
                    }

                    if (address.is_multicast())
                    {
                        continue;
                    }

                    uint32_t ip = inet_addr(address_string);
                    if (ip == ppp::net::IPEndPoint::NoneAddress ||
                        ip == ppp::net::IPEndPoint::LoopbackAddress ||
                        ip == ppp::net::IPEndPoint::AnyAddress) 
                    {
                        continue;
                    }

                    int index = ppp::win32::network::Router::GetBestInterface(ip);
                    if (index != -1)
                    {
                        bests[index]++;
                    }
                }

                int preferred = -1;
                for (auto&& kv : bests)
                {
                    if (preferred == -1)
                    {
                        preferred = kv.first;
                        continue;
                    }

                    if (kv.second > bests[preferred])
                    {
                        preferred = kv.first;
                        continue;
                    }
                }

                if (preferred != -1)
                {
                    return preferred;
                }

                // Gets the default outgoing network routing information used by the current device operating system.
                std::shared_ptr<MIB_IPFORWARDTABLE> mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULLPTR == mib)
                {
                    return -1;
                }
                else
                {
                    for (uint32_t i = 0; i < mib->dwNumEntries; i++)
                    {
                        MIB_IPFORWARDROW& r = mib->table[i];
                        if (r.dwForwardDest == ppp::net::IPEndPoint::AnyAddress && r.dwForwardMask == ppp::net::IPEndPoint::AnyAddress)
                        {
                            return r.dwForwardIfIndex;
                        }
                    }
                }

                std::unordered_set<int> indexes;
                int left_index = -1;
                int reft_index = -1;
                uint32_t mid = inet_addr("128.0.0.0");

                for (uint32_t i = 0; i < mib->dwNumEntries; i++)
                {
                    MIB_IPFORWARDROW& r = mib->table[i];
                    if (r.dwForwardDest == ppp::net::IPEndPoint::AnyAddress && r.dwForwardMask == mid)
                    {
                        if (left_index == -1)
                        {
                            left_index = r.dwForwardIfIndex;
                        }

                        indexes.emplace(r.dwForwardIfIndex);
                    }
                    elif(r.dwForwardDest == mid && r.dwForwardMask == mid)
                    {
                        if (reft_index == -1)
                        {
                            reft_index = r.dwForwardIfIndex;
                        }

                        indexes.emplace(r.dwForwardIfIndex);
                    }

                    if (left_index != -1 && reft_index == left_index)
                    {
                        return left_index;
                    }
                }

                for (auto&& index : indexes)
                {
                    return index;
                }
                return -1;
            }

            std::pair<AdapterInterfacePtr, NetworkInterfacePtr> GetUnderlyingNetowrkInterface2(const ppp::string& id, const ppp::string& nic) noexcept
            {
                if (nic.size() > 0)
                {
                    ppp::vector<NetworkInterfacePtr> interfaces;
                    ppp::win32::network::GetAllNetworkInterfaces(interfaces);

                    ppp::string nic_lower = ToLower(ATrim(nic));
                    for (NetworkInterfacePtr& ni : interfaces)
                    {
                        if (ni->Status != OperationalStatus_Up)
                        {
                            continue;
                        }

                        ppp::string connection_id_lower = ni->ConnectionId;
                        if (connection_id_lower.empty())
                        {
                            continue;
                        }

                        connection_id_lower = ToLower(ATrim(connection_id_lower));
                        if (id.size() > 0)
                        {
                            boost::uuids::uuid left_id = StringToGuid(ni->Guid);
                            boost::uuids::uuid reft_id = StringToGuid(id);
                            if (left_id == reft_id)
                            {
                                continue;
                            }
                        }

                        if (connection_id_lower == nic)
                        {
                            AdapterInterfacePtr ai = GetNetworkInterfaceByIndex2(ni->InterfaceIndex);
                            if (NULLPTR != ai)
                            {
                                FixGatewayServerAddress(ai);
                            }
                            return { ai, ni };
                        }

                        std::size_t index = connection_id_lower.find(nic_lower);
                        if (index != std::string::npos)
                        {
                            AdapterInterfacePtr ai = GetNetworkInterfaceByIndex2(ni->InterfaceIndex);
                            if (NULLPTR != ai)
                            {
                                FixGatewayServerAddress(ai);
                            }
                            return { ai, ni };
                        }
                    }
                }

                AdapterInterfacePtr ai = GetUnderlyingNetworkInterface(id);
                if (NULLPTR == ai)
                {
                    return { NULLPTR, NULLPTR };
                }

                return { ai, ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex) };
            }

            AdapterInterfacePtr GetUnderlyingNetworkInterface(const ppp::string& id) noexcept
            {
                ppp::vector<ppp::win32::network::AdapterInterfacePtr> adapters;
                if (!ppp::win32::network::GetAllAdapterInterfaces2(adapters))
                {
                    return NULLPTR;
                }
                elif(int preferred_index = GetNetworkInterfaceIndexByDefaultRoute(); preferred_index != -1)
                {
                    for (auto&& ai : adapters)
                    {
                        if (ai->IfIndex == preferred_index && FixGatewayServerAddress(ai))
                        {
                            return ai;
                        }
                    }
                }

                // Invalid single dial address range.
                uint32_t invalidIPAddr = inet_addr("169.254.0.0");
                uint32_t invalidIPMask = inet_addr("255.255.0.0");

                // Get the underlying network interface of the current candidate!
                std::vector<ppp::win32::network::AdapterInterfacePtr> in4_optionals;
                std::vector<ppp::win32::network::AdapterInterfacePtr> in6_optionals;
                for (auto&& ai : adapters)
                {
                    // Search condition 1: The network card must be online.
                    if (ai->Status != ppp::win32::network::OperationalStatus_Up)
                    {
                        continue;
                    }

                    // Search condition 2: The NIC cannot be the NIC with the specified ID.
                    if (id.size() > 0)
                    {
                        boost::uuids::uuid left_id = StringToGuid(ai->Id);
                        boost::uuids::uuid reft_id = StringToGuid(id);
                        if (left_id == reft_id)
                        {
                            continue;
                        }
                    }

                    // Search condition 3: Determine that the IP, MASK, GW address obtained must be correctly converted to the IP address format.
                    boost::system::error_code ec;
                    boost::asio::ip::address gw = StringToAddress(ai->GatewayServer.data(), ec);
                    if (ec)
                    {
                        continue;
                    }

                    boost::asio::ip::address ip = StringToAddress(ai->Address.data(), ec);
                    if (ec)
                    {
                        continue;
                    }

                    boost::asio::ip::address mask = StringToAddress(ai->Mask.data(), ec);
                    if (ec)
                    {
                        continue;
                    }

                    // Search condition 4: IP address can not be broadcast address and IP, Mask address can not be any-cast?
                    if (mask.is_unspecified() || ip.is_unspecified() || ip.is_multicast() || ppp::net::IPEndPoint::IsInvalid(ip))
                    {
                        continue;
                    }

                    // Search condition 5: IP address cannot be a loopback IP address.
                    if (ip.is_loopback())
                    {
                        continue;
                    }

                    // Search condition 6: IP address can not be in the operating system default there is no network system itself given invalid single-dial address.
                    if (ip.is_v4())
                    {
                        uint32_t nip = ip.to_v4().to_uint();
                        nip &= invalidIPMask;
                        if (nip == invalidIPAddr)
                        {
                            continue;
                        }
                    }

                    // Put into the different optional host network card address segment candidates.
                    if (ip.is_v4() && mask.is_v4())
                    {
                        in4_optionals.emplace_back(ai);
                    }
                    elif(ip.is_v6() && mask.is_v6())
                    {
                        in6_optionals.emplace_back(ai);
                    }
                }

                // PPP from the beginning of the design is in v4 Ethernet switch virtual router, 
                // This is because V6 in modern society has a lot of limitations, 
                // Including resources are not good, so we design PPP only tend to IN4 network.
                ppp::win32::network::AdapterInterfacePtr ni = SelectBaseNetowrkInterface(in4_optionals, false);
                if (NULLPTR == ni) // Try to choose the best underlying hosting network interface!
                {
                    ni = SelectBaseNetowrkInterface(in6_optionals, false);
                    if (NULLPTR == ni)
                    {
                        ni = SelectBaseNetowrkInterface(in4_optionals, true);
                        if (NULLPTR == ni)
                        {
                            ni = SelectBaseNetowrkInterface(in6_optionals, true);
                            if (NULLPTR == ni)
                            {
                                return NULLPTR;
                            }
                        }
                    }
                }

                return ni;
            }

            bool AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept
            {
                if (NULLPTR == rib)
                {
                    return false;
                }

                bool any = false;
                for (auto&& [_, entries] : rib->GetAllRoutes())
                {
                    for (auto&& entry : entries)
                    {
                        uint32_t mask = ppp::net::IPEndPoint::PrefixToNetmask(entry.Prefix);
                        any |= ppp::win32::network::Router::Add(entry.Destination, mask, entry.NextHop, 1);
                    }
                }
                return any;
            }

            bool AddAllRoutes(ppp::vector<MIB_IPFORWARDROW>& routes) noexcept
            {
                bool any = false;
                for (MIB_IPFORWARDROW& r : routes)
                {
                    any |= ppp::win32::network::Router::Add(r);
                }
                return any;
            }

            bool DeleteAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept
            {
                if (NULLPTR == rib)
                {
                    return false;
                }

                auto mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULLPTR == mib)
                {
                    return false;
                }

                auto key = [](DWORD dwForwardDest, DWORD dwForwardMask, DWORD dwForwardNextHop) noexcept
                    {
                        return ((ppp::Int128)dwForwardDest) << 64 | ((ppp::Int128)dwForwardMask) << 32 | ((ppp::Int128)dwForwardNextHop);
                    };

                ppp::unordered_map<ppp::Int128, MIB_IPFORWARDROW> routes;
                for (DWORD dwNumEntries = 0; dwNumEntries < mib->dwNumEntries; dwNumEntries++)
                {
                    MIB_IPFORWARDROW& r = mib->table[dwNumEntries];
                    routes.emplace(key(r.dwForwardDest, r.dwForwardMask, r.dwForwardNextHop), r);
                }

                bool any = false;
                for (auto&& [_, entries] : rib->GetAllRoutes())
                {
                    for (auto&& entry : entries)
                    {
                        auto mask = ppp::net::IPEndPoint::PrefixToNetmask(entry.Prefix);
                        if (auto tail = routes.find(key(entry.Destination, mask, entry.NextHop)); tail != routes.end())
                        {
                            any |= ppp::win32::network::Router::Delete(tail->second);
                            routes.erase(tail);
                        }
                    }
                }
                return any;
            }

            bool DeleteAllDefaultGatewayRoutes(boost::asio::ip::address gw) noexcept
            {
                if (!gw.is_v4())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                auto mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULLPTR == mib)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteTableUnavailable);
                }

                // MIB_IPFORWARDROW stores IPv4 values in network byte order.  The
                // three entries cover the ordinary default route and the split
                // 0/1 + 128/1 takeover used by the client.
                const uint32_t half = inet_addr("128.0.0.0");
                const uint32_t gateway = htonl(gw.to_v4().to_uint());
                ppp::vector<MIB_IPFORWARDROW> owned;
                for (DWORD i = 0; i < mib->dwNumEntries; ++i)
                {
                    const MIB_IPFORWARDROW& route = mib->table[i];
                    const bool is_default =
                        (route.dwForwardDest == ppp::net::IPEndPoint::AnyAddress &&
                            (route.dwForwardMask == ppp::net::IPEndPoint::AnyAddress || route.dwForwardMask == half)) ||
                        (route.dwForwardDest == half && route.dwForwardMask == half);
                    if (is_default && route.dwForwardNextHop == gateway)
                    {
                        owned.emplace_back(route);
                    }
                }

                ppp::vector<MIB_IPFORWARDROW> removed;
                for (MIB_IPFORWARDROW& route : owned)
                {
                    if (!ppp::win32::network::Router::Delete(route))
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                        // Deletion is not transactional at the IP Helper API
                        // boundary. Best-effort restore rows already removed so a
                        // partial takeover does not leave the host without its
                        // original default path.
                        for (MIB_IPFORWARDROW& previous : removed)
                        {
                            ppp::win32::network::Router::Add(previous);
                        }
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                        return false;
                    }
                    removed.emplace_back(route);
                }
                return true;
            }

            bool DeleteAllDefaultGatewayRoutes(ppp::vector<MIB_IPFORWARDROW>& routes, const ppp::unordered_set<uint32_t>& bypass_gws) noexcept
            {
                auto mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULLPTR == mib)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteTableUnavailable);
                }

                uint32_t mid = inet_addr("128.0.0.0");
                for (DWORD dwNumEntries = 0; dwNumEntries < mib->dwNumEntries; dwNumEntries++)
                {
                    MIB_IPFORWARDROW& r = mib->table[dwNumEntries];
                    if ((r.dwForwardDest == ppp::net::IPEndPoint::AnyAddress && r.dwForwardMask == mid) ||
                        (r.dwForwardDest == ppp::net::IPEndPoint::AnyAddress && r.dwForwardMask == ppp::net::IPEndPoint::AnyAddress) ||
                        (r.dwForwardDest == mid && r.dwForwardMask == mid))
                    {
                        auto tail = bypass_gws.find(r.dwForwardNextHop);
                        auto endl = bypass_gws.end();
                        if (tail == endl)
                        {
                            routes.emplace_back(r);
                        }
                    }
                    else
                    {
                        continue;
                    }
                }

                bool any = false;
                for (MIB_IPFORWARDROW& r : routes)
                {
                    any |= ppp::win32::network::Router::Delete(r);
                }

                return any;
            }

            int SetAllNicsDnsAddresses(ppp::vector<boost::asio::ip::address>& servers, ppp::unordered_map<int, ppp::vector<boost::asio::ip::address>>& addresses) noexcept
            {
                int events = 0;
                // A non-empty map represents a pending restore. Never discard
                // it while preparing another apply operation.
                if (!addresses.empty())
                {
                    return events;
                }

                ppp::vector<NetworkInterfacePtr> interfaces;
                if (!GetAllNetworkInterfaces(interfaces))
                {
                    return events;
                }

                ppp::unordered_map<int, ppp::unordered_set<boost::asio::ip::address>> maps;
                for (NetworkInterfacePtr& ni : interfaces)
                {
                    if (ni->Status != OperationalStatus_Up)
                    {
                        continue;
                    }

                    auto&& r = addresses[ni->InterfaceIndex];
                    auto&& s = maps[ni->InterfaceIndex];

                    for (auto&& ips : ni->DnsAddresses)
                    {
                        boost::system::error_code ec;
                        boost::asio::ip::address ip = StringToAddress(ips.data(), ec);
                        if (ec)
                        {
                            continue;
                        }

                        if (ip.is_unspecified())
                        {
                            continue;
                        }

                        if (ip.is_multicast())
                        {
                            continue;
                        }

                        if (ppp::net::IPEndPoint::IsInvalid(ip))
                        {
                            continue;
                        }

                        if (s.emplace(ip).second) {
                            r.emplace_back(ip);
                        }
                    }
                }

                ppp::vector<ppp::string> servers_string;
                ppp::net::Ipep::AddressesTransformToStrings(servers, servers_string);

                // The snapshot map is the authorization set for this operation.
                // Apply DNS only to interfaces that were captured above.  In
                // particular, do not write to a down or newly discovered
                // interface that has no corresponding restore snapshot.
                for (const auto& [interface_index, ignored] : addresses)
                {
                    (void)ignored;
                    bool ok = SetDnsAddresses(interface_index, servers_string);
                    if (ok)
                    {
                        events++;
                    }
                }

                return events;
            }

            int SetAllNicsDnsAddresses(ppp::unordered_map<int, ppp::vector<boost::asio::ip::address>>& addresses) noexcept
            {
                int events = 0;
                for (auto it = addresses.begin(); it != addresses.end();)
                {
                    const int interface_index = it->first;
                    const auto& servers = it->second;
                    ppp::vector<ppp::string> servers_string;
                    for (auto&& ip : servers)
                    {
                        servers_string.emplace_back(ip.to_string());
                    }

                    bool ok = SetDnsAddresses(interface_index, servers_string);
                    if (ok)
                    {
                        events++;
                        it = addresses.erase(it);
                    }
                    else
                    {
                        // Retain failed snapshots so the caller can report a
                        // pending restore and retry without losing the
                        // original DNS state.
                        ++it;
                    }
                }

                return events;
            }

            int GetInterfaceMtu(int interface_index) noexcept
            {
                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULLPTR == ifRow)
                {
                    return -1;
                }
                else
                {
                    return ifRow->dwMtu;
                }
            }

            static bool SetInterfaceMtuIpInterfaceEntry(int interface_index, int mtu) noexcept
            {
                PIP_ADAPTER_ADDRESSES pAddresses = NULLPTR;
                char* szBuf = NULLPTR;
                ULONG ulBufLen = 0;
                DWORD dwErr = ERROR_BUFFER_OVERFLOW;

                // Probe and fetch with identical family/flags; retry (bounded) when the
                // adapter list grows between the two calls.
                for (int attempt = 0; attempt < 5 && dwErr == ERROR_BUFFER_OVERFLOW; attempt++)
                {
                    Mfree(szBuf);
                    szBuf = NULLPTR;

                    ulBufLen = 0;
                    dwErr = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULLPTR, NULLPTR, &ulBufLen);
                    if (dwErr != ERROR_BUFFER_OVERFLOW)
                    {
                        break;
                    }

                    szBuf = (char*)Malloc(ulBufLen);
                    if (NULLPTR == szBuf)
                    {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    pAddresses = (IP_ADAPTER_ADDRESSES*)szBuf;
                    dwErr = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULLPTR, pAddresses, &ulBufLen); /* NETIOAPI_API */
                }

                if (dwErr != NO_ERROR)
                {
                    Mfree(szBuf);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                if (dwErr == NO_ERROR)
                {
                    while (NULLPTR != pAddresses)
                    {
                        if (pAddresses->IfIndex == interface_index) 
                        {
                            MIB_IPINTERFACE_ROW ifRow;
                            InitializeIpInterfaceEntry(&ifRow);

                            //interested name
                            ifRow.InterfaceLuid = pAddresses->Luid;
                            ifRow.Family = AF_INET;
                            ifRow.NlMtu = mtu;

                            dwErr = SetIpInterfaceEntry(&ifRow);
                            break;
                        }

                        pAddresses = pAddresses->Next;
                    }
                }

                Mfree(szBuf);
                if (dwErr != NO_ERROR)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
                }

                return true;
            }

            bool SetInterfaceMtu(int interface_index, int mtu) noexcept
            {
                // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2
                // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getifentry

                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULLPTR == ifRow)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
                if (ifRow->dwMtu == mtu)
                {
                    return true;
                }
                else
                {
                    ifRow->dwMtu = mtu;
                }

                DWORD dwErr = SetIfEntry(ifRow.get());
                if (dwErr == NO_ERROR)
                {
                    if (GetInterfaceMtu(interface_index) == mtu)
                    {
                        return true;
                    }
                }

                if (!SetInterfaceMtuIpInterfaceEntry(interface_index, mtu))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
                }

                return true;
            }

            bool SetInterfaceMtuIpSubInterface(int interface_index, int mtu) noexcept
            {
                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULLPTR == ifRow)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                else
                {
                    mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
                }

                char command[100];
                snprintf(command, sizeof(command), "netsh interface ipv4 set subinterface %d mtu=%d store=persistent", interface_index, mtu);

                ppp::string result = Win32Native::EchoTrim(command);
                if (result.size() < 1)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
                }

                return true;
            }

            bool ResetNetworkEnvironment() noexcept
            {
                return Win32Native::EchoTrim("netsh winsock reset").size() > 0;
            }
        }
    }
}
