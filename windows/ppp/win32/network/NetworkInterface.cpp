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
                if (NULL != s)
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
                if (NULL == s)
                {
                    return NULL;
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
                if (NULL == s)
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

            static bool RegistryEditGetValue(HKEY hSubKey, const TCHAR* key, ppp::string& value) noexcept
            {
                TCHAR szBuffer[MAX_PATH];
                DWORD dwSize = sizeof(szBuffer);
                if (RegQueryValueEx(hSubKey, key, NULL, NULL, reinterpret_cast<LPBYTE>(szBuffer), &dwSize) == ERROR_SUCCESS)
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
                IWbemLocator* pLoc = NULL;
                HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
                if (FAILED(hr))
                {
                    return false;
                }

                IWbemServices* pSvc = NULL;
                hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (FAILED(hr))
                {
                    pLoc->Release();
                    return false;
                }

                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
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

                IEnumWbemClassObject* pEnumerator = NULL;
                hr = pSvc->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(wsql),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL,
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
                    IWbemClassObject* pclsObj = NULL;
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
                IWbemLocator* pLocator = NULL;
                HRESULT hRes = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLocator);
                if (FAILED(hRes) || !pLocator)
                {
                    return ppp::string();
                }

                IWbemServices* pServices = NULL;
                hRes = pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &pServices);
                if (FAILED(hRes) || !pServices)
                {
                    pLocator->Release();
                    return ppp::string();
                }

                hRes = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
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

                IEnumWbemClassObject* pEnumerator = NULL;
                hRes = pServices->ExecQuery(_bstr_t("WQL"), _bstr_t(wszQuery), WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator);
                if (FAILED(hRes) || !pEnumerator)
                {
                    pServices->Release();
                    pLocator->Release();
                    return ppp::string();
                }

                IWbemClassObject* pObject = NULL;
                ULONG uReturn = 0;
                ppp::string szNetConnectionID = {};
                while (pEnumerator)
                {
                    IWbemClassObject* pclsObj = NULL;
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
                IWbemLocator* pLoc = NULL;
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

                IWbemServices* pSvc = NULL;
                hr = pLoc->ConnectServer(
                    _bstr_t(L"ROOT\\CIMV2"),
                    NULL,
                    NULL,
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
                    NULL,
                    RPC_C_AUTHN_LEVEL_CALL,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    NULL,
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

                IEnumWbemClassObject* pEnumerator = NULL;
                hr = pSvc->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(wsql), /*  WHERE IPEnabled = TRUE */
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    NULL,
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
                    IWbemClassObject* pclsObj = NULL;
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
                        if (NULL != networkInterface)
                        {
                            networkInterface->Description = VARIANT_string(pclsObj, L"Description");
                            networkInterface->Driver = VARIANT_string(pclsObj, L"ServiceName");
                            networkInterface->Guid = VARIANT_string(pclsObj, L"SettingID");
                            networkInterface->Index = VARIANT_value(pclsObj, L"Index", -1);
                            networkInterface->InterfaceIndex = VARIANT_value(pclsObj, L"InterfaceIndex", -1);
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
                    return NULL;
                }

                ppp::vector<NetworkInterfacePtr> network_interfaces;
                if (!GetAllNetworkInterfacesInternal(is_network_index, index, network_interfaces))
                {
                    return NULL;
                }

                if (network_interfaces.empty())
                {
                    return NULL;
                }
                else
                {
                    NetworkInterfacePtr network_interface = network_interfaces[0];
                    if (NULL != network_interface)
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
                    hr = obj->Get(L"__PATH", 0, &vtPATH, NULL, NULL);
                    if (SUCCEEDED(hr))
                    {
                        hr = services->ExecMethod(vtPATH.bstrVal, EnableDHCP, 0, NULL, obj, NULL, NULL);
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
                    while (RegEnumKeyEx(hKey, dwIndex++, szSubKeyName, &dwSubKeyNameLength, NULL, NULL, NULL, NULL) != ERROR_NO_MORE_ITEMS)
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
                HDEVINFO devInfoSet = SetupDiGetClassDevs(NULL, /*_T("Net")*/NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
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
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_CLASSGUID, NULL, (PBYTE)classGuid, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        continue;
                    }

                    if (_tcsicmp(classGuid, _T("{4d36e972-e325-11ce-bfc1-08002be10318}")) != 0)
                    {
                        continue;
                    }

                    TCHAR hardwareId[LINE_LEN];
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_HARDWAREID, NULL, (PBYTE)hardwareId, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_SERVICE, NULL, (PBYTE)hardwareId, LINE_LEN, &requiredSize);
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
                    b = SetupDiGetDeviceRegistryProperty(devInfoSet, &devInfoData, SPDRP_DRIVER, NULL, (PBYTE)driver, LINE_LEN, &requiredSize);
                    if (!b)
                    {
                        continue;
                    }
                    else
                    {
                        TCHAR* networkIndex = tcschr(driver, '\\');
                        if (NULL == networkIndex)
                        {
                            continue;
                        }

                        NetworkInterfacePtr network_interface = GetNetworkInterfaceByIndex(ttoll(++networkIndex));
                        if (NULL == network_interface)
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
                IWbemLocator* pLoc = NULL;
                HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
                if (FAILED(hr))
                {
                    return false;
                }

                IWbemServices* pSvc = NULL;
                hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (FAILED(hr))
                {
                    pLoc->Release();
                    return false;
                }

                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                if (FAILED(hr))
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                WCHAR wszQuery[512];
                swprintf_s(wszQuery, _countof(wszQuery), L"SELECT * FROM Win32_NetworkAdapter WHERE InterfaceIndex='%u'", dwIndex);

                IEnumWbemClassObject* pEnumerator = NULL;
                hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wszQuery), WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator);
                if (FAILED(hr) || NULL == pEnumerator)
                {
                    pSvc->Release();
                    pLoc->Release();
                    return false;
                }

                IWbemClassObject* pNetAdapter = NULL;
                ULONG uReturned = 0;
                hr = pEnumerator->Next(WBEM_INFINITE, 1, &pNetAdapter, &uReturned);
                if (FAILED(hr) || NULL == pNetAdapter || uReturned == 0)
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
                if (NULL != pName)
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

                hr = pSvc->PutInstance(pNetAdapter, WBEM_FLAG_UPDATE_ONLY, NULL, NULL);
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
                        if (NULL != interfacex)
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
                    } while (NULL != pEntry);
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
                    return NULL;
                }

                for (AdapterInterfacePtr ai : ais)
                {
                    if (ai->IfIndex == interface_index)
                    {
                        return ai;
                    }
                }
                return NULL;
            }

            std::shared_ptr<MIB_IFTABLE> GetIfTable() noexcept
            {
                DWORD dwSize = 0;
                if (::GetIfTable(NULL, &dwSize, FALSE) != ERROR_INSUFFICIENT_BUFFER)
                {
                    return NULL;
                }

                std::shared_ptr<MIB_IFTABLE> pIfTable = std::shared_ptr<MIB_IFTABLE>((MIB_IFTABLE*)Malloc(dwSize),
                    [](MIB_IFTABLE* p) noexcept
                    {
                        Mfree(p);
                    });
                if (pIfTable == NULL)
                {
                    return NULL;
                }

                if (::GetIfTable(pIfTable.get(), &dwSize, FALSE) != NO_ERROR)
                {
                    return NULL;
                }

                return pIfTable;
            }

            std::shared_ptr<MIB_IFROW> GetIfEntry(int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return NULL;
                }

                std::shared_ptr<MIB_IFROW> pIfRow = std::shared_ptr<MIB_IFROW>((MIB_IFROW*)Malloc(sizeof(MIB_IFROW)),
                    [](MIB_IFROW* p) noexcept
                    {
                        Mfree(p);
                    });
                if (NULL == pIfRow)
                {
                    return NULL;
                }

                pIfRow->dwIndex = interface_index;
                if (::GetIfEntry(pIfRow.get()) != NO_ERROR)
                {
                    return NULL;
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
                    return false;
                }

                PROCESS_INFORMATION pi;
                ZeroMemory(&pi, sizeof(pi));

                STARTUPINFOA si;
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);

                char command[1000];
                snprintf(command, sizeof(command), "netsh interface ipv4 set address name=\"%s\" static %s %s", interface_name.data(), ip.data(), mask.data());

                if (!CreateProcessA(NULL, command,
                    NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
                {
                    return false;
                }

                DWORD dwExitCode = INFINITE;
                if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0)
                {
                    if (!GetExitCodeProcess(pi.hProcess, &dwExitCode))
                    {
                        dwExitCode = INFINITE;
                    }
                }

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return dwExitCode == ERROR_SUCCESS;
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
                return NULL;
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
                if (NULL == mib)
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
                            if (NULL != ai)
                            {
                                FixGatewayServerAddress(ai);
                            }
                            return { ai, ni };
                        }

                        std::size_t index = connection_id_lower.find(nic_lower);
                        if (index != std::string::npos)
                        {
                            AdapterInterfacePtr ai = GetNetworkInterfaceByIndex2(ni->InterfaceIndex);
                            if (NULL != ai)
                            {
                                FixGatewayServerAddress(ai);
                            }
                            return { ai, ni };
                        }
                    }
                }

                AdapterInterfacePtr ai = GetUnderlyingNetowrkInterface(id);
                if (NULL == ai)
                {
                    return { NULL, NULL };
                }

                return { ai, ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex) };
            }

            AdapterInterfacePtr GetUnderlyingNetowrkInterface(const ppp::string& id) noexcept
            {
                ppp::vector<ppp::win32::network::AdapterInterfacePtr> adapters;
                if (!ppp::win32::network::GetAllAdapterInterfaces2(adapters))
                {
                    return NULL;
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
                if (NULL == ni) // Try to choose the best underlying hosting network interface!
                {
                    ni = SelectBaseNetowrkInterface(in6_optionals, false);
                    if (NULL == ni)
                    {
                        ni = SelectBaseNetowrkInterface(in4_optionals, true);
                        if (NULL == ni)
                        {
                            ni = SelectBaseNetowrkInterface(in6_optionals, true);
                            if (NULL == ni)
                            {
                                return NULL;
                            }
                        }
                    }
                }

                return ni;
            }

            bool AddAllRoutes(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept
            {
                if (NULL == rib)
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
                if (NULL == rib)
                {
                    return false;
                }

                auto mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULL == mib)
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

            void DeleteAllDefaultGatewayRoutes(boost::asio::ip::address gw) noexcept
            {
                std::string tp = gw.to_string();
                ppp::string ip = ppp::string(tp.data(), tp.size());
                ppp::win32::Win32Native::Echo("route delete 0.0.0.0 mask 0.0.0.0 " + ip);
                ppp::win32::Win32Native::Echo("route delete 128.0.0.0 mask 128.0.0.0 " + ip);
                ppp::win32::Win32Native::Echo("route delete 128.0.0.0 mask 128.0.0.0 " + ip);
            }

            bool DeleteAllDefaultGatewayRoutes(ppp::vector<MIB_IPFORWARDROW>& routes, const ppp::unordered_set<uint32_t>& bypass_gws) noexcept
            {
                auto mib = ppp::win32::network::Router::GetIpForwardTable();
                if (NULL == mib)
                {
                    return false;
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
                addresses.clear();

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

                for (NetworkInterfacePtr& ni : interfaces)
                {
                    bool ok = SetDnsAddresses(ni->InterfaceIndex, servers_string);
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
                for (auto&& [interface_index, servers] : addresses)
                {
                    ppp::vector<ppp::string> servers_string;
                    for (auto&& ip : servers)
                    {
                        servers_string.emplace_back(ip.to_string());
                    }

                    bool ok = SetDnsAddresses(interface_index, servers_string);
                    if (ok)
                    {
                        events++;
                    }
                }

                addresses.clear();
                return events;
            }

            int GetInterfaceMtu(int interface_index) noexcept
            {
                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULL == ifRow)
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
                PIP_ADAPTER_ADDRESSES pAddresses = NULL;
                ULONG ulBufLen = 0;
                GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &ulBufLen);

                if (ulBufLen == 0)
                {
                    return false;
                }

                char* szBuf = (char*)Malloc(ulBufLen);
                pAddresses = (IP_ADAPTER_ADDRESSES*)szBuf;
                if (NULL == pAddresses)
                {
                    return false;
                }

                DWORD dwErr = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST, NULL, pAddresses, &ulBufLen); /* NETIOAPI_API */
                if (dwErr == NO_ERROR)
                {
                    while (NULL != pAddresses)
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
                return dwErr == NO_ERROR;
            }

            bool SetInterfaceMtu(int interface_index, int mtu) noexcept
            {
                // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2
                // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getifentry

                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULL == ifRow)
                {
                    return false;
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

                return SetInterfaceMtuIpInterfaceEntry(interface_index, mtu);
            }

            bool SetInterfaceMtuIpSubInterface(int interface_index, int mtu) noexcept
            {
                std::shared_ptr<MIB_IFROW> ifRow = GetIfEntry(interface_index);
                if (NULL == ifRow)
                {
                    return false;
                }
                else
                {
                    mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
                }

                char command[100];
                snprintf(command, sizeof(command), "netsh interface ipv4 set subinterface %d mtu=%d store=persistent", interface_index, mtu);

                ppp::string result = Win32Native::EchoTrim(command);
                return result.size() > 0;
            }

            bool ResetNetworkEnvironment() noexcept
            {
                return Win32Native::EchoTrim("netsh winsock reset").size() > 0;
            }
        }
    }
}