#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/Win32Variant.h>

#include <Windows.h>
#include <atlbase.h>
#include <netfw.h>
#include <comutil.h>

#pragma comment(lib, "ole32.lib")          /* netfw32.lib */
#pragma comment(lib, "comsuppw.lib")

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            static bool FW_NetFirewallAddApplication(const wchar_t* name, const wchar_t* executablePath, NET_FW_PROFILE_TYPE netFwType) noexcept
            {
                if (!name || !executablePath)
                {
                    return false;
                }

                if (GetFileAttributes(executablePath) == INVALID_FILE_ATTRIBUTES)
                {
                    return false;
                }

                CComPtr<INetFwMgr> pNetFwMgr;
                HRESULT hr = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&pNetFwMgr);
                if (FAILED(hr))
                {
                    return false;
                }

                CComPtr<INetFwPolicy> pNetFwPolicy;
                hr = pNetFwMgr->get_LocalPolicy(&pNetFwPolicy);
                if (FAILED(hr))
                {
                    return false;
                }

                CComPtr<INetFwAuthorizedApplication> pApp;
                hr = CoCreateInstance(__uuidof(NetFwAuthorizedApplication), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwAuthorizedApplication), (void**)&pApp);
                if (FAILED(hr))
                {
                    return false;
                }

                // 在例外列表里，程序显示的名称
                BSTR bstrName = SysAllocString(name);
                pApp->put_Name(bstrName);
                SysFreeString(bstrName);

                // 程序的路径及文件名
                BSTR bstrExecutablePath = SysAllocString(executablePath);
                pApp->put_ProcessImageFileName(bstrExecutablePath);
                SysFreeString(bstrExecutablePath);

                // 是否启用该规则
                pApp->put_Enabled(VARIANT_TRUE);

                // 加入到防火墙的管理策略
                CComPtr<INetFwProfile> pNetFwProfile;
                hr = pNetFwPolicy->GetProfileByType(netFwType, &pNetFwProfile);
                if (FAILED(hr))
                {
                    return false;
                }

                CComPtr<INetFwAuthorizedApplications> pApps;
                hr = pNetFwProfile->get_AuthorizedApplications(&pApps);
                if (FAILED(hr))
                {
                    return false;
                }

                hr = pApps->Add(pApp);
                if (FAILED(hr))
                {
                    return false;
                }
                return true;
            }

            static bool FW_NetFirewallAddApplication(const wchar_t* name, const wchar_t* executablePath)
            {
                HRESULT hr = S_OK;

                // 创建NetFwPolicy2对象
                INetFwPolicy2* pPolicy = NULL;
                hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pPolicy);
                if (FAILED(hr))
                {
                    return false;
                }

                // 获取INetFwRules对象
                INetFwRules* pRules = NULL;
                hr = pPolicy->get_Rules(&pRules);
                if (FAILED(hr))
                {
                    pPolicy->Release();
                    return false;
                }

                // 创建规则对象
                INetFwRule* pRule = NULL;
                hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pRule);
                if (FAILED(hr))
                {
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                // 设置规则属性
                _bstr_t bstrName(name);
                _bstr_t bstrExecutablePath(executablePath);

                hr = pRule->put_Name(bstrName);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                hr = pRule->put_Description(bstrName);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                hr = pRule->put_ApplicationName(bstrExecutablePath);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                hr = pRule->put_Direction(NET_FW_RULE_DIR_IN);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                hr = pRule->put_Action(NET_FW_ACTION_ALLOW);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                hr = pRule->put_Enabled(VARIANT_TRUE);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                // 检查是否已存在同名规则
                VARIANT_BOOL bFound = VARIANT_FALSE;
                IUnknown* pEnumeratorUnk = NULL;
                hr = pRules->get__NewEnum(&pEnumeratorUnk);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                IEnumVARIANT* pEnumerator = NULL;
                hr = pEnumeratorUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnumerator);
                pEnumeratorUnk->Release();
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                VARIANT var;
                ULONG cElems;
                while (pEnumerator->Next(1, &var, &cElems) == S_OK)
                {
                    IUnknown* pUnknown = var.punkVal;
                    INetFwRule* pExistingRule = NULL;
                    hr = pUnknown->QueryInterface(__uuidof(INetFwRule), (void**)&pExistingRule);
                    if (hr == S_OK)
                    {
                        _bstr_t bstrExistingName;
                        hr = pExistingRule->get_Name(bstrExistingName.GetAddress());
                        if (FAILED(hr))
                        {
                            continue;
                        }

                        _bstr_t bstrExistingAppPath;
                        hr = pExistingRule->get_ApplicationName(bstrExistingAppPath.GetAddress());
                        if (FAILED(hr))
                        {
                            continue;
                        }

                        if (bstrExistingName == bstrName && bstrExistingAppPath == bstrExecutablePath) {
                            bFound = VARIANT_TRUE;
                            break;
                        }
                        else
                        {
                            pExistingRule->Release();
                        }
                    }
                    VariantClear(&var);
                }

                // 如果已存在同名规则，则释放资源并返回
                pEnumerator->Release();
                if (bFound)
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return true;
                }

                // 添加规则
                hr = pRules->Add(pRule);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return false;
                }

                // 释放资源
                pRule->Release();
                pRules->Release();
                pPolicy->Release();

                return true;
            }

            static bool FW_NetFirewallAddAllApplication(const wchar_t* name, const wchar_t* executablePath) noexcept
            {
                if (FW_NetFirewallAddApplication(name, executablePath))
                {
                    return true;
                }

                bool b = true;
                b &= FW_NetFirewallAddApplication(name, executablePath, NET_FW_PROFILE_STANDARD); // 1
                b &= FW_NetFirewallAddApplication(name, executablePath, NET_FW_PROFILE_CURRENT);  // 2
                return b;
            }

            static bool FW_require(const char* name, const char* executablePath, NET_FW_PROFILE_TYPE netFwType, bool(*f)(_bstr_t&, _bstr_t&, NET_FW_PROFILE_TYPE)) noexcept
            {
                if (NULL == name)
                {
                    name = "";
                }

                if (NULL == executablePath)
                {
                    executablePath = "";
                }

                _bstr_t bstr_name(name);
                _bstr_t bstr_executablePath(executablePath);

                return f(bstr_name, bstr_executablePath, netFwType);
            }

            bool Fw::NetFirewallAddApplication(const char* name, const char* executablePath, NetFirewallType netFwType) noexcept
            {
                NET_FW_PROFILE_TYPE netFwProfileType = NET_FW_PROFILE_DOMAIN; // 城域网络
                if (netFwType == NetFirewallType_PrivateNetwork)   // 专用网络
                {
                    netFwProfileType = NET_FW_PROFILE_STANDARD;
                }
                elif(netFwType == NetFirewallType_PublicNetwork) // 公共网络
                {
                    netFwProfileType = NET_FW_PROFILE_CURRENT;
                }

                return FW_require(name, executablePath, netFwProfileType, [](_bstr_t& name, _bstr_t& executablePath, NET_FW_PROFILE_TYPE netFwType) noexcept
                    {
                        return FW_NetFirewallAddApplication(name, executablePath, netFwType);
                    });
            }

            bool Fw::NetFirewallAddApplication(const char* name, const char* executablePath) noexcept
            {
                return FW_require(name, executablePath, NET_FW_PROFILE_TYPE_MAX, [](_bstr_t& name, _bstr_t& executablePath, NET_FW_PROFILE_TYPE netFwType) noexcept
                    {
                        return FW_NetFirewallAddApplication(name, executablePath);
                    });
            }

            bool Fw::NetFirewallAddAllApplication(const char* name, const char* executablePath) noexcept
            {
                return FW_require(name, executablePath, NET_FW_PROFILE_TYPE_MAX, [](_bstr_t& name, _bstr_t& executablePath, NET_FW_PROFILE_TYPE netFwType) noexcept
                    {
                        return FW_NetFirewallAddAllApplication(name, executablePath);
                    });
            }
        }
    }
}