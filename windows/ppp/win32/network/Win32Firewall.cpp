#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/Win32Variant.h>

#include <ppp/diagnostics/Error.h>

#include <Windows.h>
#include <netfw.h>
#include <comutil.h>
#include <wrl/client.h>

#include <cctype>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "ole32.lib")          /* netfw32.lib */
#pragma comment(lib, "comsuppw.lib")

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            namespace
            {
                static std::string FW_EncodeOwnershipField(
                    const std::string& value)
                {
                    static const char digits[] = "0123456789abcdef";
                    std::string encoded;
                    encoded.reserve(value.size() * 2);
                    for (const unsigned char ch : value) {
                        encoded.push_back(digits[ch >> 4]);
                        encoded.push_back(digits[ch & 0x0f]);
                    }
                    return encoded;
                }

                static bool FW_DecodeOwnershipField(
                    const std::string& value, std::string& output) noexcept
                {
                    if ((value.size() & 1u) != 0) return false;
                    auto digit = [](const char ch) noexcept -> int {
                        if (ch >= '0' && ch <= '9') return ch - '0';
                        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
                        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
                        return -1;
                    };
                    std::string decoded;
                    decoded.reserve(value.size() / 2);
                    for (std::size_t i = 0; i < value.size(); i += 2) {
                        const int high = digit(value[i]);
                        const int low = digit(value[i + 1]);
                        if (high < 0 || low < 0) return false;
                        decoded.push_back(static_cast<char>((high << 4) | low));
                    }
                    output = std::move(decoded);
                    return true;
                }

                static bool FW_SplitOwnership(
                    const std::string& value,
                    std::vector<std::string>& fields) noexcept
                {
                    std::size_t begin = 0;
                    for (;;) {
                        const std::size_t end = value.find('|', begin);
                        fields.emplace_back(value.substr(
                            begin, end == std::string::npos ? end : end - begin));
                        if (end == std::string::npos) return true;
                        begin = end + 1;
                    }
                }

            }

            enum class FW_ApplicationRuleState
            {
                Missing,
                Exact,
                Conflict,
                Error,
            };

            // Enumerates the modern firewall policy without making any
            // destructive change.  Name/path alone establish pre-existing
            // ownership; removal additionally requires the full rule shape.
            static FW_ApplicationRuleState FW_FindApplicationRule(
                const wchar_t* name, const wchar_t* executablePath) noexcept
            {
                if (!name || !executablePath) return FW_ApplicationRuleState::Error;

                Microsoft::WRL::ComPtr<INetFwPolicy2> policy;
                HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULLPTR,
                    CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                    reinterpret_cast<void**>(policy.GetAddressOf()));
                if (FAILED(hr)) return FW_ApplicationRuleState::Error;

                Microsoft::WRL::ComPtr<INetFwRules> rules;
                hr = policy->get_Rules(rules.GetAddressOf());
                if (FAILED(hr)) return FW_ApplicationRuleState::Error;

                Microsoft::WRL::ComPtr<IUnknown> enumeratorUnknown;
                hr = rules->get__NewEnum(enumeratorUnknown.GetAddressOf());
                if (FAILED(hr)) return FW_ApplicationRuleState::Error;
                Microsoft::WRL::ComPtr<IEnumVARIANT> enumerator;
                hr = enumeratorUnknown.As(&enumerator);
                if (FAILED(hr)) return FW_ApplicationRuleState::Error;

                bool namePathFound = false;
                bool conflictingNameFound = false;
                bool exactShapeFound = false;
                VARIANT value;
                VariantInit(&value);
                ULONG count = 0;
                while (enumerator->Next(1, &value, &count) == S_OK) {
                    Microsoft::WRL::ComPtr<INetFwRule> rule;
                    if (value.vt != VT_UNKNOWN || !value.punkVal ||
                        FAILED(value.punkVal->QueryInterface(
                            __uuidof(INetFwRule), reinterpret_cast<void**>(rule.GetAddressOf())))) {
                        VariantClear(&value);
                        continue;
                    }
                    _bstr_t existingName;
                    _bstr_t existingPath;
                    if (FAILED(rule->get_Name(existingName.GetAddress())) ||
                        FAILED(rule->get_ApplicationName(existingPath.GetAddress()))) {
                        VariantClear(&value);
                        return FW_ApplicationRuleState::Error;
                    }
                    if (existingName == _bstr_t(name) && existingPath == _bstr_t(executablePath)) {
                        namePathFound = true;
                        NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_MAX;
                        NET_FW_ACTION action = NET_FW_ACTION_MAX;
                        VARIANT_BOOL enabled = VARIANT_FALSE;
                        _bstr_t description;
                        const bool shape =
                            SUCCEEDED(rule->get_Direction(&direction)) &&
                            SUCCEEDED(rule->get_Action(&action)) &&
                            SUCCEEDED(rule->get_Enabled(&enabled)) &&
                            SUCCEEDED(rule->get_Description(description.GetAddress())) &&
                            direction == NET_FW_RULE_DIR_IN &&
                            action == NET_FW_ACTION_ALLOW &&
                            enabled == VARIANT_TRUE &&
                            description == _bstr_t(name);
                        VariantClear(&value);
                        if (shape) {
                            exactShapeFound = true;
                        } else {
                            // A same-name/path rule with a changed shape is
                            // also a conflict: Remove(name) would otherwise
                            // be unable to target the exact row safely.
                            conflictingNameFound = true;
                        }
                    } else {
                        if (existingName == _bstr_t(name)) {
                            conflictingNameFound = true;
                        }
                        VariantClear(&value);
                    }
                }
                VariantClear(&value);
                if (exactShapeFound && !conflictingNameFound) {
                    return FW_ApplicationRuleState::Exact;
                }
                return (namePathFound || conflictingNameFound)
                    ? FW_ApplicationRuleState::Conflict
                    : FW_ApplicationRuleState::Missing;
            }

            static bool FW_NetFirewallAddApplication(const wchar_t* name, const wchar_t* executablePath, NET_FW_PROFILE_TYPE netFwType) noexcept
            {
                if (!name || !executablePath)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                if (GetFileAttributes(executablePath) == INVALID_FILE_ATTRIBUTES)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                Microsoft::WRL::ComPtr<INetFwMgr> pNetFwMgr;
                HRESULT hr = CoCreateInstance(__uuidof(NetFwMgr), NULLPTR, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), reinterpret_cast<void**>(pNetFwMgr.GetAddressOf()));
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                Microsoft::WRL::ComPtr<INetFwPolicy> pNetFwPolicy;
                hr = pNetFwMgr->get_LocalPolicy(pNetFwPolicy.GetAddressOf());
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                Microsoft::WRL::ComPtr<INetFwAuthorizedApplication> pApp;
                hr = CoCreateInstance(__uuidof(NetFwAuthorizedApplication), NULLPTR, CLSCTX_INPROC_SERVER, __uuidof(INetFwAuthorizedApplication), reinterpret_cast<void**>(pApp.GetAddressOf()));
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                // 设置应用程序名称，供界面显示和识别。
                BSTR bstrName = SysAllocString(name);
                pApp->put_Name(bstrName);
                SysFreeString(bstrName);

                // 设置应用程序可执行文件路径。
                BSTR bstrExecutablePath = SysAllocString(executablePath);
                pApp->put_ProcessImageFileName(bstrExecutablePath);
                SysFreeString(bstrExecutablePath);

                // 启用该规则。
                pApp->put_Enabled(VARIANT_TRUE);

                // 获取对应配置文件下的防火墙规则集合。
                Microsoft::WRL::ComPtr<INetFwProfile> pNetFwProfile;
                hr = pNetFwPolicy->GetProfileByType(netFwType, pNetFwProfile.GetAddressOf());
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                Microsoft::WRL::ComPtr<INetFwAuthorizedApplications> pApps;
                hr = pNetFwProfile->get_AuthorizedApplications(pApps.GetAddressOf());
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pApps->Add(pApp.Get());
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }
                return true;
            }

            static bool FW_NetFirewallAddApplication(const wchar_t* name, const wchar_t* executablePath)
            {
                HRESULT hr = S_OK;

                // 创建 NetFwPolicy2 对象。
                INetFwPolicy2* pPolicy = NULLPTR;
                hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULLPTR, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pPolicy);
                if (FAILED(hr))
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                // 获取 INetFwRules 集合。
                INetFwRules* pRules = NULLPTR;
                hr = pPolicy->get_Rules(&pRules);
                if (FAILED(hr))
                {
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                // 创建防火墙规则对象。
                INetFwRule* pRule = NULLPTR;
                hr = CoCreateInstance(__uuidof(NetFwRule), NULLPTR, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pRule);
                if (FAILED(hr))
                {
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                // 设置规则属性。
                _bstr_t bstrName(name);
                _bstr_t bstrExecutablePath(executablePath);

                hr = pRule->put_Name(bstrName);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pRule->put_Description(bstrName);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pRule->put_ApplicationName(bstrExecutablePath);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pRule->put_Direction(NET_FW_RULE_DIR_IN);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pRule->put_Action(NET_FW_ACTION_ALLOW);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                hr = pRule->put_Enabled(VARIANT_TRUE);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                // 检查是否已经存在同名且同路径的规则。
                VARIANT_BOOL bFound = VARIANT_FALSE;
                IUnknown* pEnumeratorUnk = NULLPTR;
                hr = pRules->get__NewEnum(&pEnumeratorUnk);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                IEnumVARIANT* pEnumerator = NULLPTR;
                hr = pEnumeratorUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnumerator);
                pEnumeratorUnk->Release();
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallCreateFailed);
                }

                VARIANT var;
                ULONG cElems;
                while (pEnumerator->Next(1, &var, &cElems) == S_OK)
                {
                    IUnknown* pUnknown = var.punkVal;
                    INetFwRule* pExistingRule = NULLPTR;
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

                // 如果已存在相同规则，则释放资源后直接返回。
                pEnumerator->Release();
                if (bFound)
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return true;
                }

                // 添加规则。
                hr = pRules->Add(pRule);
                if (FAILED(hr))
                {
                    pRule->Release();
                    pRules->Release();
                    pPolicy->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                }

                // 释放资源。
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
                if (NULLPTR == name)
                {
                    name = "";
                }

                if (NULLPTR == executablePath)
                {
                    executablePath = "";
                }

                _bstr_t bstr_name(name);
                _bstr_t bstr_executablePath(executablePath);

                return f(bstr_name, bstr_executablePath, netFwType);
            }

            bool Fw::NetFirewallAddApplication(const char* name, const char* executablePath, NetFirewallType netFwType) noexcept
            {
                NET_FW_PROFILE_TYPE netFwProfileType = NET_FW_PROFILE_DOMAIN; // 域网络
                if (netFwType == NetFirewallType_PrivateNetwork)   // 专用网络
                {
                    netFwProfileType = NET_FW_PROFILE_STANDARD;
                }
                elif(netFwType == NetFirewallType_PublicNetwork) // 公用网络
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

            bool Fw::CaptureApplicationOwnership(const char* name,
                                                  const char* executablePath,
                                                  ApplicationOwnership* ownership) noexcept
            {
                if (!name || !executablePath || !ownership) return false;
                ownership->name = name;
                ownership->executable_path = executablePath;
                ownership->added = false;
                _bstr_t wideName(name);
                _bstr_t widePath(executablePath);
                const FW_ApplicationRuleState state =
                    FW_FindApplicationRule(wideName, widePath);
                if (state == FW_ApplicationRuleState::Error) return false;
                ownership->existed = state != FW_ApplicationRuleState::Missing;
                return true;
            }

            bool Fw::AddApplicationOwned(const char* name,
                                         const char* executablePath,
                                         ApplicationOwnership* ownership) noexcept
            {
                if (!CaptureApplicationOwnership(name, executablePath, ownership)) return false;
                if (!NetFirewallAddApplication(name, executablePath)) return false;
                // An existing rule is not ours, even when the Add call was a
                // successful idempotent no-op.
                ownership->added = !ownership->existed;
                return true;
            }

            bool Fw::RestoreApplicationOwned(const ApplicationOwnership& ownership) noexcept
            {
                if (!ownership.added) return true;
                if (ownership.name.empty() || ownership.executable_path.empty()) return false;
                _bstr_t wideName(ownership.name.c_str());
                _bstr_t widePath(ownership.executable_path.c_str());
                const FW_ApplicationRuleState state =
                    FW_FindApplicationRule(wideName, widePath);
                if (state == FW_ApplicationRuleState::Missing) return true;
                // A changed or ambiguous rule must remain untouched.  This is
                // the compare-before-delete boundary for user/other-VPN edits.
                if (state != FW_ApplicationRuleState::Exact) return false;

                Microsoft::WRL::ComPtr<INetFwPolicy2> policy;
                HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULLPTR,
                    CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                    reinterpret_cast<void**>(policy.GetAddressOf()));
                if (FAILED(hr)) return false;
                Microsoft::WRL::ComPtr<INetFwRules> rules;
                hr = policy->get_Rules(rules.GetAddressOf());
                if (FAILED(hr) || FAILED(rules->Remove(wideName))) return false;
                // Confirm the actual policy state before allowing the caller
                // to discard its durable ownership record.
                return FW_FindApplicationRule(wideName, widePath) ==
                    FW_ApplicationRuleState::Missing;
            }

            std::string Fw::SerializeApplicationOwnership(
                const ApplicationOwnership& ownership)
            {
                if (ownership.name.empty() || ownership.executable_path.empty()) {
                    return std::string();
                }
                return "fw-app-v1|" + FW_EncodeOwnershipField(ownership.name) +
                    "|" + FW_EncodeOwnershipField(ownership.executable_path) +
                    "|" + (ownership.existed ? "1" : "0") +
                    "|" + (ownership.added ? "1" : "0");
            }

            bool Fw::DeserializeApplicationOwnership(
                const std::string& value,
                ApplicationOwnership* ownership) noexcept
            {
                if (!ownership) return false;
                std::vector<std::string> fields;
                FW_SplitOwnership(value, fields);
                if (fields.size() != 5 || fields[0] != "fw-app-v1" ||
                    (fields[3] != "0" && fields[3] != "1") ||
                    (fields[4] != "0" && fields[4] != "1")) {
                    return false;
                }
                ApplicationOwnership decoded;
                if (!FW_DecodeOwnershipField(fields[1], decoded.name) ||
                    !FW_DecodeOwnershipField(fields[2], decoded.executable_path) ||
                    decoded.name.empty() || decoded.executable_path.empty()) {
                    return false;
                }
                decoded.existed = fields[3] == "1";
                decoded.added = fields[4] == "1";
                // An existing row is never owned by this process.  Reject
                // malformed records instead of allowing them to authorize a
                // destructive recovery operation.
                if (decoded.existed && decoded.added) return false;
                *ownership = std::move(decoded);
                return true;
            }

            std::string Fw::ApplicationOwnershipTarget(
                const ApplicationOwnership& ownership)
            {
                if (ownership.name.empty() || ownership.executable_path.empty()) {
                    return std::string();
                }
                return "application:" + FW_EncodeOwnershipField(ownership.name) +
                    ":" + FW_EncodeOwnershipField(ownership.executable_path);
            }
        }
    }
}
