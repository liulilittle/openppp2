#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/Win32RegistryKey.h>
#include <ppp/diagnostics/Error.h>

#include <wininet.h>
#include <tchar.h>
#include <comdef.h>
#include <comutil.h>

#include <Windows.h>
#include <Shellapi.h>
#include <shlobj_core.h>

#pragma comment(lib, "wininet.lib")

using ppp::win32::Win32Native;

namespace ppp
{
    namespace net
    {
        namespace proxies
        {
            static constexpr const wchar_t* EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME = L"Software\\Policies\\Google\\Chrome";
            static constexpr const wchar_t* EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE = L"Software\\Policies\\Microsoft\\Edge";

            // Tracks whether THIS process currently has the Windows system proxy engaged.
            // Used by EmergencyRestoreSystemProxy() so the crash-path restore is a strict
            // no-op when we never touched the system proxy (don't clobber a user's own proxy).
            static std::atomic<bool> s_system_proxy_engaged{ false };
            static constexpr const wchar_t* SYSTEM_PROXY_PATH =
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
            static constexpr const wchar_t* SYSTEM_PROXY_OVERRIDE =
                L"localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;172.32.*;192.168.*;<local>";
            // The core can be terminated without running its normal teardown. Keep
            // the original values outside the process so the crash handler can
            // restore the user's proxy instead of blindly clearing it.
            static constexpr const wchar_t* SYSTEM_PROXY_RECOVERY_PATH =
                L"Software\\OpenPPP2\\NetworkRecovery\\SystemProxy";

            static bool STATIC_SetSnapshotPresence(const wchar_t* name, bool present) noexcept
            {
                return ppp::win32::SetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, name, present ? 1u : 0u);
            }

            static bool STATIC_CaptureSystemProxySnapshot() noexcept
            {
                bool version_ok = false;
                ppp::win32::GetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"Version", &version_ok);
                if (version_ok)
                {
                    return true;
                }

                bool server_ok = false;
                bool enable_ok = false;
                bool pac_ok = false;
                bool override_ok = false;
                const std::wstring server = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyServer", &server_ok);
                const DWORD enable = ppp::win32::GetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", &enable_ok);
                const std::wstring pac = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"AutoConfigURL", &pac_ok);
                const std::wstring override = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyOverride", &override_ok);

                // Presence bits distinguish an absent registry value from an
                // explicitly empty value, which is required for exact restore.
                bool ok = STATIC_SetSnapshotPresence(L"OriginalServerPresent", server_ok) &&
                    STATIC_SetSnapshotPresence(L"OriginalEnablePresent", enable_ok) &&
                    STATIC_SetSnapshotPresence(L"OriginalPacPresent", pac_ok) &&
                    STATIC_SetSnapshotPresence(L"OriginalOverridePresent", override_ok);
                if (server_ok)
                    ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalServer", server) && ok;
                if (enable_ok)
                    ok = ppp::win32::SetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalEnable", enable) && ok;
                if (pac_ok)
                    ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalPac", pac) && ok;
                if (override_ok)
                    ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalOverride", override) && ok;
                if (ok)
                {
                    ok = ppp::win32::SetRegistryValueDword(
                        HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"Version", 1u);
                }
                return ok;
            }

            static bool STATIC_RecordAppliedSystemProxy(
                const std::wstring& server, const std::wstring& pac, bool enable,
                const std::wstring& override) noexcept
            {
                bool ok = ppp::win32::SetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedServer", server);
                ok = ppp::win32::SetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedEnable", enable ? 1u : 0u) && ok;
                ok = ppp::win32::SetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedPac", pac) && ok;
                ok = ppp::win32::SetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedOverride", override) && ok;
                return ok;
            }

            static bool STATIC_DeleteSnapshot() noexcept
            {
                HKEY key = NULLPTR;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
                    return true;
                const wchar_t* names[] = {
                    L"Version", L"OriginalServerPresent", L"OriginalEnablePresent",
                    L"OriginalPacPresent", L"OriginalOverridePresent", L"OriginalServer",
                    L"OriginalEnable", L"OriginalPac", L"OriginalOverride", L"AppliedServer",
                    L"AppliedEnable", L"AppliedPac", L"AppliedOverride"};
                bool ok = true;
                for (const wchar_t* name : names)
                {
                    const LONG result = RegDeleteValueW(key, name);
                    ok = (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) && ok;
                }
                RegCloseKey(key);
                return ok;
            }

            static bool STATIC_RestoreSystemProxy(bool force) noexcept
            {
                bool version_ok = false;
                ppp::win32::GetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"Version", &version_ok);
                if (!version_ok)
                    return true;

                bool original_server_present = false;
                bool original_enable_present = false;
                bool original_pac_present = false;
                bool original_override_present = false;
                const bool server_present = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalServerPresent", &original_server_present) != 0;
                const bool enable_present = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalEnablePresent", &original_enable_present) != 0;
                const bool pac_present = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalPacPresent", &original_pac_present) != 0;
                const bool override_present = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalOverridePresent", &original_override_present) != 0;
                if (!original_server_present || !original_enable_present || !original_pac_present || !original_override_present)
                    return false;

                const std::wstring server = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalServer", nullptr);
                const DWORD enable = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalEnable", nullptr);
                const std::wstring pac = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalPac", nullptr);
                const std::wstring override = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"OriginalOverride", nullptr);

                if (!force)
                {
                    bool current_server_ok = false;
                    bool current_enable_ok = false;
                    bool current_pac_ok = false;
                    bool current_override_ok = false;
                    const std::wstring current_server = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyServer", &current_server_ok);
                    const DWORD current_enable = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", &current_enable_ok);
                    const std::wstring current_pac = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"AutoConfigURL", &current_pac_ok);
                    const std::wstring current_override = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyOverride", &current_override_ok);
                    const std::wstring applied_server = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedServer", nullptr);
                    const DWORD applied_enable = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedEnable", nullptr);
                    const std::wstring applied_pac = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedPac", nullptr);
                    const std::wstring applied_override = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_RECOVERY_PATH, L"AppliedOverride", nullptr);
                    if (!current_server_ok || !current_enable_ok || !current_pac_ok || !current_override_ok ||
                        current_server != applied_server || current_enable != applied_enable ||
                        current_pac != applied_pac || current_override != applied_override)
                        return false;
                }

                bool ok = true;
                auto restore_string = [&](const wchar_t* name, bool present, const std::wstring& value) {
                    if (present)
                        return ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, name, value);
                    HKEY key = NULLPTR;
                    if (RegOpenKeyExW(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
                        return false;
                    const LONG result = RegDeleteValueW(key, name);
                    RegCloseKey(key);
                    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
                };
                ok = restore_string(L"ProxyServer", server_present, server) && ok;
                if (enable_present)
                    ok = ppp::win32::SetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", enable) && ok;
                else
                {
                    HKEY key = NULLPTR;
                    if (RegOpenKeyExW(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
                        ok = false;
                    else
                    {
                        const LONG result = RegDeleteValueW(key, L"ProxyEnable");
                        RegCloseKey(key);
                        ok = (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) && ok;
                    }
                }
                ok = restore_string(L"AutoConfigURL", pac_present, pac) && ok;
                ok = restore_string(L"ProxyOverride", override_present, override) && ok;
                ok = HttpProxy::RefreshSystemProxy() && ok;
                if (!ok)
                    return false;
                return STATIC_DeleteSnapshot();
            }

            static bool STATIC_IsSupportExperimentalQuicProtocol(LPCWSTR path) noexcept
            {
                bool bOK = false;
                DWORD dwQuicAllowed = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, path, L"QuicAllowed", &bOK);
                if (!bOK)
                {
                    return true;
                }
                else
                {
                    return dwQuicAllowed != 0;
                }
            }

            static bool STATIC_SetSupportExperimentalQuicProtocol(LPCWSTR path, bool value) noexcept
            {
                bool bOK = ppp::win32::SetRegistryValueDword(HKEY_CURRENT_USER, path, L"QuicAllowed", value ? 1 : 0);
                return bOK;
            }

            bool HttpProxy::RefreshSystemProxy() noexcept
            {
                INTERNET_PROXY_INFO ipi;
                RtlZeroMemory(&ipi, sizeof(ipi));

                bool b =
                    InternetSetOption(NULLPTR, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, NULLPTR, 0) &&
                    InternetSetOption(NULLPTR, INTERNET_OPTION_SETTINGS_CHANGED, &ipi, sizeof(INTERNET_PROXY_INFO)) &&
                    InternetSetOption(NULLPTR, INTERNET_OPTION_REFRESH, NULLPTR, 0);
                if (!b)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                }
                return b;
            }

            bool HttpProxy::SetSystemProxy(const ppp::string& server, const ppp::string& bypass) noexcept
            {
                INTERNET_PROXY_INFO ipi;
                RtlZeroMemory(&ipi, sizeof(ipi));

                _bstr_t bypass_bstr(bypass.data());
                _bstr_t server_bstr(server.data());

                ipi.dwAccessType = INTERNET_OPEN_TYPE_PROXY;
                ipi.lpszProxy = server_bstr;
                ipi.lpszProxyBypass = bypass_bstr;

                if (!STATIC_CaptureSystemProxySnapshot())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                    return false;
                }
                s_system_proxy_engaged.store(true, std::memory_order_release);

                bool b = InternetSetOption(NULLPTR, INTERNET_OPTION_PROXY, &ipi, sizeof(INTERNET_PROXY_INFO));
                if (!b)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                }
                if (b)
                {
                    bool enable_ok = false;
                    const DWORD enable = ppp::win32::GetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", &enable_ok);
                    // AutoConfigURL is optional; a missing value means no PAC and is
                    // recorded as empty rather than failing an otherwise applied proxy.
                    bool pac_ok = false;
                    const std::wstring pac = ppp::win32::GetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"AutoConfigURL", &pac_ok);
                    const std::wstring server_wcs = server_bstr.GetBSTR();
                    const std::wstring bypass_wcs = bypass_bstr.GetBSTR();
                    b = enable_ok && STATIC_RecordAppliedSystemProxy(server_wcs, pac_ok ? pac : std::wstring(), enable != 0, bypass_wcs);
                }
                return b;
            }

            bool HttpProxy::SetSystemProxy(const ppp::string& server) noexcept
            {
                return SetSystemProxy(server, "local");
            }

            bool HttpProxy::SetSystemProxy(const ppp::string& server, const ppp::string& pac, bool enable) noexcept
            {
                _bstr_t server_bstr(server.data());
                _bstr_t pac_bstr(pac.data());

                std::wstring server_wcs = server_bstr.GetBSTR();
                std::wstring pac_wcs = pac_bstr.GetBSTR();
                return SetSystemProxy(server_wcs, pac_wcs, enable);
            }

            bool HttpProxy::SetSystemProxy(const std::wstring& server, const std::wstring& pac, bool enable) noexcept
            {
                if (!enable && server.empty() && pac.empty())
                {
                    const bool restored = STATIC_RestoreSystemProxy(false);
                    if (restored)
                        s_system_proxy_engaged.store(false, std::memory_order_release);
                    return restored;
                }

                if (!STATIC_CaptureSystemProxySnapshot() ||
                    !STATIC_RecordAppliedSystemProxy(server, pac, enable, SYSTEM_PROXY_OVERRIDE))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                    s_system_proxy_engaged.store(true, std::memory_order_release);
                    return false;
                }
                // Mark the operation before the first write so a partial update is
                // still eligible for the crash-path emergency restore. Clear it only
                // after every write, refresh and read-back has succeeded.
                s_system_proxy_engaged.store(true, std::memory_order_release);

                bool ok = true;
                ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyServer", server) && ok;
                ok = ppp::win32::SetRegistryValueDword(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", enable ? 1 : 0) && ok;
                ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"AutoConfigURL", pac) && ok;
                ok = RefreshSystemProxy() && ok;
                ok = ppp::win32::SetRegistryValueString(HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyOverride", SYSTEM_PROXY_OVERRIDE) && ok;
                ok = RefreshSystemProxy() && ok;

                bool server_read = false;
                bool enable_read = false;
                bool pac_read = false;
                bool override_read = false;
                const std::wstring observed_server = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyServer", &server_read);
                const DWORD observed_enable = ppp::win32::GetRegistryValueDword(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyEnable", &enable_read);
                const std::wstring observed_pac = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"AutoConfigURL", &pac_read);
                const std::wstring observed_override = ppp::win32::GetRegistryValueString(
                    HKEY_CURRENT_USER, SYSTEM_PROXY_PATH, L"ProxyOverride", &override_read);
                ok = server_read && observed_server == server && ok;
                ok = enable_read && observed_enable == (enable ? 1u : 0u) && ok;
                ok = pac_read && observed_pac == pac && ok;
                ok = override_read && observed_override == SYSTEM_PROXY_OVERRIDE && ok;

                if (!ok)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                    // Keep the marker set on failure. The next stop/crash path must
                    // still attempt cleanup instead of reporting success.
                    return false;
                }

                // The registry was changed and a snapshot exists, so keep the marker
                // set even when enable is false; only a successful restore clears it.
                s_system_proxy_engaged.store(true, std::memory_order_release);
                return true;
            }

            void HttpProxy::EmergencyRestoreSystemProxy() noexcept
            {
                // No-op unless this process engaged the system proxy. This keeps the
                // crash-path restore from disabling a proxy the user set themselves.
                if (!s_system_proxy_engaged.load(std::memory_order_acquire))
                {
                    return;
                }

                // Restore the persisted original values and keep the marker if any
                // registry or WinINet operation fails, so a later retry remains possible.
                if (STATIC_RestoreSystemProxy(false))
                    s_system_proxy_engaged.store(false, std::memory_order_release);
            }

            bool HttpProxy::RecoverSystemProxy() noexcept
            {
                // STATIC_RestoreSystemProxy is a no-op when no durable
                // snapshot exists.  It also performs compare-and-restore and
                // removes the record only after a verified restore.
                const bool restored = STATIC_RestoreSystemProxy(false);
                if (restored)
                    s_system_proxy_engaged.store(false, std::memory_order_release);
                return restored;
            }

            bool HttpProxy::OpenProxySettingsWindow() noexcept
            {
                ULONG dwMajor;
                ULONG dwMinor;
                ULONG dwBuildNumber;
                if (!Win32Native::RtlGetNtVersionNumbers(&dwMajor, &dwMinor, &dwBuildNumber))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32VersionQueryFailed);
                    return false;
                }

                if (dwMajor >= 10) // How-to: Quickly open control panel applets with ms-settings
                {                  // https://ss64.com/nt/syntax-settings.html
                    if (ShellExecuteA(NULLPTR, "open", "ms-settings:network-proxy", NULLPTR, NULLPTR, SW_SHOWNORMAL) != 0)
                    {
                        return true;
                    }
                }
                return OpenControlWindow(4);
            }

            bool HttpProxy::OpenControlWindow() noexcept
            {
                // control.exe inetcpl.cpl
                bool b = 0 != reinterpret_cast<INT_PTR>(ShellExecute(NULLPTR, TEXT("open"), TEXT("rundll32"), TEXT("shell32.dll,Control_RunDLL inetcpl.cpl"), NULLPTR, SW_SHOWNORMAL));
                if (!b)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxySettingsUiOpenFailed);
                }
                return b;
            }

            bool HttpProxy::OpenControlWindow(int TabIndex) noexcept
            {
                if (TabIndex < 0)
                {
                    TabIndex = 0;
                }

                ppp::string cmd = "shell32,Control_RunDLL inetcpl.cpl";
                if (TabIndex > 0)
                {
                    cmd += ",," + stl::to_string<ppp::string>(TabIndex);
                }

                // control.exe inetcpl.cpl
                bool b = 0 != reinterpret_cast<INT_PTR>(ShellExecuteA(NULLPTR, "open", "rundll32", cmd.data(), NULLPTR, SW_SHOWNORMAL));
                if (!b)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxySettingsUiOpenFailed);
                }
                return b;
            }

            bool HttpProxy::IsSupportExperimentalQuicProtocol() noexcept
            {
                bool b = STATIC_IsSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE) ||
                    STATIC_IsSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME);
                return b;
            }

            bool HttpProxy::SetSupportExperimentalQuicProtocol(bool value) noexcept
            {
                bool b = STATIC_SetSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_EDGE, value);
                b |= STATIC_SetSupportExperimentalQuicProtocol(EXPERIMENTALQUICPROTOCOL_POLICIES_CHROME, value);
                return b;
            }

            bool HttpProxy::PreferredNetwork(bool in4or6) noexcept
            {
                DWORD dwFlags = in4or6 ? 0x20 : 0x00;
                bool b = ppp::win32::SetRegistryValueDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", L"DisabledComponents", dwFlags);
                if (!b)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }
                return b;
            }
        }
    }
}
