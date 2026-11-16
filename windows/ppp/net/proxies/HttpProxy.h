#pragma once

#include <ppp/stdafx.h>

namespace ppp 
{
    namespace net
    {
        namespace proxies
        {
            class HttpProxy
            {
            public:
                static bool RefreshSystemProxy() noexcept;
                static bool SetSystemProxy(const ppp::string& server) noexcept;
                static bool SetSystemProxy(const ppp::string& server, const ppp::string& bypass) noexcept;
                static bool SetSystemProxy(const ppp::string& server, const ppp::string& pac, bool enable) noexcept;
                static bool SetSystemProxy(const std::wstring& server, const std::wstring& pac, bool enable) noexcept;
                static bool IsSupportExperimentalQuicProtocol() noexcept;
                static bool SetSupportExperimentalQuicProtocol(bool value) noexcept;
                static bool OpenProxySettingsWindow() noexcept;
                static bool OpenControlWindow() noexcept;
                static bool OpenControlWindow(int TabIndex) noexcept;
                static bool PreferredNetwork(bool in4or6) noexcept;

                // Emergency, allocation-free restore of the Windows system proxy.
                // Safe to call from an SEH unhandled-exception filter (crash path):
                // it only touches HKCU registry + WinINet via raw Win32 and is a no-op
                // unless this process previously engaged the system proxy.
                static void EmergencyRestoreSystemProxy() noexcept;

                // Replays the durable Core-side snapshot after the original
                // process has exited.  Unlike the emergency hook this is
                // intentionally callable by the independent recovery worker.
                // It compares the current values with the values OpenPPP2
                // applied and preserves the snapshot on conflicts/failure.
                static bool RecoverSystemProxy() noexcept;
            };
        }
    }
}
