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
            };
        }
    }
}