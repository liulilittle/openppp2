#pragma once

#include <stdio.h>
#include <Winsock2.h> 

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace lsp
            {
                namespace paper_airplane
                {
                    bool NoLsp(const wchar_t* wszExePath) noexcept;
                    GUID GetProviderGuid() noexcept;
                    BOOL IsInstallProvider(BOOL b32) noexcept;
                    BOOL UninstallProvider(BOOL b32) noexcept;
                    BOOL InstallProvider(WCHAR* pwszPathName, BOOL b32) noexcept;
                }
            }
        }
    }
}