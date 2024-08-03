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
                    int Setup_Main(int argc, char** argv) noexcept;
                    BOOL IsWow64System() noexcept;
                    BOOL InstallLayeredServiceProvider(WCHAR* pwszPathName) noexcept;
                    BOOL UninstallLayeredServiceProvider() noexcept;
                }
            }
        }
    }
}