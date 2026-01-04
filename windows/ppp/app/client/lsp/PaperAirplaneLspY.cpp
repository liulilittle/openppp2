#include <stdio.h> 
#include <Winsock2.h> 
#include <Windows.h> 
#include <Ws2spi.h> 
#include <tchar.h> 
#include <Iphlpapi.h>
#include <Sporder.h>      // For WSCWriteProviderOrder function

#include <iostream>
#include <memory>

#include "PaperAirplaneRoot.h"
#include "PaperAirplaneLspY.h"
#include "PaperAirplaneLspX.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Rpcrt4.lib")  // For UuidCreate

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
                    static void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo) noexcept
                    {
                        if (NULLPTR != pProtoInfo)
                        {
                            ::GlobalFree(pProtoInfo);
                        }
                    }

                    static std::shared_ptr<WSAPROTOCOL_INFOW> GetProvider(LPINT lpnTotalProtocols) noexcept
                    {
                        DWORD dwSize = 0;
                        int nError;
                        LPWSAPROTOCOL_INFOW pProtoInfo = NULLPTR;

                        // Get required buffer size
                        if (::WSCEnumProtocols(NULLPTR, pProtoInfo, &dwSize, &nError) == SOCKET_ERROR)
                        {
                            if (nError != WSAENOBUFS)
                            {
                                return NULLPTR;
                            }
                        }

                        pProtoInfo = (LPWSAPROTOCOL_INFOW)::GlobalAlloc(GPTR, dwSize);
                        *lpnTotalProtocols = ::WSCEnumProtocols(NULLPTR, pProtoInfo, &dwSize, &nError);

                        return std::shared_ptr<WSAPROTOCOL_INFOW>(pProtoInfo,
                            [](WSAPROTOCOL_INFOW* p) noexcept
                            {
                                FreeProvider(p);
                            });
                    }

                    BOOL InstallLayeredServiceProvider(WCHAR* pwszPathName) noexcept
                    {
                        UninstallLayeredServiceProvider();

                        WCHAR wszLSPName[] = L"PaperAirplane";
                        std::shared_ptr<WSAPROTOCOL_INFOW> pProtoInfo;
                        int nProtocols;
                        WSAPROTOCOL_INFOW OriginalProtocolInfo[3];
                        DWORD            dwOrigCatalogId[3];
                        int nArrayCount = 0;

                        DWORD dwLayeredCatalogId;       // Catalog ID of layered protocol

                        int nError;
                        BOOL bFindTcp = FALSE;

                        // Find base protocols and store their information in array
                        // Enumerate all installed protocol providers
                        pProtoInfo = GetProvider(&nProtocols);
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (pProtoInfo.get()[i].iAddressFamily == AF_INET)
                            {
                                if (!bFindTcp && pProtoInfo.get()[i].iProtocol == IPPROTO_TCP)
                                {
                                    bFindTcp = TRUE;
                                    {
                                        memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo.get()[i], sizeof(WSAPROTOCOL_INFOW));
                                        OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
                                            OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);
                                    }
                                    dwOrigCatalogId[nArrayCount++] = pProtoInfo.get()[i].dwCatalogEntryId;
                                }
                            }
                        }

                        // Install our layered protocol and get dwLayeredCatalogId
                        // Copy a base protocol structure as template
                        WSAPROTOCOL_INFOW LayeredProtocolInfo;
                        memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));

                        // Modify protocol name, type, add PFL_HIDDEN flag
                        wcscpy(LayeredProtocolInfo.szProtocol, wszLSPName);
                        LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL; // 0;
                        LayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;

                        // Install
                        GUID ProviderGuid = GetProviderGuid();
                        if (::WSCInstallProvider(&ProviderGuid,
                            pwszPathName, &LayeredProtocolInfo, 1, &nError) == SOCKET_ERROR)
                        {
                            return FALSE;
                        }

                        // Enumerate protocols again to get layered protocol's catalog ID
                        pProtoInfo = GetProvider(&nProtocols);
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&pProtoInfo.get()[i].ProviderId, &ProviderGuid, sizeof(ProviderGuid)) == 0)
                            {
                                dwLayeredCatalogId = pProtoInfo.get()[i].dwCatalogEntryId;
                                break;
                            }
                        }

                        // Install protocol chain
                        // Modify protocol name, chain
                        WCHAR wszChainName[WSAPROTOCOL_LEN + 1];
                        for (int i = 0; i < nArrayCount; i++)
                        {
                            if (OriginalProtocolInfo[i].iProtocol == IPPROTO_TCP)
                            {
                                swprintf(wszChainName, L"%ws %ws", wszLSPName, L"Tcpip [TCP/IP]");
                            }

                            wcscpy(OriginalProtocolInfo[i].szProtocol, wszChainName);
                            if (OriginalProtocolInfo[i].ProtocolChain.ChainLen == 1)
                            {
                                OriginalProtocolInfo[i].ProtocolChain.ChainEntries[1] = dwOrigCatalogId[i];
                            }
                            else
                            {
                                for (int j = OriginalProtocolInfo[i].ProtocolChain.ChainLen; j > 0; j--)
                                {
                                    OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j]
                                        = OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j - 1];
                                }
                            }
                            OriginalProtocolInfo[i].ProtocolChain.ChainLen++;
                            OriginalProtocolInfo[i].ProtocolChain.ChainEntries[0] = dwLayeredCatalogId;
                        }

                        // Generate a GUID and install protocol chain
                        GUID ProviderChainGuid;
                        if (::UuidCreate(&ProviderChainGuid) == RPC_S_OK)
                        {
                            if (::WSCInstallProvider(&ProviderChainGuid,
                                pwszPathName, OriginalProtocolInfo, nArrayCount, &nError) == SOCKET_ERROR)
                            {
                                return FALSE;
                            }
                        }
                        else
                        {
                            return FALSE;
                        }

                        // Reorder Winsock catalog to put our protocol chain first
                        // Enumerate installed protocols again
                        pProtoInfo = GetProvider(&nProtocols);

                        DWORD dwIds[100];
                        int nIndex = 0;

                        // Put our protocol chains first
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) && (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // Put other protocols after
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen <= 1) || (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // Reorder Winsock catalog
                        if ((nError = ::WSCWriteProviderOrder(dwIds, nIndex)) != ERROR_SUCCESS)
                        {
                            return FALSE;
                        }

                        // Set LSP categories
                        INT nCategories = 0;
                        size_t nCategoriesSize = 4;
                        if (WSCGetProviderInfo(&ProviderGuid, ProviderInfoLspCategories, (PBYTE)&nCategories, &nCategoriesSize, 0, &nError) == ERROR_SUCCESS)
                        {
                            nCategories |= LSP_SYSTEM
                                | LSP_INSPECTOR
                                | LSP_REDIRECTOR
                                | LSP_PROXY
                                | LSP_FIREWALL
                                | LSP_INBOUND_MODIFY
                                | LSP_OUTBOUND_MODIFY
                                | LSP_CRYPTO_COMPRESS
                                | LSP_LOCAL_CACHE;

                            WSCSetProviderInfo(&ProviderGuid, ProviderInfoLspCategories, (PBYTE)&nCategories, nCategoriesSize, 0, &nError);
                        }

                        return TRUE;
                    }

                    BOOL UninstallLayeredServiceProvider() noexcept
                    {
                        std::shared_ptr<WSAPROTOCOL_INFOW> pProtoInfo;
                        int nProtocols;
                        DWORD dwLayeredCatalogId;

                        GUID ProviderGuid = GetProviderGuid();
                        pProtoInfo = GetProvider(&nProtocols);

                        // Get layered protocol's catalog ID by GUID
                        int nError, i;
                        for (i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&ProviderGuid, &pProtoInfo.get()[i].ProviderId, sizeof(ProviderGuid)) == 0)
                            {
                                dwLayeredCatalogId = pProtoInfo.get()[i].dwCatalogEntryId;
                                break;
                            }
                        }

                        if (i < nProtocols)
                        {
                            // Remove protocol chains
                            for (int i = 0; i < nProtocols; i++)
                            {
                                if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) && (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                                {
                                    ::WSCDeinstallProvider(&pProtoInfo.get()[i].ProviderId, &nError);
                                }
                            }

                            // Remove layered protocol
                            ::WSCDeinstallProvider(&ProviderGuid, &nError);
                        }

                        return TRUE;
                    }

                    BOOL IsWow64System() noexcept
                    {
                        SYSTEM_INFO stInfo = { 0 };
                        GetNativeSystemInfo(&stInfo);

                        if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
                            || stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
                        {
                            return TRUE;
                        }
                        return FALSE;
                    }

                    static void Setup_Install() noexcept
                    {
                        WCHAR path[MAX_PATH] = L"%SystemRoot%\\system32\\PaperAirplane.dll";
                        if (!InstallLayeredServiceProvider(path))
                        {
                            printf("%s\r\n", "0");
                        }
                        else
                        {
                            printf("%s\r\n", "1");
                        }
                    }

                    static void Setup_Uninstall() noexcept
                    {
                        if (!UninstallLayeredServiceProvider())
                        {
                            fprintf(stdout, "%s\r\n", "0");
                        }
                        else
                        {
                            fprintf(stdout, "%s\r\n", "1");
                        }
                    }

                    static void Setup_Usage(char* progname) noexcept
                    {
                        printf("usage: %s install | uninstall\r\n", progname);
                        system("pause");
                        ExitProcess(-1);
                    }

                    int Setup_Main(int argc, char** argv) noexcept
                    {
                        WSADATA wsd;
                        char* ptr;
                        if (argc != 2)
                        {
                            Setup_Usage(argv[0]);
                            return -1;
                        }

                        if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
                        {
                            printf("WSAStartup() failed: %d\r\n", GetLastError());
                            return -1;
                        }

                        ptr = argv[1];
                        while (*ptr)
                        {
                            *ptr++ = tolower(*ptr);
                        }

                        if (!strncmp(argv[1], "install", 8))
                        {
                            Setup_Install();
                        }
                        else if (!strncmp(argv[1], "uninstall", 10))
                        {
                            Setup_Uninstall();
                        }
                        else
                        {
                            Setup_Usage(argv[0]);
                        }

                        WSACleanup();
                        return 0;
                    }
                }
            }
        }
    }
}

#if defined(_SYSPROXY32)
int main(int argc, char** argv) noexcept
{
    return ppp::app::client::lsp::paper_airplane::Setup_Main(argc, argv);
}
#endif