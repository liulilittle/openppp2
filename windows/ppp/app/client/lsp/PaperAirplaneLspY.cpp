#include <stdio.h> 
#include <Winsock2.h> 
#include <Windows.h> 
#include <Ws2spi.h> 
#include <tchar.h> 
#include <Iphlpapi.h>
#include <Sporder.h>      // 定义了WSCWriteProviderOrder函数 

#include <iostream>
#include <memory>

#include "PaperAirplaneLspY.h"
#include "PaperAirplaneLspX.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Rpcrt4.lib")  // 实现了UuidCreate

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
                        if (NULL != pProtoInfo)
                        {
                            ::GlobalFree(pProtoInfo);
                        }
                    }

                    static std::shared_ptr<WSAPROTOCOL_INFOW> GetProvider(LPINT lpnTotalProtocols) noexcept
                    {
                        DWORD dwSize = 0;
                        int nError;
                        LPWSAPROTOCOL_INFOW pProtoInfo = NULL;

                        // 取得需要的长度 
                        if (::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError) == SOCKET_ERROR)
                        {
                            if (nError != WSAENOBUFS)
                            {
                                return NULL;
                            }
                        }

                        pProtoInfo = (LPWSAPROTOCOL_INFOW)::GlobalAlloc(GPTR, dwSize);
                        *lpnTotalProtocols = ::WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError);

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

                        DWORD dwLayeredCatalogId;       // 我们分层协议的目录ID号 

                        int nError;
                        BOOL bFindTcp = FALSE;

                        // 找到我们的下层协议，将信息放入数组中 
                        // 枚举所有服务程序提供者 
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

                        // 安装我们的分层协议，获取一个dwLayeredCatalogId 
                        // 随便找一个下层协议的结构复制过来即可 
                        WSAPROTOCOL_INFOW LayeredProtocolInfo;
                        memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));

                        // 修改协议名称，类型，设置PFL_HIDDEN标志 
                        wcscpy(LayeredProtocolInfo.szProtocol, wszLSPName);
                        LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL; // 0; 
                        LayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;

                        // 安装 
                        GUID ProviderGuid = GetProviderGuid();
                        if (::WSCInstallProvider(&ProviderGuid,
                            pwszPathName, &LayeredProtocolInfo, 1, &nError) == SOCKET_ERROR)
                        {
                            return FALSE;
                        }

                        // 重新枚举协议，获取分层协议的目录ID号 
                        pProtoInfo = GetProvider(&nProtocols);
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&pProtoInfo.get()[i].ProviderId, &ProviderGuid, sizeof(ProviderGuid)) == 0)
                            {
                                dwLayeredCatalogId = pProtoInfo.get()[i].dwCatalogEntryId;
                                break;
                            }
                        }

                        // 安装协议链 
                        // 修改协议名称，类型 
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

                        // 获取一个Guid，安装之 
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

                        // 重新排序Winsock目录，将我们的协议链提前 
                        // 重新枚举安装的协议 
                        pProtoInfo = GetProvider(&nProtocols);

                        DWORD dwIds[100];
                        int nIndex = 0;

                        // 添加我们的协议链 
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) && (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // 添加其它协议 
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen <= 1) || (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // 重新排序Winsock目录 
                        if ((nError = ::WSCWriteProviderOrder(dwIds, nIndex)) != ERROR_SUCCESS)
                        {
                            return FALSE;
                        }

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

                        // 根据Guid取得分层协议的目录ID号 
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
                            // 移除协议链 
                            for (int i = 0; i < nProtocols; i++)
                            {
                                if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) && (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                                {
                                    ::WSCDeinstallProvider(&pProtoInfo.get()[i].ProviderId, &nError);
                                }
                            }

                            // 移除分层协议 
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

#ifdef _SYSPROXY32
int main(int argc, char** argv) noexcept
{
    return ppp::app::client::lsp::paper_airplane::Setup_Main(argc, argv);
}
#endif