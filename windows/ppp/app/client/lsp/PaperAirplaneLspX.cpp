#include <stdio.h> 
#include <Winsock2.h> 
#include <Windows.h> 
#include <Ws2spi.h> 
#include <tchar.h> 
#include <Iphlpapi.h>
#include <Sporder.h>      // 定义了WSCWriteProviderOrder函数 
#include <wscapi.h>

#include <iostream>
#include <memory>

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
                    // 要安装的LSP的硬编码，在移除的时候还要使用它 
                    static GUID ProviderGuid[] =
                    {
                        GUID({ 0x70b2b755, 0xa09d, 0x4b5d,{ 0xba, 0xda, 0xdb, 0x70, 0xbb, 0x1a, 0xbb, 0x21 } }),
                        GUID({ 0x51361ede, 0xe7c4, 0x4598,{ 0xa1, 0x77, 0xf4, 0xc5, 0xe9, 0x1, 0x7c, 0x25 } }),
                    };

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

                    static BOOL UninstallProvider(GUID& providerGuid) noexcept
                    {
                        std::shared_ptr<WSAPROTOCOL_INFOW> pProtoInfo;
                        int nProtocols;
                        DWORD dwLayeredCatalogId;

                        // 根据Guid取得分层协议的目录ID号 
                        pProtoInfo = GetProvider(&nProtocols);
                        int nError, i;
                        for (i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&providerGuid, &pProtoInfo.get()[i].ProviderId, sizeof(providerGuid)) == 0)
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
                                if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) &&
                                    (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                                {
                                    ::WSCDeinstallProvider(&pProtoInfo.get()[i].ProviderId, &nError);
                                }
                            }
                            // 移除分层协议 
                            ::WSCDeinstallProvider(&providerGuid, &nError);
                        }

                        return TRUE;
                    }

                    static BOOL InstallProvider(GUID& providerGuid, WCHAR* pwszPathName) noexcept
                    {
                        WCHAR wszLSPName[] = L"PaperAirplane";
                        std::shared_ptr<WSAPROTOCOL_INFOW> pProtoInfo;
                        int nProtocols;
                        WSAPROTOCOL_INFOW OriginalProtocolInfo[3];
                        DWORD            dwOrigCatalogId[3];
                        int nArrayCount = 0;

                        DWORD dwLayeredCatalogId;       // 我们分层协议的目录ID号 

                        int nError;

                        // 找到我们的下层协议，将信息放入数组中 
                        // 枚举所有服务程序提供者 
                        pProtoInfo = GetProvider(&nProtocols);
                        BOOL bFindUdp = FALSE;
                        BOOL bFindTcp = FALSE;
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (pProtoInfo.get()[i].iAddressFamily == AF_INET)
                            {
                                if (!bFindUdp && pProtoInfo.get()[i].iProtocol == IPPROTO_UDP)
                                {
                                    memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo.get()[i], sizeof(WSAPROTOCOL_INFOW));
                                    OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
                                        OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

                                    dwOrigCatalogId[nArrayCount++] = pProtoInfo.get()[i].dwCatalogEntryId;

                                    bFindUdp = TRUE;
                                }

                                if (!bFindTcp && pProtoInfo.get()[i].iProtocol == IPPROTO_TCP)
                                {
                                    memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo.get()[i], sizeof(WSAPROTOCOL_INFOW));
                                    OriginalProtocolInfo[nArrayCount].dwServiceFlags1 =
                                        OriginalProtocolInfo[nArrayCount].dwServiceFlags1 & (~XP1_IFS_HANDLES);

                                    dwOrigCatalogId[nArrayCount++] = pProtoInfo.get()[i].dwCatalogEntryId;

                                    bFindTcp = TRUE;
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
                        if (::WSCInstallProvider(&providerGuid,
                            pwszPathName, &LayeredProtocolInfo, 1, &nError) == SOCKET_ERROR)
                        {
                            return FALSE;
                        }

                        // 重新枚举协议，获取分层协议的目录ID号 
                        pProtoInfo = GetProvider(&nProtocols);
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&pProtoInfo.get()[i].ProviderId, &providerGuid, sizeof(providerGuid)) == 0)
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
                            else if (OriginalProtocolInfo[i].iProtocol == IPPROTO_UDP)
                            {
                                swprintf(wszChainName, L"%ws %ws", wszLSPName, L"Tcpip [UDP/IP]");
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

                        DWORD dwIds[1000];
                        int nIndex = 0;

                        // 添加我们的协议链 
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) &&
                                (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // 添加其它协议 
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen <= 1) ||
                                (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
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
                        if (WSCGetProviderInfo(&providerGuid, ProviderInfoLspCategories, (PBYTE)&nCategories, &nCategoriesSize, 0, &nError) == ERROR_SUCCESS)
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

                            WSCSetProviderInfo(&providerGuid, ProviderInfoLspCategories, (PBYTE)&nCategories, nCategoriesSize, 0, &nError);
                        }

                        return TRUE;
                    }

                    BOOL InstallProvider(WCHAR* pwszPathName, BOOL b32) noexcept
                    {
                        if (IsInstallProvider(b32))
                        {
                            return TRUE;
                        }

                        if (NULL == pwszPathName)
                        {
                            pwszPathName = (WCHAR*)L"%SystemRoot%\\System32\\PaperAirplane.dll";
                        }

                        if (b32)
                        {
                            return InstallProvider(ProviderGuid[0], pwszPathName);
                        }
                        else
                        {
                            return InstallProvider(ProviderGuid[1], pwszPathName);
                        }
                    }

                    BOOL UninstallProvider(BOOL b32) noexcept
                    {
                        if (!IsInstallProvider(b32))
                        {
                            return FALSE;
                        }
                        if (b32)
                        {
                            return UninstallProvider(ProviderGuid[0]);
                        }
                        else
                        {
                            return UninstallProvider(ProviderGuid[1]);
                        }
                    }

                    BOOL IsInstallProvider(BOOL b32) noexcept
                    {
                        INT nCategories = 0;
                        INT nError = 0;
                        size_t nCategoriesSize = 4;
                        if (b32)
                        {
                            int rc = WSCGetProviderInfo(&ProviderGuid[0],
                                ProviderInfoLspCategories, (PBYTE)&nCategories, &nCategoriesSize, 0, &nError);
                            if (rc != ERROR_SUCCESS)
                            {
                                return FALSE;
                            }
                        }
                        else
                        {
                            int rc = WSCGetProviderInfo(&ProviderGuid[1],
                                ProviderInfoLspCategories, (PBYTE)&nCategories, &nCategoriesSize, 0, &nError);
                            if (rc != ERROR_SUCCESS)
                            {
                                return FALSE;
                            }
                        }
                        return nError == ERROR_SUCCESS ? TRUE : FALSE;
                    }

                    GUID GetProviderGuid() noexcept
                    {
                        return sizeof(HANDLE) < 8 ? ProviderGuid[0] : ProviderGuid[1];
                    }

                    bool NoLsp(const wchar_t* wszExePath) noexcept
                    {
                        if (NULL == wszExePath)
                        {
                            return false;
                        }

                        DWORD dwExePathLength = (DWORD)wcslen(wszExePath);
                        DWORD dwPrevCat = 0;
                        DWORD dwPermittedLspCategories = 0x80000000;
                        LPINT lpErrno = NULL;

                        int nErr = WSCSetApplicationCategory(wszExePath, dwExePathLength, NULL, 0, dwPermittedLspCategories, &dwPrevCat, lpErrno);
                        return nErr == ERROR_SUCCESS;
                    }
                }
            }
        }
    }
}