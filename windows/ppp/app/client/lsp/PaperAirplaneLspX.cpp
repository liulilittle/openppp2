#include <stdio.h> 
#include <Winsock2.h> 
#include <Windows.h> 
#include <Ws2spi.h> 
#include <tchar.h> 
#include <Iphlpapi.h>
#include <Sporder.h>      // For WSCWriteProviderOrder function
#include <wscapi.h>

#include <iostream>
#include <memory>

#include "PaperAirplaneRoot.h"
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
                    // Hard-coded GUIDs for LSP to be installed, used when uninstalling
                    static GUID ProviderGuid[] =
                    {
                        GUID({ 0x70b2b755, 0xa09d, 0x4b5d,{ 0xba, 0xda, 0xdb, 0x70, 0xbb, 0x1a, 0xbb, 0x21 } }),
                        GUID({ 0x51361ede, 0xe7c4, 0x4598,{ 0xa1, 0x77, 0xf4, 0xc5, 0xe9, 0x1, 0x7c, 0x25 } }),
                    };

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

                    static BOOL UninstallProvider(GUID& providerGuid) noexcept
                    {
                        std::shared_ptr<WSAPROTOCOL_INFOW> pProtoInfo;
                        int nProtocols;
                        DWORD dwLayeredCatalogId;

                        // Get layered protocol's catalog ID by GUID
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
                            // Remove protocol chains
                            for (int i = 0; i < nProtocols; i++)
                            {
                                if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) &&
                                    (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                                {
                                    ::WSCDeinstallProvider(&pProtoInfo.get()[i].ProviderId, &nError);
                                }
                            }
                            // Remove layered protocol
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

                        DWORD dwLayeredCatalogId;       // Catalog ID of layered protocol

                        int nError;

                        // Find base protocols and store their information in array
                        // Enumerate all installed protocol providers
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

                        // Install our layered protocol and get dwLayeredCatalogId
                        // Copy a base protocol structure as template
                        WSAPROTOCOL_INFOW LayeredProtocolInfo;
                        memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));

                        // Modify protocol name, type, add PFL_HIDDEN flag
                        wcscpy(LayeredProtocolInfo.szProtocol, wszLSPName);
                        LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL; // 0;
                        LayeredProtocolInfo.dwProviderFlags |= PFL_HIDDEN;

                        // Install
                        if (::WSCInstallProvider(&providerGuid,
                            pwszPathName, &LayeredProtocolInfo, 1, &nError) == SOCKET_ERROR)
                        {
                            return FALSE;
                        }

                        // Enumerate protocols again to get layered protocol's catalog ID
                        pProtoInfo = GetProvider(&nProtocols);
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if (memcmp(&pProtoInfo.get()[i].ProviderId, &providerGuid, sizeof(providerGuid)) == 0)
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

                        DWORD dwIds[1000];
                        int nIndex = 0;

                        // Put our protocol chains first
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen > 1) &&
                                (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId))
                            {
                                dwIds[nIndex++] = pProtoInfo.get()[i].dwCatalogEntryId;
                            }
                        }

                        // Put other protocols after
                        for (int i = 0; i < nProtocols; i++)
                        {
                            if ((pProtoInfo.get()[i].ProtocolChain.ChainLen <= 1) ||
                                (pProtoInfo.get()[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId))
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

                        if (NULLPTR == pwszPathName)
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
                        if (NULLPTR == wszExePath)
                        {
                            return false;
                        }

                        DWORD dwExePathLength = (DWORD)wcslen(wszExePath);
                        DWORD dwPrevCat = 0;
                        DWORD dwPermittedLspCategories = 0x80000000;
                        INT nErrno = ERROR_SUCCESS;

                        int nErr = WSCSetApplicationCategory(wszExePath, dwExePathLength, NULLPTR, 0, dwPermittedLspCategories, &dwPrevCat, &nErrno);
                        return nErr == ERROR_SUCCESS;
                    }
                }
            }
        }
    }
}