#include <ws2spi.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <malloc.h>
#include <tchar.h>
#include <limits.h>
#include <winsock2.h>

#include <iostream>
#include <hash_map>
#include <hash_set>
#include <vector>
#include <string>

#include "PaperAirplaneRoot.h"
#include "PaperAirplaneLspX.h"

#pragma warning(push)
#pragma warning(disable: 4312)
#pragma warning(disable: 4800)

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "WinMM.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifndef PAPERAIRPLANE_CONFIGURATION_NM
#define PAPERAIRPLANE_CONFIGURATION_NM "PAPERAIRPLANE_CONFIGURATION"
#endif

#ifndef PAPERAIRPLANE_CONFIGURATION_KF_1
#define PAPERAIRPLANE_CONFIGURATION_KF_1 0xFFBADD11
#endif

#ifndef PAPERAIRPLANE_CONFIGURATION_KF_2
#define PAPERAIRPLANE_CONFIGURATION_KF_2 0xE011CFD0
#endif

#ifndef PAPERAIRPLANE_CONFIGURATION_ADD_PORT_FORWARD
#define PAPERAIRPLANE_CONFIGURATION_ADD_PORT_FORWARD 0x2A2B7C1E
#endif

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
                    class Debugger final
                    {
                    public:
                        static void                                             Write(LPCWSTR fmt, ...) noexcept;
                        static void                                             Write(LPCSTR fmt, ...) noexcept;
                    };

                    void                                                        Debugger::Write(LPCWSTR fmt, ...) noexcept
                    {
                        WCHAR message[1024];
                        wvsprintfW(message, fmt, va_list(&fmt + 1));
                        StrCatBuffW(message, L"\r\n", sizeof(message));

                        OutputDebugStringW(message);
                    }

                    void                                                        Debugger::Write(LPCSTR fmt, ...) noexcept
                    {
                        CHAR message[1024];
                        wvsprintfA(message, fmt, va_list(&fmt + 1));
                        strncat(message, fmt, sizeof(message));

                        OutputDebugStringA(message);
                    }

                    typedef void (WSPAPI* StartLspCompletedEventHandler)(WSPPROC_TABLE* sender, WSPPROC_TABLE* e);

                    static class LayeredServiceProvider final
                    {
                    private:
                        WSAPROTOCOL_INFOW*                                      ProtoInfo;
                        DWORD                                                   ProtoInfoSize;
                        int                                                     TotalProtos;
                        GUID                                                    filterguid;

                    private:
                        BOOL                                                    Load() noexcept
                        {
                            int error;
                            ProtoInfo = NULL;
                            ProtoInfoSize = 0;
                            TotalProtos = 0;

                            if (WSCEnumProtocols(NULL, ProtoInfo, &ProtoInfoSize, &error) == SOCKET_ERROR)
                            {
                                if (error != WSAENOBUFS)
                                {
                                    Debugger::Write(L"First WSCEnumProtocols Error!");
                                    return FALSE;
                                }
                            }

                            if ((ProtoInfo = (LPWSAPROTOCOL_INFOW)GlobalAlloc(GPTR, ProtoInfoSize)) == NULL)
                            {
                                Debugger::Write(L"GlobalAlloc Error!");
                                return FALSE;
                            }

                            if ((TotalProtos = WSCEnumProtocols(NULL, ProtoInfo, &ProtoInfoSize, &error)) == SOCKET_ERROR)
                            {
                                Debugger::Write(L"Second WSCEnumProtocols Error!");
                                return FALSE;
                            }
                            return TRUE;
                        }
                        void                                                    Free() noexcept // 释放内存
                        {
                            if (ProtoInfo != NULL && GlobalSize(ProtoInfo) > 0)
                            {
                                GlobalFree(ProtoInfo);
                                ProtoInfo = NULL;
                            }
                        }

                    public:
                        StartLspCompletedEventHandler                           StartProviderCompleted;
                        WSPPROC_TABLE                                           NextProcTable;

                    public:
                        LayeredServiceProvider() noexcept
                        {
                            filterguid = GetProviderGuid();
                            TotalProtos = 0;
                            ProtoInfoSize = 0;
                            ProtoInfo = NULL;
                            StartProviderCompleted = NULL;
                        }

                    public:
                        int                                                     Start(
                            WORD                                                wversionrequested,
                            LPWSPDATA                                           lpwspdata,
                            LPWSAPROTOCOL_INFOW                                 lpProtoInfo,
                            WSPUPCALLTABLE                                      upcalltable,
                            LPWSPPROC_TABLE                                     lpproctable) noexcept
                        {
                            LayeredServiceProvider::Free();
                            {
                                int i;
                                int errorcode;
                                int filterpathlen;
                                DWORD layerid = 0;
                                DWORD nextlayerid = 0;
                                WCHAR* filterpath;
                                HINSTANCE hfilter;
                                LPWSPSTARTUP wspstartupfunc = NULL;
                                if (lpProtoInfo->ProtocolChain.ChainLen <= 1)
                                {
                                    Debugger::Write(L"ChainLen<=1");
                                    return FALSE;
                                }

                                LayeredServiceProvider::Load();
                                for (i = 0; i < TotalProtos; i++)
                                {
                                    if (memcmp(&ProtoInfo[i].ProviderId, &filterguid, sizeof(GUID)) == 0)
                                    {
                                        layerid = ProtoInfo[i].dwCatalogEntryId;
                                        break;
                                    }
                                }

                                for (i = 0; i < lpProtoInfo->ProtocolChain.ChainLen; i++)
                                {
                                    if (lpProtoInfo->ProtocolChain.ChainEntries[i] == layerid)
                                    {
                                        nextlayerid = lpProtoInfo->ProtocolChain.ChainEntries[i + 1];
                                        break;
                                    }
                                }

                                filterpathlen = MAX_PATH;
                                filterpath = (WCHAR*)GlobalAlloc(GPTR, filterpathlen);
                                for (i = 0; i < TotalProtos; i++)
                                {
                                    if (nextlayerid == ProtoInfo[i].dwCatalogEntryId)
                                    {
                                        if (WSCGetProviderPath(&ProtoInfo[i].ProviderId, filterpath, &filterpathlen, &errorcode) == SOCKET_ERROR)
                                        {
                                            Debugger::Write(L"WSCGetProviderPath Error!");
                                            return WSAEPROVIDERFAILEDINIT;
                                        }
                                        break;
                                    }
                                }

                                if (!ExpandEnvironmentStringsW(filterpath, filterpath, MAX_PATH))
                                {
                                    Debugger::Write(L"ExpandEnvironmentStrings Error!");
                                    return WSAEPROVIDERFAILEDINIT;
                                }

                                if ((hfilter = LoadLibraryW(filterpath)) == NULL)
                                {
                                    Debugger::Write(L"LoadLibrary Error!");
                                    return WSAEPROVIDERFAILEDINIT;
                                }

                                if ((wspstartupfunc = (LPWSPSTARTUP)GetProcAddress(hfilter, "WSPStartup")) == NULL)
                                {
                                    Debugger::Write(L"GetProcessAddress Error!");
                                    return WSAEPROVIDERFAILEDINIT;
                                }

                                if ((errorcode = wspstartupfunc(wversionrequested, lpwspdata, lpProtoInfo, upcalltable, lpproctable)) != ERROR_SUCCESS)
                                {
                                    Debugger::Write(L"wspstartupfunc Error!");
                                    return errorcode;
                                }

                                NextProcTable = *lpproctable; // 保存原来的入口函数表
                                if (StartProviderCompleted != NULL)
                                {
                                    StartProviderCompleted(&NextProcTable, lpproctable);
                                }
                            }
                            LayeredServiceProvider::Free();
                            return 0;
                        }
                    }                                                           LayeredServiceProvider_Current;

                    static VOID*                                                GetExtensionFunction(SOCKET s, GUID* clasid) noexcept
                    {
                        if (NULL == clasid || s == INVALID_SOCKET)
                        {
                            return NULL;
                        }

                        VOID* func = NULL;
                        DWORD size = 0;

                        //
                        WSATHREADID threadid;
                        threadid.ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
                        threadid.Reserved = NULL;

                        INT error = 0;
                        if (LayeredServiceProvider_Current.NextProcTable.lpWSPIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, clasid,
                            sizeof(GUID), &func, sizeof(VOID*), &size, NULL, NULL, &threadid, &error) == SOCKET_ERROR)
                        {
                            CloseHandle(threadid.ThreadHandle);
                            return NULL;
                        }

                        CloseHandle(threadid.ThreadHandle);
                        return func;
                    }

                    static VOID*                                                GetExtensionFunction(GUID* clasid) noexcept
                    {
                        if (NULL == clasid)
                        {
                            return NULL;
                        }

                        INT error = 0;
                        SOCKET s = LayeredServiceProvider_Current.NextProcTable.lpWSPSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED, &error);
                        if (s == INVALID_SOCKET)
                        {
                            return NULL;
                        }

                        VOID* func = GetExtensionFunction(s, clasid);
                        LayeredServiceProvider_Current.NextProcTable.lpWSPShutdown(s, SD_BOTH, &error);
                        LayeredServiceProvider_Current.NextProcTable.lpWSPCloseSocket(s, &error);
                        return func;
                    }

                    static VOID*                                                GetExtensionFunction(SOCKET s, GUID clasid) noexcept
                    {
                        return GetExtensionFunction(s, &clasid);
                    }

                    static VOID*                                                GetExtensionFunction(GUID clasid) noexcept
                    {
                        return GetExtensionFunction(&clasid);
                    }

                    static LPFN_CONNECTEX                                       PFN_ConnectEx = NULL;
                    static class ConnectionTable final
                    {
                        typedef std::hash_map<UINT64, struct sockaddr_in>       AddressTable;

                    public:
                        BOOL                                                    FindAddress(SOCKET s, struct sockaddr* name, LPINT namelen) noexcept
                        {
                            std::lock_guard<std::mutex> scope(_cs);
                            AddressTable::iterator tail = this->_addressTable.find(s);
                            AddressTable::iterator endl = this->_addressTable.end();
                            if (tail == endl)
                            {
                                return FALSE;
                            }

                            if (NULL != namelen)
                            {
                                *namelen = sizeof(struct sockaddr_in);
                            }

                            if (NULL != name)
                            {
                                *(struct sockaddr_in*)name = tail->second;
                            }
                            return TRUE;
                        }
                        BOOL                                                    RemoveAddress(SOCKET s) noexcept
                        {
                            std::lock_guard<std::mutex> scope(_cs);
                            AddressTable::iterator tail = this->_addressTable.find(s);
                            AddressTable::iterator endl = this->_addressTable.end();
                            if (tail == endl)
                            {
                                return FALSE;
                            }

                            this->_addressTable.erase(tail);
                            return TRUE;
                        }
                        BOOL                                                    AddAddress(SOCKET s, const struct sockaddr* name) noexcept
                        {
                            if (NULL == name || name->sa_family != AF_INET) 
                            {
                                return FALSE;
                            }

                            std::lock_guard<std::mutex> scope(_cs);
                            this->_addressTable[s] = *(struct sockaddr_in*)name;
                            return TRUE;
                        }

                    private:
                        AddressTable                                            _addressTable;
                        std::mutex                                              _cs;
                    }                                                           ConnectionTable_Current;

                    static BOOL PASCAL                                          WSPConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) noexcept
                    {
                        if (NULL == PFN_ConnectEx) 
                        {
                            GUID metid = WSAID_CONNECTEX;
                            PFN_ConnectEx = (LPFN_CONNECTEX)GetExtensionFunction(s, metid);
                            if (NULL == PFN_ConnectEx) 
                            {
                                return FALSE;
                            }
                        }

                        auto [port, host] = GetForwardPort((void*)s, name, namelen);
                        if (port > 0 && port <= UINT16_MAX)
                        {
                            struct sockaddr_in server;
                            ZeroMemory(&server, sizeof(struct sockaddr_in));

                            server.sin_family = AF_INET;
                            server.sin_port = htons(port); // PORT
                            server.sin_addr.s_addr = host;

                            return PFN_ConnectEx(s, (struct sockaddr*)&server, sizeof(struct sockaddr_in), lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
                        }
                        return PFN_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
                    }

                    static int WSPAPI                                           WSPGetPeerName(SOCKET s, struct sockaddr* name, LPINT namelen, LPINT lpErrno)
                    {
                        if (ConnectionTable_Current.FindAddress(s, name, namelen)) 
                        {
                            if (NULL != lpErrno) 
                            {
                                *lpErrno = ERROR_SUCCESS;
                            }
                            return ERROR_SUCCESS;
                        }
                        return LayeredServiceProvider_Current.NextProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);
                    }

                    static int WSPAPI                                           WSPIoctl(SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer, DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                        LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine, LPWSATHREADID lpThreadId, LPINT lpErrno) noexcept
                    {
                        if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER) 
                        {
                            GUID connectex = WSAID_CONNECTEX;
                            if (memcmp(lpvInBuffer, &connectex, sizeof(GUID)) == 0) 
                            {
                                *((LPFN_CONNECTEX*)lpvOutBuffer) = &WSPConnectEx;
                                *lpcbBytesReturned = sizeof(HANDLE);
                                *lpErrno = NO_ERROR;
                                return NO_ERROR;
                            }
                        }
                        return LayeredServiceProvider_Current.NextProcTable.lpWSPIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer
                            , lpcbBytesReturned, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
                    }

                    static int WSPAPI                                           WSPCloseSocket(SOCKET s, LPINT lpErrno) noexcept
                    {
                        if (ConnectionTable_Current.RemoveAddress(s)) 
                        {
                            if (NULL != lpErrno) 
                            {
                                *lpErrno = ERROR_SUCCESS;
                            }
                            return ERROR_SUCCESS;
                        }
                        return LayeredServiceProvider_Current.NextProcTable.lpWSPCloseSocket(s, lpErrno);
                    }

                    static int WSPAPI                                           WSPConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS,
                        LPQOS lpGQOS, LPINT lpErrno) noexcept
                    {
                        auto [port, host] = GetForwardPort((void*)s, name, namelen);
                        if (port > 0 && port <= UINT16_MAX) 
                        {
                            struct sockaddr_in server;
                            ZeroMemory(&server, sizeof(struct sockaddr_in));

                            server.sin_family = AF_INET;
                            server.sin_port = htons(port); // PORT
                            server.sin_addr.s_addr = host;

                            ConnectionTable_Current.AddAddress(s, name);
                            return LayeredServiceProvider_Current.NextProcTable.lpWSPConnect(s, (struct sockaddr*)&server, sizeof(struct sockaddr_in),
                                lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
                        }
                        return LayeredServiceProvider_Current.NextProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
                    }

                    static void WSPAPI                                          StartProviderCompleted(WSPPROC_TABLE* sender, WSPPROC_TABLE* e) noexcept
                    {
                        if (NULL != e) 
                        {
                            e->lpWSPIoctl = &WSPIoctl;
                            e->lpWSPConnect = &WSPConnect;
                            e->lpWSPGetPeerName = &WSPGetPeerName;
                            e->lpWSPCloseSocket = &WSPCloseSocket;
                        }
                    }

                    static int WSPAPI                                           WSPStartupInit(WORD wversionrequested, LPWSPDATA lpwspdata, LPWSAPROTOCOL_INFOW lpProtoInfo, WSPUPCALLTABLE upcalltable, LPWSPPROC_TABLE lpproctable) noexcept
                    {
                        TCHAR process_name[MAX_PATH];
                        GetModuleFileName(NULL, process_name, MAX_PATH);
                        Debugger::Write(L"[PaperAirplane]%s Loading WSPStartup ...", process_name);

                        LayeredServiceProvider_Current.StartProviderCompleted = &StartProviderCompleted;
                        return LayeredServiceProvider_Current.Start(wversionrequested, lpwspdata, lpProtoInfo, upcalltable, lpproctable);
                    }

#pragma pack(push, 1)
                    typedef struct
                    {
                        uint32_t                                                cmd;
                        uint32_t                                                destinationIP;
                        uint16_t                                                destinationPort;
                        uint32_t                                                localIP;
                        uint32_t                                                localPort;
                    } PaperAirplaneControl_AddPortForwardProtocol;
#pragma pack(pop)

                    PaperAirplaneControlBlockPort::PaperAirplaneControlBlockPort() noexcept
                        : hMap(NULL)
                        , pBlock(NULL)
                    {
                        int64_t dwCapacity = sizeof(PaperAirplaneControlBlock);
                        int dwMaximumSizeLow = (int)(dwCapacity & ((INT64)(UINT64)-1));
                        int dwMaximumSizeHigh = (int)(dwCapacity >> 32);

                        // Open virtual memory mapping and create virtual memory mapping if it fails to open.
                        hMap = OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, _T(PAPERAIRPLANE_CONFIGURATION_NM));
                        if (NULL == hMap)
                        {
                            hMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | 0, dwMaximumSizeHigh, dwMaximumSizeLow, _T(PAPERAIRPLANE_CONFIGURATION_NM));
                        }

                        // When a memory map is successfully opened or created, the view of virtual memory is mapped to the process address space.
                        if (NULL != hMap)
                        {
                            pBlock = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
                            if (NULL == pBlock)
                            {
                                // If the address space mapping fails, the shared memory mapping handle is closed.
                                CloseHandle(hMap);

                                // Reset the value of the shared memory map handle hosting class member field to NULL.
                                hMap = NULL;
                            }
                            else
                            {
                                PaperAirplaneControlBlock* p = (PaperAirplaneControlBlock*)pBlock;
                                p->port = 0;
                                p->kf_1 = PAPERAIRPLANE_CONFIGURATION_KF_1;
                                p->kf_2 = PAPERAIRPLANE_CONFIGURATION_KF_2;
                            }
                        }
                    }

                    PaperAirplaneControlBlockPort::~PaperAirplaneControlBlockPort() noexcept
                    {
                        if (NULL != pBlock)
                        {
                            UnmapViewOfFile(pBlock);
                        }

                        if (NULL != hMap)
                        {
                            CloseHandle(hMap);
                        }

                        hMap = NULL;
                        pBlock = NULL;
                    }

                    bool                                                        PaperAirplaneControlBlockPort::IsAvailable() noexcept
                    {
                        return NULL != hMap && NULL != pBlock;
                    }

                    std::pair<int, int>                                         PaperAirplaneControlBlockPort::Get() noexcept
                    {
                        int nPort = 0;
                        int nInterfaceIndex = -1;

                        PaperAirplaneControlBlock* p = (PaperAirplaneControlBlock*)pBlock;
                        if (NULL == p)
                        {
                            return { nPort, nInterfaceIndex };
                        }

                        PaperAirplaneControlBlock stBlock = *p;
                        if (stBlock.kf_1 == PAPERAIRPLANE_CONFIGURATION_KF_1 && stBlock.kf_2 == PAPERAIRPLANE_CONFIGURATION_KF_2)
                        {
                            nPort = stBlock.port;
                            nInterfaceIndex = stBlock.interface_index;
                        }

                        return { nPort, nInterfaceIndex };
                    }

                    bool                                                        PaperAirplaneControlBlockPort::Set(int interface_index, int port) noexcept
                    {
                        if (NULL == pBlock)
                        {
                            return false;
                        }

                        int32_t pid = GetCurrentProcessId();
                        if (interface_index == -1 || port < 0 || port > UINT16_MAX)
                        {
                            port = 0;
                            pid = NULL;
                        }

                        PaperAirplaneControlBlock* p = (PaperAirplaneControlBlock*)pBlock;
                        p->port = port;
                        p->process_id = pid;
                        p->interface_index = interface_index;
                        p->kf_1 = PAPERAIRPLANE_CONFIGURATION_KF_1;
                        p->kf_2 = PAPERAIRPLANE_CONFIGURATION_KF_2;
                        return true;
                    }

                    std::pair<int, int>                                         GetBlock() noexcept
                    {
                        HANDLE hMap = OpenFileMapping(FILE_MAP_READ, FALSE, _T(PAPERAIRPLANE_CONFIGURATION_NM));
                        if (NULL == hMap)
                        {
                            return { 0, -1 };
                        }

                        int nPort = 0;
                        int nProcessId = 0;
                        int nInterfaceIndex = -1;

                        PaperAirplaneControlBlock* pBlock = (PaperAirplaneControlBlock*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
                        if (NULL != pBlock)
                        {
                            PaperAirplaneControlBlock stBlock = *pBlock;
                            if (stBlock.kf_1 == PAPERAIRPLANE_CONFIGURATION_KF_1 && stBlock.kf_2 == PAPERAIRPLANE_CONFIGURATION_KF_2)
                            {
                                nPort = stBlock.port;
                                nProcessId = stBlock.process_id;
                                nInterfaceIndex = stBlock.interface_index;
                            }

                            UnmapViewOfFile(pBlock);
                        }

                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, nProcessId);
                        CloseHandle(hMap);

                        if (NULL == hProcess)
                        {
                            return { 0, -1 };
                        }

                        CloseHandle(hProcess);
                        return { nPort, nInterfaceIndex };
                    }

                    static int                                                  GetLocalEndPoint(SOCKET s, uint32_t& bind_address)
                    {
                        if (NULL == s || s == (SOCKET)INVALID_HANDLE_VALUE)
                        {
                            return 0;
                        }

                        struct sockaddr_in localEP;
                        memset(&localEP, 0, sizeof(localEP));

                        int sockaddr_len = sizeof(localEP);
                        if (getsockname(s, (struct sockaddr*)&localEP, &sockaddr_len) < 0)
                        {
                            struct sockaddr_in bindEP;
                            memset(&bindEP, 0, sizeof(bindEP));

                            bindEP.sin_family = AF_INET;
                            bindEP.sin_addr.s_addr = htonl(INADDR_ANY);
                            bindEP.sin_port = htons(0);

                            // If the SOCKET does not have a binding address, bind an IPV4 address to ANY. In this way, the SOCKET supports 127.0.0.1 and normal access to the external network.
                            if (bind(s, (struct sockaddr*)&bindEP, sizeof(bindEP)) < 0)
                            {
                                return 0;
                            }
                            else
                            {
                                memset(&localEP, 0, sizeof(localEP));
                            }

                            sockaddr_len = sizeof(localEP);
                            if (getsockname(s, (struct sockaddr*)&localEP, &sockaddr_len) < 0)
                            {
                                return 0;
                            }
                        }

                        // If it is not IN4, it is not considered as a proxy. PPP is an IN4 virtual ethernet route.
                        if (localEP.sin_family != AF_INET)
                        {
                            return 0;
                        }

                        // Determine whether it is a broadcast IP address, if it is also do not proxy, this is invalid.
                        bind_address = localEP.sin_addr.s_addr;
                        if (bind_address == htonl(INADDR_BROADCAST))
                        {
                            return 0;
                        }

                        // Obtain the current SOCKET bound NIC IP address if the socket is already bound to the socket, otherwise use 127.0.0.1.
                        if (bind_address == htonl(INADDR_ANY))
                        {
                            bind_address = htonl(INADDR_LOOPBACK);
                        }

                        return ntohs(localEP.sin_port);
                    }

                    std::pair<int, uint32_t>                                    GetForwardPort(void* s, const struct sockaddr* name, int namelen) noexcept
                    {
                        if (NULL == name || namelen < (int)sizeof(struct sockaddr))
                        {
                            return { 0, 0 };
                        }

                        if (name->sa_family != AF_INET)
                        {
                            return { 0, 0 };
                        }

                        DWORD dwBestIfIndex;
                        if (GetBestInterface(((struct sockaddr_in*)name)->sin_addr.s_addr, &dwBestIfIndex) != NO_ERROR)
                        {
                            return { 0, 0 };
                        }

                        auto [nMasterPort, dwInterfaceIndex] = GetBlock();
                        if (dwBestIfIndex != dwInterfaceIndex)
                        {
                            return { 0, 0 };
                        }
                        else
                        {
                            uint32_t localIP = 0;
                            int32_t localPort = GetLocalEndPoint((SOCKET)s, localIP);
                            if (localPort < 1 || localPort > UINT16_MAX)
                            {
                                return { 0, 0 };
                            }

                            SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                            if (clientSocket == INVALID_SOCKET)
                            {
                                return { 0, 0 };
                            }
                            else
                            {
                                int nNetTimeout = 200;
                                if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&nNetTimeout, sizeof(nNetTimeout)) < 0 ||
                                    setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&nNetTimeout, sizeof(nNetTimeout)) < 0)
                                {
                                    closesocket(clientSocket);
                                    return { 0, 0 };
                                }
                                else
                                {
                                    struct sockaddr_in in = { 0 };
                                    in.sin_family = AF_INET;
                                    in.sin_port = htons(nMasterPort);
                                    in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                                    if (connect(clientSocket, (sockaddr*)&in, sizeof(in)) < 0)
                                    {
                                        closesocket(clientSocket);
                                        return { 0, 0 };
                                    }
                                    else
                                    {
                                        PaperAirplaneControl_AddPortForwardProtocol protocol;
                                        protocol.cmd = PAPERAIRPLANE_CONFIGURATION_ADD_PORT_FORWARD;
                                        protocol.localIP = localIP;
                                        protocol.localPort = localPort;
                                        protocol.destinationIP = ((struct sockaddr_in*)name)->sin_addr.s_addr;
                                        protocol.destinationPort = ntohs(((struct sockaddr_in*)name)->sin_port);

                                        if (send(clientSocket, (char*)&protocol, sizeof(protocol), 0) < 0)
                                        {
                                            shutdown(clientSocket, SD_BOTH);
                                            closesocket(clientSocket);
                                            return { 0, 0 };
                                        }
                                    }
                                }
                            }

                            int32_t forwardPort = 0;
                            int32_t receivedOffset = 0;
                            while (receivedOffset < sizeof(forwardPort))
                            {
                                int32_t transferredSize = recv(clientSocket, ((char*)&forwardPort) + receivedOffset, sizeof(forwardPort) - receivedOffset, 0);
                                if (transferredSize < 1)
                                {
                                    shutdown(clientSocket, SD_BOTH);
                                    closesocket(clientSocket);
                                    return { 0, 0 };
                                }

                                receivedOffset += transferredSize;
                            }

                            shutdown(clientSocket, SD_BOTH);
                            closesocket(clientSocket);
                            return { forwardPort, localIP };
                        }
                    }

                    bool                                                        PacketInput(
                        boost::asio::ip::tcp::socket&                                                               socket,
                        const std::function<int(boost::asio::ip::tcp::endpoint&, boost::asio::ip::tcp::endpoint&)>& add_port_forward_handling)
                    {
                        if (!socket.is_open())
                        {
                            return false;
                        }

                        if (NULL == add_port_forward_handling)
                        {
                            return false;
                        }

                        auto buffers = std::make_shared<PaperAirplaneControl_AddPortForwardProtocol>();
                        boost::asio::async_read(socket,
                            boost::asio::buffer((char*)buffers.get(), sizeof(PaperAirplaneControl_AddPortForwardProtocol)),
                                [&socket, add_port_forward_handling, buffers](const boost::system::error_code& ec, std::size_t sz) noexcept
                                {
                                    auto close_socket = [&socket]()
                                        {
                                            boost::system::error_code ec;
                                            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                                            socket.close(ec);
                                        };

                                    bool ok = false;
                                    int bytes_transferred = std::max<int>(ec ? -1 : (int)sz, -1);
                                    if (bytes_transferred > 0)
                                    {
                                        PaperAirplaneControl_AddPortForwardProtocol* protocol = buffers.get();
                                        if (protocol->cmd == PAPERAIRPLANE_CONFIGURATION_ADD_PORT_FORWARD)
                                        {
                                            if (bytes_transferred == sizeof(PaperAirplaneControl_AddPortForwardProtocol))
                                            {
                                                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v4(ntohl(protocol->localIP)), protocol->localPort);
                                                boost::asio::ip::tcp::endpoint destinationEP(boost::asio::ip::address_v4(ntohl(protocol->destinationIP)), protocol->destinationPort);

                                                int32_t forward_port = add_port_forward_handling(localEP, destinationEP);
                                                if (forward_port > 0 && forward_port <= UINT16_MAX)
                                                {
                                                    *(int32_t*)buffers.get() = forward_port;
                                                    ok = true;

                                                    boost::asio::async_write(socket,
                                                        boost::asio::buffer((char*)buffers.get(), sizeof(int32_t)),
                                                        [&socket, add_port_forward_handling, buffers, close_socket](const boost::system::error_code& ec, std::size_t sz) noexcept
                                                        {
                                                            close_socket();
                                                        });
                                                }
                                            }
                                        }
                                    }

                                    if (!ok)
                                    {
                                        close_socket();
                                    }
                                });
                        return true;
                    }
                }
            }
        }
    }
}

#ifdef _WINDLL
_Must_inspect_result_
int
WSPAPI
WSPStartup(
    _In_ WORD wVersionRequested,
    _In_ LPWSPDATA lpWSPData,
    _In_ LPWSAPROTOCOL_INFOW lpProtocolInfo,
    _In_ WSPUPCALLTABLE UpcallTable,
    _Out_ LPWSPPROC_TABLE lpProcTable
)
{
    return ppp::app::client::lsp::paper_airplane::WSPStartupInit(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
}
#endif

#pragma warning(pop)