// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

// Refer: https://git.zx2c4.com/wintun/tree/example/example.c
#include <windows/ppp/tap/WintunAdapter.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// -------------------- Wintun API function pointers --------------------
typedef WINTUN_ADAPTER_HANDLE(WINAPI* WintunCreateAdapterFunc)(LPCWSTR, LPCWSTR, const GUID*);
typedef WINTUN_ADAPTER_HANDLE(WINAPI* WintunOpenAdapterFunc)(LPCWSTR);
typedef VOID(WINAPI* WintunCloseAdapterFunc)(WINTUN_ADAPTER_HANDLE);
typedef VOID(WINAPI* WintunGetAdapterLUIDFunc)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
typedef WINTUN_SESSION_HANDLE(WINAPI* WintunStartSessionFunc)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef VOID(WINAPI* WintunEndSessionFunc)(WINTUN_SESSION_HANDLE);
typedef HANDLE(WINAPI* WintunGetReadWaitEventFunc)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI* WintunReceivePacketFunc)(WINTUN_SESSION_HANDLE, DWORD*);
typedef VOID(WINAPI* WintunReleaseReceivePacketFunc)(WINTUN_SESSION_HANDLE, BYTE*);
typedef BYTE* (WINAPI* WintunAllocateSendPacketFunc)(WINTUN_SESSION_HANDLE, DWORD);
typedef VOID(WINAPI* WintunSendPacketFunc)(WINTUN_SESSION_HANDLE, BYTE*);

static HMODULE DLL_HANDLE = NULL;

static WintunCreateAdapterFunc WintunCreateAdapter = NULL;
static WintunOpenAdapterFunc WintunOpenAdapter = NULL;
static WintunCloseAdapterFunc WintunCloseAdapter = NULL;
static WintunGetAdapterLUIDFunc WintunGetAdapterLUID = NULL;
static WintunStartSessionFunc WintunStartSession = NULL;
static WintunEndSessionFunc WintunEndSession = NULL;
static WintunGetReadWaitEventFunc WintunGetReadWaitEvent = NULL;
static WintunReceivePacketFunc WintunReceivePacket = NULL;
static WintunReleaseReceivePacketFunc WintunReleaseReceivePacket = NULL;
static WintunAllocateSendPacketFunc WintunAllocateSendPacket = NULL;
static WintunSendPacketFunc WintunSendPacket = NULL;

namespace {
    HMODULE LoadWintunFromApplicationDirectory(LPCWSTR relative_path) noexcept {
        WCHAR module_path[MAX_PATH];
        DWORD length = GetModuleFileNameW(NULL, module_path, ARRAYSIZE(module_path));
        if (length == 0 || length == ARRAYSIZE(module_path)) {
            return NULL;
        }

        WCHAR* file_name = wcsrchr(module_path, L'\\');
        if (!file_name) {
            return NULL;
        }

        *(file_name + 1) = L'\0';
        if (wcscat_s(module_path, relative_path) != 0) {
            return NULL;
        }

        return LoadLibraryExW(module_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

struct ReadyWintunAdapter
{
    ReadyWintunAdapter() noexcept { READY = LoadWintun(); }
    ~ReadyWintunAdapter() noexcept { UnloadWintun(); }

    bool LoadWintun() noexcept {
        if (DLL_HANDLE) return true;

        // Search only the application directory, bundled Driver directory, and System32.
        // Avoid bare or relative LoadLibraryW calls so the current directory and PATH cannot hijack wintun.dll.
        DLL_HANDLE = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!DLL_HANDLE) {
            DLL_HANDLE = LoadWintunFromApplicationDirectory(L"Driver\\wintun.dll");
            if (!DLL_HANDLE) {
#ifdef _M_ARM64
                LPCWSTR wzDllPath = L"Driver\\arm64\\wintun.dll";
#elif defined(_WIN64)
                LPCWSTR wzDllPath = L"Driver\\x64\\wintun.dll";
#else
                LPCWSTR wzDllPath = L"Driver\\x86\\wintun.dll";
#endif
                DLL_HANDLE = LoadWintunFromApplicationDirectory(wzDllPath);
                if (!DLL_HANDLE) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
                    return false;
                }
            }
        }

#define GET_PROC(name) \
    name = (decltype(name))GetProcAddress(DLL_HANDLE, #name); \
    if (!name) { ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed); FreeLibrary(DLL_HANDLE); DLL_HANDLE = NULL; return false; }

        GET_PROC(WintunCreateAdapter);
        GET_PROC(WintunOpenAdapter);
        GET_PROC(WintunCloseAdapter);
        GET_PROC(WintunGetAdapterLUID);
        GET_PROC(WintunStartSession);
        GET_PROC(WintunEndSession);
        GET_PROC(WintunGetReadWaitEvent);
        GET_PROC(WintunReceivePacket);
        GET_PROC(WintunReleaseReceivePacket);
        GET_PROC(WintunAllocateSendPacket);
        GET_PROC(WintunSendPacket);
#undef GET_PROC
        return true;
    }

    void UnloadWintun() noexcept {
        if (DLL_HANDLE) {
            FreeLibrary(DLL_HANDLE);
            DLL_HANDLE = NULL;
        }
    }

    bool READY = false;
};

WintunAdapter::~WintunAdapter() noexcept {
    Stop();
}

bool WintunAdapter::Open() noexcept {
    {
        std::unique_lock<std::mutex> lock(lifecycle_mutex_);
        if (!stop_requested_ && session_handle_ && adapter_handle_ && quit_event_) {
            return true;
        }
        if (stop_requested_ || finalized_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            return false;
        }
        if (opening_) {
            lifecycle_cv_.wait(lock, [this]() noexcept { return !opening_; });
            return !stop_requested_ && !finalized_ && session_handle_ && adapter_handle_ && quit_event_;
        }
        opening_ = true;
    }

    WINTUN_ADAPTER_HANDLE adapter = NULL;
    WINTUN_SESSION_HANDLE session = NULL;
    HANDLE quit_event = NULL;
    bool success = false;

    if (!Ready() || !WintunOpenAdapter || !WintunCreateAdapter || !WintunStartSession) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
    }
    else {
        adapter = WintunOpenAdapter(adapter_name_.c_str());
        if (!adapter) {
            adapter = WintunCreateAdapter(adapter_name_.c_str(), adapter_desc_.c_str(), adapter_guid_ptr_);
        }
        if (!adapter) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
        }
        else {
            session = WintunStartSession(adapter, ring_buffer_size_);
            if (!session) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunSessionStartFailed);
            }
            else {
                quit_event = CreateEventW(NULL, TRUE, FALSE, NULL);
                if (!quit_event) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                }
                else {
                    success = true;
                }
            }
        }
    }

    bool published = false;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        opening_ = false;
        if (success && !stop_requested_ && !finalized_) {
            adapter_handle_ = adapter;
            session_handle_ = session;
            quit_event_ = quit_event;
            adapter = NULL;
            session = NULL;
            quit_event = NULL;
            published = true;
        }
        lifecycle_cv_.notify_all();
    }

    if (quit_event) {
        CloseHandle(quit_event);
    }
    if (session && WintunEndSession) {
        WintunEndSession(session);
    }
    if (adapter && WintunCloseAdapter) {
        WintunCloseAdapter(adapter);
    }

    if (!published) {
        Finalize();
    }
    return published;
}

bool WintunAdapter::Start() noexcept {
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (receive_active_) {
            return true;
        }
        if (opening_ || stop_requested_ || finalized_ || !session_handle_ || !adapter_handle_ || !quit_event_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            return false;
        }
        receive_active_ = true;
        receive_thread_id_ = std::thread::id();
    }

    std::shared_ptr<WintunAdapter> self;
    try {
        self = shared_from_this();
    }
    catch (...) {
        {
            std::lock_guard<std::mutex> lock(lifecycle_mutex_);
            receive_active_ = false;
            stop_requested_ = true;
            lifecycle_cv_.notify_all();
        }
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
        Finalize();
        return false;
    }

    try {
        std::thread([self]() noexcept {
            ppp::SetThreadPriorityToMaxLevel();
            ppp::SetThreadName("wintun");
            self->ReceiveLoop();
        }).detach();
    }
    catch (...) {
        {
            std::lock_guard<std::mutex> lock(lifecycle_mutex_);
            receive_active_ = false;
            stop_requested_ = true;
            lifecycle_cv_.notify_all();
        }
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
        Finalize();
        return false;
    }

    return true;
}

void WintunAdapter::Stop() noexcept {
    HANDLE quit_event = NULL;
    bool receive_thread = false;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (finalized_) {
            return;
        }
        stop_requested_ = true;
        quit_event = quit_event_;
        receive_thread = receive_active_ && receive_thread_id_ == std::this_thread::get_id();
    }

    if (quit_event) {
        SetEvent(quit_event);
    }

    Finalize();
    if (receive_thread) {
        return;
    }

    std::unique_lock<std::mutex> lock(lifecycle_mutex_);
    lifecycle_cv_.wait(lock, [this]() noexcept { return finalized_; });
}

bool WintunAdapter::SendPacket(const uint8_t* data, uint32_t len) noexcept {
    if (!data || len < 1 || len > static_cast<uint32_t>(ppp::tap::ITap::Mtu)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketTooLarge);
        return false;
    }

    WINTUN_SESSION_HANDLE session = NULL;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (stop_requested_ || finalized_ || !session_handle_) {
            ppp::diagnostics::SetLastErrorCode(stop_requested_
                ? ppp::diagnostics::ErrorCode::WintunAdapterSendStoppedState
                : ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            return false;
        }
        session = session_handle_;
        ++sends_in_flight_;
    }

    bool success = false;
    try {
        BYTE* buffer = WintunAllocateSendPacket(session, len);
        if (buffer) {
            memcpy(buffer, data, len);
            WintunSendPacket(session, buffer);
            success = true;
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelPacketInjectFailed);
        }
    }
    catch (...) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelPacketInjectFailed);
    }

    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        --sends_in_flight_;
        lifecycle_cv_.notify_all();
    }
    Finalize();
    return success;
}

bool WintunAdapter::IsOpen() noexcept {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return !stop_requested_ && !finalized_ && session_handle_ && adapter_handle_ && quit_event_;
}

void WintunAdapter::SetPacketInput(const std::shared_ptr<PacketHandler>& handler) noexcept {
    std::lock_guard<std::mutex> lock(packet_input_mutex_);
    packet_input_ = handler;
}

void WintunAdapter::ClearPacketInput() noexcept {
    std::lock_guard<std::mutex> lock(packet_input_mutex_);
    packet_input_.reset();
}

std::shared_ptr<WintunAdapter::PacketHandler> WintunAdapter::GetPacketInput() const noexcept {
    std::lock_guard<std::mutex> lock(packet_input_mutex_);
    return packet_input_;
}

bool WintunAdapter::Ready() noexcept {
    static ReadyWintunAdapter ready;
    return ready.READY;
}

void WintunAdapter::ReceiveLoop() noexcept {
    WINTUN_SESSION_HANDLE session = NULL;
    HANDLE quit_event = NULL;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        receive_thread_id_ = std::this_thread::get_id();
        session = session_handle_;
        quit_event = quit_event_;
    }

    if (!session || !quit_event || !WintunGetReadWaitEvent) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WintunAdapterReceiveLoopInvalidState);
    }
    else {
        HANDLE read_event = WintunGetReadWaitEvent(session);
        if (!read_event) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WintunAdapterReceiveLoopInvalidState);
        }
        else {
            HANDLE events[2] = { read_event, quit_event };
            for (;;) {
                {
                    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
                    if (stop_requested_) {
                        break;
                    }
                }

                DWORD packet_size = 0;
                BYTE* packet = WintunReceivePacket(session, &packet_size);
                if (packet) {
                    if (packet_size >= static_cast<DWORD>(ppp::net::native::ip_hdr::IP_HLEN)) {
                        std::shared_ptr<PacketHandler> handler = GetPacketInput();
                        if (handler && *handler) {
                            try {
                                (*handler)(packet, packet_size);
                            }
                            catch (...) {
                                // A callback cannot be allowed to strand a Wintun receive packet.
                            }
                        }
                    }
                    WintunReleaseReceivePacket(session, packet);
                    continue;
                }

                DWORD error = GetLastError();
                if (error == ERROR_HANDLE_EOF) {
                    break;
                }
                if (error != ERROR_NO_MORE_ITEMS) {
                    break;
                }

                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                if (wait != WAIT_OBJECT_0) {
                    break;
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        receive_active_ = false;
        receive_thread_id_ = std::thread::id();
        lifecycle_cv_.notify_all();
    }
    Finalize();
}

void WintunAdapter::Finalize() noexcept {
    WINTUN_ADAPTER_HANDLE adapter = NULL;
    WINTUN_SESSION_HANDLE session = NULL;
    HANDLE quit_event = NULL;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (!stop_requested_ || opening_ || receive_active_ || sends_in_flight_ != 0 || finalizing_ || finalized_) {
            return;
        }

        finalizing_ = true;
        adapter = adapter_handle_;
        session = session_handle_;
        quit_event = quit_event_;
        adapter_handle_ = NULL;
        session_handle_ = NULL;
        quit_event_ = NULL;
    }

    ClearPacketInput();
    if (session && WintunEndSession) {
        WintunEndSession(session);
    }
    if (adapter && WintunCloseAdapter) {
        WintunCloseAdapter(adapter);
    }
    if (quit_event) {
        CloseHandle(quit_event);
    }

    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        finalizing_ = false;
        finalized_ = true;
        lifecycle_cv_.notify_all();
    }
}

WintunAdapter::WintunAdapter(const std::wstring& adapter_name, const std::wstring& adapter_desc, const GUID* adapter_guid, uint32_t ring_buffer_size) noexcept
    : adapter_name_(adapter_name)
    , adapter_desc_(adapter_desc)
    , adapter_guid_ptr_(NULL)
    , ring_buffer_size_(ring_buffer_size)
    , adapter_handle_(NULL)
    , session_handle_(NULL)
    , quit_event_(NULL)
{
    if (adapter_guid) {
        adapter_guid_ = *adapter_guid;
        adapter_guid_ptr_ = &adapter_guid_;
    }
}
