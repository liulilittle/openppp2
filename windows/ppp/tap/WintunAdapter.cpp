// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

// Refer: https://git.zx2c4.com/wintun/tree/example/example.c
#include <windows/ppp/tap/WintunAdapter.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>
#include <ppp/Filesystem.h>
#include <ppp/text/Encoding.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

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
    // WintunAllocateSendPacket accepts IP packets up to 0xFFFF bytes.
    // Windows can deliver coalesced TCP packets larger than the interface
    // MTU; rejecting those here drops payload while small handshakes pass.
    constexpr uint32_t kWintunMaxIpPacketSize = 0xFFFFu;

    // Wintun's adapter object is persistent and the bundled DLL does not
    // export an adapter-removal entry point. The marker represents the process-owned
    // session lifecycle, not a request to remove the installed adapter.
    constexpr const char* kRecoveryMarkerHeader = "WINTUN-RECOVERY|1";
    constexpr const char* kRecoveryMarkerName = "wintun-adapter.pending";

    enum class RecoveryMarkerState {
        Intent,
        Confirmed,
    };

    struct RecoveryMarker final {
        RecoveryMarkerState state = RecoveryMarkerState::Intent;
        std::string adapter_name;
        uint64_t luid = 0;
        uint32_t interface_index = 0;
        uint32_t owner_pid = 0;
    };

    ppp::filesystem::fs::path RecoveryMarkerPath() noexcept {
        const ppp::string startup = ppp::GetApplicationStartupPath();
        if (startup.empty()) return {};
        return ppp::filesystem::fs::path(startup.data()) /
            "network-recovery" / kRecoveryMarkerName;
    }

    bool EnsureRecoveryDirectory(const ppp::filesystem::fs::path& marker) noexcept {
        if (marker.empty()) return false;
        ppp::filesystem::error_code ec;
        ppp::filesystem::fs::create_directories(marker.parent_path(), ec);
        return !ec;
    }

    bool IsSafeAdapterName(const std::string& name) noexcept {
        if (name.empty() || name.size() > 256) return false;
        return std::all_of(name.begin(), name.end(), [](unsigned char ch) noexcept {
            return ch >= 0x20 && ch != '|' && ch != '\r' && ch != '\n';
        });
    }

    std::string SerializeRecoveryMarker(const RecoveryMarker& marker) {
        std::ostringstream output;
        output << kRecoveryMarkerHeader << '\n'
            << "state|" << (marker.state == RecoveryMarkerState::Confirmed ? "confirmed" : "intent") << '\n'
            << "name|" << marker.adapter_name << '\n'
            << "luid|" << marker.luid << '\n'
            << "ifindex|" << marker.interface_index << '\n'
            << "pid|" << marker.owner_pid << '\n';
        return output.str();
    }

    bool ParseUnsigned(const std::string& value, uint64_t& output) noexcept {
        if (value.empty()) return false;
        try {
            std::size_t consumed = 0;
            output = std::stoull(value, &consumed, 10);
            return consumed == value.size();
        }
        catch (...) {
            return false;
        }
    }

    bool ParseRecoveryMarker(const std::string& bytes, RecoveryMarker& marker) noexcept {
        std::istringstream input(bytes);
        std::string line;
        if (!std::getline(input, line) || line != kRecoveryMarkerHeader) return false;
        std::string state;
        uint64_t luid = 0;
        uint64_t interface_index = 0;
        uint64_t owner_pid = 0;
        bool have_state = false;
        bool have_name = false;
        bool have_luid = false;
        bool have_ifindex = false;
        bool have_pid = false;
        while (std::getline(input, line)) {
            const std::size_t separator = line.find('|');
            if (separator == std::string::npos) return false;
            const std::string key = line.substr(0, separator);
            const std::string value = line.substr(separator + 1);
            if (key == "state") {
                if (have_state || (value != "intent" && value != "confirmed")) return false;
                state = value;
                have_state = true;
            }
            else if (key == "name") {
                if (have_name || !IsSafeAdapterName(value)) return false;
                marker.adapter_name = value;
                have_name = true;
            }
            else if (key == "luid") {
                if (have_luid || !ParseUnsigned(value, luid)) return false;
                have_luid = true;
            }
            else if (key == "ifindex") {
                if (have_ifindex || !ParseUnsigned(value, interface_index) || interface_index > UINT32_MAX) return false;
                have_ifindex = true;
            }
            else if (key == "pid") {
                if (have_pid || !ParseUnsigned(value, owner_pid) || owner_pid == 0 || owner_pid > UINT32_MAX) return false;
                have_pid = true;
            }
            else {
                return false;
            }
        }
        if (!have_state || !have_name || !have_luid || !have_ifindex || !have_pid) return false;
        marker.state = state == "confirmed" ? RecoveryMarkerState::Confirmed : RecoveryMarkerState::Intent;
        marker.luid = luid;
        marker.interface_index = static_cast<uint32_t>(interface_index);
        marker.owner_pid = static_cast<uint32_t>(owner_pid);
        if (marker.state == RecoveryMarkerState::Confirmed && marker.luid == 0) return false;
        return true;
    }

    bool ReadRecoveryMarker(RecoveryMarker& marker, bool& exists) noexcept {
        exists = false;
        const auto path = RecoveryMarkerPath();
        if (path.empty()) return false;
        ppp::filesystem::error_code ec;
        if (!ppp::filesystem::fs::exists(path, ec)) return !ec;
        if (ec) return false;
        exists = true;
        std::ifstream input(ppp::filesystem::StreamPath(path), std::ios::binary);
        if (!input) return false;
        std::ostringstream bytes;
        bytes << input.rdbuf();
        return input.good() || input.eof() ? ParseRecoveryMarker(bytes.str(), marker) : false;
    }

    bool WriteRecoveryMarker(const RecoveryMarker& marker) noexcept {
        const auto path = RecoveryMarkerPath();
        if (path.empty() || !IsSafeAdapterName(marker.adapter_name) || marker.owner_pid == 0) return false;
        if (!EnsureRecoveryDirectory(path)) return false;
        RecoveryMarker existing;
        bool exists = false;
        if (!ReadRecoveryMarker(existing, exists)) return false;
        if (exists && (existing.owner_pid != marker.owner_pid ||
            existing.adapter_name != marker.adapter_name)) {
            // Never replace another process's durable ownership record. The
            // recovery worker must first verify that owner is gone and that
            // its adapter identity is safe to replay.
            return false;
        }
        const auto temporary = ppp::filesystem::fs::path(path.string() + ".tmp");
        const std::string bytes = SerializeRecoveryMarker(marker);
        HANDLE handle = CreateFileW(temporary.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        const bool ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()),
            &written, nullptr) && written == bytes.size() && FlushFileBuffers(handle);
        CloseHandle(handle);
        if (!ok || !MoveFileExW(temporary.wstring().c_str(), path.wstring().c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            DeleteFileW(temporary.wstring().c_str());
            return false;
        }
        return true;
    }

    bool RemoveRecoveryMarker(const RecoveryMarker* expected = nullptr) noexcept {
        const auto path = RecoveryMarkerPath();
        if (path.empty()) return false;
        if (expected) {
            RecoveryMarker current;
            bool exists = false;
            if (!ReadRecoveryMarker(current, exists)) return false;
            if (!exists || current.adapter_name != expected->adapter_name ||
                current.owner_pid != expected->owner_pid ||
                (expected->luid != 0 && current.luid != expected->luid)) {
                return false;
            }
        }
        if (DeleteFileW(path.wstring().c_str())) return true;
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }

    bool QueryAdapterIdentity(WINTUN_ADAPTER_HANDLE adapter, uint64_t& luid,
                              uint32_t& interface_index) noexcept {
        if (!adapter || !WintunGetAdapterLUID) return false;
        NET_LUID value{};
        WintunGetAdapterLUID(adapter, &value);
        NET_IFINDEX index = 0;
        if (ConvertInterfaceLuidToIndex(&value, &index) != NO_ERROR) return false;
        luid = value.Value;
        interface_index = static_cast<uint32_t>(index);
        return luid != 0 && interface_index != 0;
    }

    bool AdapterIdentityMatches(WINTUN_ADAPTER_HANDLE adapter,
                                const RecoveryMarker& marker) noexcept {
        uint64_t luid = 0;
        uint32_t interface_index = 0;
        return QueryAdapterIdentity(adapter, luid, interface_index) &&
            luid == marker.luid && interface_index == marker.interface_index;
    }

    bool VerifyAdapterIdentity(const RecoveryMarker& marker) noexcept {
        if (marker.adapter_name.empty() || marker.luid == 0 ||
            marker.interface_index == 0 || !WintunOpenAdapter ||
            !WintunCloseAdapter) {
            return false;
        }
        WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(
            ppp::text::Encoding::ascii_to_wstring(marker.adapter_name).c_str());
        if (!adapter) return false;
        const bool matches = AdapterIdentityMatches(adapter, marker);
        WintunCloseAdapter(adapter);
        return matches;
    }

    enum class ProcessState {
        Dead,
        Alive,
        Unknown,
    };

    ProcessState GetProcessState(uint32_t process_id) noexcept {
        if (process_id == 0) return ProcessState::Unknown;
        if (process_id == GetCurrentProcessId()) return ProcessState::Alive;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, process_id);
        if (!process) {
            const DWORD error = GetLastError();
            return error == ERROR_NOT_FOUND || error == ERROR_INVALID_PARAMETER
                ? ProcessState::Dead : ProcessState::Unknown;
        }
        const DWORD result = WaitForSingleObject(process, 0);
        CloseHandle(process);
        if (result == WAIT_TIMEOUT) return ProcessState::Alive;
        if (result == WAIT_OBJECT_0) return ProcessState::Dead;
        return ProcessState::Unknown;
    }

    bool RecoverMarker(const RecoveryMarker& marker) noexcept {
        const ProcessState owner_state = GetProcessState(marker.owner_pid);
        if (owner_state != ProcessState::Dead) {
            // A live owner may still have an active Wintun session. Do not
            // attach to or mutate it from another process.
            return owner_state == ProcessState::Alive &&
                marker.owner_pid == GetCurrentProcessId();
        }
        if (marker.state == RecoveryMarkerState::Intent) {
            // Creation may have failed before a handle was published. An
            // existing adapter with no stable identity is a conflict, not a
            // license to claim another program's adapter.
            const std::wstring adapter_name =
                ppp::text::Encoding::ascii_to_wstring(marker.adapter_name);
            WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(adapter_name.c_str());
            if (adapter) {
                WintunCloseAdapter(adapter);
                return false;
            }
            return RemoveRecoveryMarker(&marker);
        }
        const std::wstring adapter_name =
            ppp::text::Encoding::ascii_to_wstring(marker.adapter_name);
        WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(adapter_name.c_str());
        if (!adapter) {
            // The adapter disappeared, so there is no process-owned session
            // left to recover. Keep other Win32 errors retryable.
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND || error == ERROR_NOT_FOUND || error == ERROR_DEV_NOT_EXIST) {
                return RemoveRecoveryMarker(&marker);
            }
            return false;
        }
        if (!AdapterIdentityMatches(adapter, marker)) {
            WintunCloseAdapter(adapter);
            return false;
        }
        WINTUN_SESSION_HANDLE session = WintunStartSession(adapter, 0x100000);
        if (!session) {
            WintunCloseAdapter(adapter);
            return false;
        }
        WintunEndSession(session);
        WintunCloseAdapter(adapter);
        return VerifyAdapterIdentity(marker) && RemoveRecoveryMarker(&marker);
    }
}

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
    bool owns_adapter = false;
    bool recovery_marker = false;
    RecoveryMarker marker;
    marker.adapter_name = ppp::text::Encoding::wstring_to_ascii(adapter_name_);
    marker.owner_pid = GetCurrentProcessId();

    if (!Ready() || !WintunOpenAdapter || !WintunCreateAdapter || !WintunStartSession) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
    }
    else {
        adapter = WintunOpenAdapter(adapter_name_.c_str());
        if (!adapter) {
            // Persist the create intent before invoking the OS. If the
            // process dies in this window, recovery can distinguish an
            // absent adapter from a name collision and will not claim a
            // replacement adapter.
            if (!IsSafeAdapterName(marker.adapter_name) || !WriteRecoveryMarker(marker)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
            }
            else {
                recovery_marker = true;
            }
        }
        if (!adapter && recovery_marker) {
            adapter = WintunCreateAdapter(adapter_name_.c_str(), adapter_desc_.c_str(), adapter_guid_ptr_);
            owns_adapter = adapter != NULL;
        }
        if (!adapter) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
        }
        else {
            if (owns_adapter) {
                if (!QueryAdapterIdentity(adapter, marker.luid, marker.interface_index)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
                    recovery_marker = false;
                }
                else {
                    marker.state = RecoveryMarkerState::Confirmed;
                    recovery_marker = WriteRecoveryMarker(marker);
                    if (!recovery_marker) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
                    }
                }
            }
            if (owns_adapter && !recovery_marker) {
                // Do not continue with an unjournaled adapter. The marker is
                // retained if the atomic rewrite failed, so a later worker
                // can retry without guessing ownership.
                WintunCloseAdapter(adapter);
                adapter = NULL;
                owns_adapter = false;
            }
        }
        if (adapter && (owns_adapter ? recovery_marker : true)) {
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
            owns_adapter_ = owns_adapter;
            recovery_marker_ = recovery_marker;
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
        if (recovery_marker && marker.state == RecoveryMarkerState::Confirmed) {
            RemoveRecoveryMarker(&marker);
        }
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
    if (!data || len < 1 || len > kWintunMaxIpPacketSize) {
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
    bool owns_adapter = false;
    RecoveryMarker marker;
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
        owns_adapter = owns_adapter_;
        if (recovery_marker_) {
            marker.state = RecoveryMarkerState::Confirmed;
            marker.adapter_name = ppp::text::Encoding::wstring_to_ascii(adapter_name_);
            marker.owner_pid = GetCurrentProcessId();
            QueryAdapterIdentity(adapter, marker.luid, marker.interface_index);
        }
        owns_adapter_ = false;
        recovery_marker_ = false;
    }

    ClearPacketInput();
    if (session && WintunEndSession) {
        WintunEndSession(session);
    }
    if (adapter && WintunCloseAdapter) {
        WintunCloseAdapter(adapter);
    }
    if (owns_adapter && marker.luid != 0 && marker.interface_index != 0) {
        // WintunCloseAdapter releases this process's handle. The adapter
        // remains installed because this API version has no supported delete
        // operation; remove the marker only after the stable identity was
        // captured and the session/handle close calls completed.
        if (VerifyAdapterIdentity(marker)) {
            RemoveRecoveryMarker(&marker);
        }
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

bool WintunAdapter::OwnsAdapter() const noexcept {
    std::lock_guard<std::mutex> lock(lifecycle_mutex_);
    return owns_adapter_ && !finalized_;
}

bool WintunAdapter::HasPendingRecovery() noexcept {
    RecoveryMarker marker;
    bool exists = false;
    if (!ReadRecoveryMarker(marker, exists)) return true;
    if (!exists) return false;
    // A marker written by this process belongs to the live adapter instance;
    // it is not a stale cross-process recovery task.
    return marker.owner_pid != GetCurrentProcessId();
}

bool WintunAdapter::RecoverPending() noexcept {
    if (!Ready() || !WintunOpenAdapter || !WintunCloseAdapter ||
        !WintunStartSession || !WintunEndSession) {
        return !HasPendingRecovery();
    }
    RecoveryMarker marker;
    bool exists = false;
    if (!ReadRecoveryMarker(marker, exists)) return false;
    if (!exists) return true;
    if (marker.owner_pid == GetCurrentProcessId()) return true;
    return RecoverMarker(marker);
}
