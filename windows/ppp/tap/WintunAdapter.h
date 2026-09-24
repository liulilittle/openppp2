#pragma once

// -----------------------------------------------------------------------------
// WintunAdapter owns one Wintun adapter/session pair. Native handles and their
// users share one lifecycle lock; packet callbacks have a separate hand-off lock.
// -----------------------------------------------------------------------------

#include <ppp/stdafx.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdint.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

// -------------------- Wintun API types (as declared by wintun.h) --------------------
typedef struct _WINTUN_ADAPTER*         WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION*         WINTUN_SESSION_HANDLE;

class WintunAdapter : public std::enable_shared_from_this<WintunAdapter> {
public:
    using PacketHandler = ppp::function<void(const uint8_t* data, uint32_t len)>;

    static constexpr int MAX_RING_BUFFER_SIZE = 1 << 20;

public:
    WintunAdapter(const WintunAdapter&) = delete;
    ~WintunAdapter() noexcept;

public:
    WintunAdapter& operator=(const WintunAdapter&) = delete;

public:
    bool Open() noexcept;
    bool Start() noexcept;
    void Stop() noexcept;
    bool SendPacket(const uint8_t* data, uint32_t len) noexcept;
    bool IsOpen() noexcept;

    // PacketInput is delivered outside both adapter locks. Callers must use these
    // methods rather than retaining a mutable callback field across threads.
    void SetPacketInput(const std::shared_ptr<PacketHandler>& handler) noexcept;
    void ClearPacketInput() noexcept;

    static bool Ready() noexcept;

public:
    // adapter_guid may be nullptr → Wintun generates a random GUID
    WintunAdapter(const std::wstring& adapter_name,
        const std::wstring& adapter_desc,
        const GUID* adapter_guid,
        uint32_t ring_buffer_size) noexcept;

private:
    std::shared_ptr<PacketHandler> GetPacketInput() const noexcept;
    void ResetPacketInput() noexcept;
    void ReceiveLoop() noexcept;
    void Finalize() noexcept;

private:
    std::wstring adapter_name_;
    std::wstring adapter_desc_;
    GUID adapter_guid_;
    const GUID* adapter_guid_ptr_;
    uint32_t ring_buffer_size_;

    // All native handles and lifecycle counters below are protected by
    // lifecycle_mutex_. Finalize only detaches handles after every user lease
    // (the receive loop and sends) has finished.
    mutable std::mutex lifecycle_mutex_;
    std::condition_variable lifecycle_cv_;
    WINTUN_ADAPTER_HANDLE adapter_handle_;
    WINTUN_SESSION_HANDLE session_handle_;
    HANDLE quit_event_;
    bool opening_ = false;
    bool stop_requested_ = false;
    bool receive_active_ = false;
    std::thread::id receive_thread_id_;
    size_t sends_in_flight_ = 0;
    bool finalizing_ = false;
    bool finalized_ = false;

    // Packet callbacks may re-enter Stop(), so their ownership hand-off uses a
    // separate mutex and is always invoked after releasing it.
    mutable std::mutex packet_input_mutex_;
    std::shared_ptr<PacketHandler> packet_input_;
};
