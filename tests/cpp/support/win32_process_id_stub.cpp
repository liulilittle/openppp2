// Link-only stub for test binaries that do not link ppp/stdafx.cpp. Provides
// the native process identifier used by the OTLP exporter's resource metadata
// and the handle-close platform abstraction.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#if defined(_WIN32)
#include <windows.h>

#ifndef PPP_STUB_NO_PROCESS_ID
namespace ppp {

int GetCurrentProcessId() noexcept {
    return static_cast<int>(::GetCurrentProcessId());
}

bool CloseHandle(const void* handle) noexcept {
    if (handle == nullptr) return false;
    return ::CloseHandle(const_cast<void*>(handle)) != FALSE;
}

} // namespace ppp
#endif // PPP_STUB_NO_PROCESS_ID

#endif // _WIN32
