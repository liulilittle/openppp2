// Link-only stubs for spinlock_test.
//
// SpinLock.cpp needs ppp::GetCurrentThreadId() (normally in ppp/stdafx.cpp,
// which would drag the io/File/Random dependency graph into this test) and
// ErrorHandler::SetLastErrorCode() needs Executors::GetTickCount().

#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

#if !defined(_WIN32)
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace ppp {

    int64_t GetCurrentThreadId() noexcept {
#if defined(_WIN32)
        return static_cast<int64_t>(::GetCurrentThreadId());
#else
        static thread_local const int64_t tid = static_cast<int64_t>(::syscall(SYS_gettid));
        return tid;
#endif
    }

    uint64_t GetTickCount() noexcept {
        return 0;
    }

namespace threading {

    uint64_t Executors::GetTickCount() noexcept {
        return 0;
    }

}  // namespace threading
}  // namespace ppp
