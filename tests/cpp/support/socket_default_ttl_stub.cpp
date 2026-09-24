// Minimal stubs for tests that link ppp/net/native/checksum.cpp and the
// diagnostics sources without pulling in the whole Socket/Executors implementation.
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace net {
        int Socket::GetDefaultTTL() noexcept {
            return 64;
        }
    }

    namespace threading {
        uint64_t Executors::GetTickCount() noexcept {
            return 0;
        }
    }
}
