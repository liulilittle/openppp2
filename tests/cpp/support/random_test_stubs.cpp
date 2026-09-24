// Links ppp/Random.cpp into random_test without dragging the full
// Executors/io dependency graph: only the tick provider is needed.
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace threading {
        uint64_t Executors::GetTickCount() noexcept {
            return 0;
        }
    }
}
