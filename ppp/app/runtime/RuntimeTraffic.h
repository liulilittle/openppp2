#pragma once

#include <cstdint>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeTraffic final {
                std::uint64_t rx_bytes = 0;
                std::uint64_t tx_bytes = 0;
            };

        }
    }
}
