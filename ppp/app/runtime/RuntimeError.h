#pragma once

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeError final {
                std::uint32_t code = 0;
                std::string severity;
                bool retryable = false;
                std::string user_message_key;
                std::string diagnostic_detail;

                bool HasError() const noexcept {
                    return code != 0 || !diagnostic_detail.empty();
                }
            };

        }
    }
}
