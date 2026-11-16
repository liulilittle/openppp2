#pragma once

namespace ppp::app::client::xtcp {

inline bool DirectBridgeEnabled(const char* env_value, bool platform_default) noexcept {
    if (env_value == nullptr || env_value[0] == '\0') {
        return platform_default;
    }
    return env_value[0] == '1' && env_value[1] == '\0';
}

} // namespace ppp::app::client::xtcp
