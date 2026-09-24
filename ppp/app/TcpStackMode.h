/**
 * @file TcpStackMode.h
 * @brief Pure parsing and selection policy for the client TCP stack mode.
 */

#pragma once

#include <string_view>

namespace ppp::app {

enum class TcpStackMode {
    Native,
    Lwip,
    Xtcp,
};

enum class TcpStackModeStatus {
    Success,
    InvalidValue,
    ExplicitConflict,
    XtcpUnavailable,
};

struct TcpStackModeOptions {
    bool PlatformDefaultLwip = false;
    bool TcpStackSpecified = false;
    std::string_view TcpStackValue;
    bool LegacyLwipSpecified = false;
    bool LegacyLwipValue = false;
    bool XtcpAvailable = false;
};

struct TcpStackModeResult {
    TcpStackModeStatus Status = TcpStackModeStatus::Success;
    TcpStackMode Mode = TcpStackMode::Native;
};

constexpr const char* GetTcpStackModeName(TcpStackMode mode) noexcept {
    switch (mode) {
    case TcpStackMode::Native:
        return "native";
    case TcpStackMode::Lwip:
        return "lwip";
    case TcpStackMode::Xtcp:
        return "xtcp";
    }
    return "native";
}

constexpr bool TryParseTcpStackMode(std::string_view value, TcpStackMode& mode) noexcept {
    if (value == "native") {
        mode = TcpStackMode::Native;
        return true;
    }
    if (value == "lwip") {
        mode = TcpStackMode::Lwip;
        return true;
    }
    if (value == "xtcp") {
        mode = TcpStackMode::Xtcp;
        return true;
    }
    return false;
}

constexpr TcpStackModeResult ResolveTcpStackMode(const TcpStackModeOptions& options) noexcept {
    TcpStackMode requested = options.PlatformDefaultLwip ? TcpStackMode::Lwip : TcpStackMode::Native;

    if (options.TcpStackSpecified && !TryParseTcpStackMode(options.TcpStackValue, requested)) {
        return {TcpStackModeStatus::InvalidValue, TcpStackMode::Native};
    }

    if (options.TcpStackSpecified && options.LegacyLwipSpecified) {
        const TcpStackMode legacy = options.LegacyLwipValue ? TcpStackMode::Lwip : TcpStackMode::Native;
        if (requested == TcpStackMode::Xtcp || requested != legacy) {
            return {TcpStackModeStatus::ExplicitConflict, TcpStackMode::Native};
        }
    } else if (!options.TcpStackSpecified && options.LegacyLwipSpecified) {
        requested = options.LegacyLwipValue ? TcpStackMode::Lwip : TcpStackMode::Native;
    }

    if (requested == TcpStackMode::Xtcp && !options.XtcpAvailable) {
        return {TcpStackModeStatus::XtcpUnavailable, TcpStackMode::Xtcp};
    }

    return {TcpStackModeStatus::Success, requested};
}

} // namespace ppp::app
