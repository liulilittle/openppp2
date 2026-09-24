#pragma once

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            enum class RuntimePhase : std::uint8_t {
                Idle,
                Starting,
                PreparingHost,
                Connecting,
                Handshaking,
                ApplyingPolicy,
                Connected,
                Reconnecting,
                Stopping,
                Failed,
                Unknown,
            };

            inline const char* ToString(RuntimePhase phase) noexcept {
                switch (phase) {
                case RuntimePhase::Idle: return "idle";
                case RuntimePhase::Starting: return "starting";
                case RuntimePhase::PreparingHost: return "preparing_host";
                case RuntimePhase::Connecting: return "connecting";
                case RuntimePhase::Handshaking: return "handshaking";
                case RuntimePhase::ApplyingPolicy: return "applying_policy";
                case RuntimePhase::Connected: return "connected";
                case RuntimePhase::Reconnecting: return "reconnecting";
                case RuntimePhase::Stopping: return "stopping";
                case RuntimePhase::Failed: return "failed";
                default: return "unknown";
                }
            }

            inline RuntimePhase ParseRuntimePhase(const std::string& value) noexcept {
                if (value == "idle") return RuntimePhase::Idle;
                if (value == "starting") return RuntimePhase::Starting;
                if (value == "preparing_host") return RuntimePhase::PreparingHost;
                if (value == "connecting") return RuntimePhase::Connecting;
                if (value == "handshaking") return RuntimePhase::Handshaking;
                if (value == "applying_policy") return RuntimePhase::ApplyingPolicy;
                if (value == "connected") return RuntimePhase::Connected;
                if (value == "reconnecting") return RuntimePhase::Reconnecting;
                if (value == "stopping") return RuntimePhase::Stopping;
                if (value == "failed") return RuntimePhase::Failed;
                if (value == "unknown") return RuntimePhase::Unknown;
                return RuntimePhase::Unknown;
            }

        }
    }
}
