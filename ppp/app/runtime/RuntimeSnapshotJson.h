#pragma once

#include <ppp/app/runtime/RuntimeSnapshot.h>

#include <json/json.h>

#include <algorithm>
#include <climits>
#include <string>
#include <utility>

namespace ppp {
    namespace app {
        namespace runtime {

            namespace detail {

                inline Json::String ToRuntimeJsonString(
                    const std::string& value) noexcept {
                    return Json::String(value.data(), value.size());
                }

                inline std::string FromRuntimeJsonString(
                    const Json::String& value) noexcept {
                    return std::string(value.data(), value.size());
                }

                inline std::string RuntimeJsonString(
                    const Json::Value& root,
                    const char* name) noexcept {
                    if (!root.isMember(name) || !root[name].isString()) {
                        return std::string();
                    }
                    return FromRuntimeJsonString(root[name].asString());
                }

                inline void WriteRuntimeError(
                    Json::Value& root,
                    const RuntimeError& error) noexcept {
                    Json::Value value(Json::objectValue);
                    value["code"] = error.code;
                    value["severity"] = ToRuntimeJsonString(error.severity);
                    value["retryable"] = error.retryable;
                    value["user_message_key"] = ToRuntimeJsonString(error.user_message_key);
                    value["diagnostic_detail"] = ToRuntimeJsonString(error.diagnostic_detail);
                    root["last_error"] = std::move(value);
                }

                inline void WriteRuntimeTraffic(
                    Json::Value& root,
                    const RuntimeTraffic& traffic) noexcept {
                    Json::Value value(Json::objectValue);
                    value["rx_bytes"] = Json::UInt64(traffic.rx_bytes);
                    value["tx_bytes"] = Json::UInt64(traffic.tx_bytes);
                    root["traffic"] = std::move(value);
                }

                inline void ReadRuntimeTraffic(
                    const Json::Value& root,
                    RuntimeTraffic& traffic) noexcept {
                    traffic = RuntimeTraffic();
                    if (!root.isMember("traffic") || !root["traffic"].isObject()) {
                        return;
                    }

                    const Json::Value& value = root["traffic"];
                    if (value.isMember("rx_bytes") && value["rx_bytes"].isUInt64()) {
                        traffic.rx_bytes = value["rx_bytes"].asUInt64();
                    }
                    if (value.isMember("tx_bytes") && value["tx_bytes"].isUInt64()) {
                        traffic.tx_bytes = value["tx_bytes"].asUInt64();
                    }
                }

                inline void ReadRuntimeError(
                    const Json::Value& root,
                    RuntimeError& error) noexcept {
                    error = RuntimeError();
                    if (!root.isMember("last_error") || !root["last_error"].isObject()) {
                        return;
                    }

                    const Json::Value& value = root["last_error"];
                    if (value.isMember("code") && value["code"].isUInt()) {
                        error.code = value["code"].asUInt();
                    }
                    if (value.isMember("severity") && value["severity"].isString()) {
                        error.severity = FromRuntimeJsonString(value["severity"].asString());
                    }
                    if (value.isMember("retryable") && value["retryable"].isBool()) {
                        error.retryable = value["retryable"].asBool();
                    }
                    if (value.isMember("user_message_key") && value["user_message_key"].isString()) {
                        error.user_message_key = FromRuntimeJsonString(value["user_message_key"].asString());
                    }
                    if (value.isMember("diagnostic_detail") && value["diagnostic_detail"].isString()) {
                        error.diagnostic_detail = FromRuntimeJsonString(value["diagnostic_detail"].asString());
                    }
                }

            }

            inline std::string SerializeRuntimeSnapshot(
                const RuntimeSnapshot& snapshot) noexcept {
                Json::Value root(Json::objectValue);
                root["schema_version"] = snapshot.schema_version;
                root["generation"] = Json::UInt64(snapshot.generation);
                root["monotonic_ms"] = Json::UInt64(snapshot.monotonic_ms);
                root["phase"] = ToString(snapshot.phase);
                root["role"] = detail::ToRuntimeJsonString(snapshot.role);
                root["server"] = detail::ToRuntimeJsonString(snapshot.server);
                root["transport"] = detail::ToRuntimeJsonString(snapshot.transport);
                Json::Value capabilities(Json::arrayValue);
                for (const std::string& capability : snapshot.capabilities) {
                    capabilities.append(detail::ToRuntimeJsonString(capability));
                }
                root["capabilities"] = std::move(capabilities);
                root["requested_mux_mode"] = detail::ToRuntimeJsonString(snapshot.requested_mux_mode);
                root["effective_mux_mode"] = detail::ToRuntimeJsonString(snapshot.effective_mux_mode);
                root["mux_receiver_ordering"] = detail::ToRuntimeJsonString(snapshot.mux_receiver_ordering);
                root["mux_scheduler"] = detail::ToRuntimeJsonString(snapshot.mux_scheduler);
                root["mux_pool_policy"] = detail::ToRuntimeJsonString(snapshot.mux_pool_policy);
                root["mux_turbo"] = snapshot.mux_turbo;
                root["mux_active_links"] = snapshot.mux_active_links;
                root["mux_fallback_reason"] = detail::ToRuntimeJsonString(snapshot.mux_fallback_reason);
                root["p2p_state"] = ppp::p2p::ToString(snapshot.p2p_state);
                root["effective_path"] = ppp::p2p::EffectivePath(snapshot.p2p_state);
                detail::WriteRuntimeTraffic(root, snapshot.traffic);
                root["connected_monotonic_ms"] = Json::UInt64(snapshot.connected_monotonic_ms);
                detail::WriteRuntimeError(root, snapshot.last_error);

                Json::FastWriter writer;
                const Json::String encoded = writer.write(root);
                std::string json = detail::FromRuntimeJsonString(encoded);
                while (!json.empty() && (json.back() == '\n' || json.back() == '\r')) {
                    json.pop_back();
                }
                return json;
            }

            inline bool ParseRuntimeSnapshot(
                const std::string& json,
                RuntimeSnapshot& snapshot) noexcept {
                if (json.empty()) {
                    return false;
                }

                Json::Reader reader;
                Json::Value root;
                if (!reader.parse(json.data(), json.data() + json.size(), root) || !root.isObject()) {
                    return false;
                }
                if (!root.isMember("schema_version") || !root["schema_version"].isUInt()) {
                    return false;
                }
                if (root["schema_version"].asUInt() != RuntimeSnapshot::SchemaVersion) {
                    return false;
                }
                if (!root.isMember("generation") || !root["generation"].isUInt64()) {
                    return false;
                }
                if (!root.isMember("monotonic_ms") || !root["monotonic_ms"].isUInt64()) {
                    return false;
                }
                if (!root.isMember("phase") || !root["phase"].isString()) {
                    return false;
                }

                const std::string phase_name = detail::RuntimeJsonString(root, "phase");
                const RuntimePhase phase = ParseRuntimePhase(phase_name);
                if (phase == RuntimePhase::Unknown && phase_name != "unknown") {
                    return false;
                }

                RuntimeSnapshot parsed;
                parsed.schema_version = root["schema_version"].asUInt();
                parsed.generation = root["generation"].asUInt64();
                parsed.monotonic_ms = root["monotonic_ms"].asUInt64();
                parsed.phase = phase;
                parsed.role = detail::RuntimeJsonString(root, "role");
                parsed.server = detail::RuntimeJsonString(root, "server");
                parsed.transport = detail::RuntimeJsonString(root, "transport");
                if (root.isMember("capabilities") && root["capabilities"].isArray()) {
                    for (const Json::Value& capability : root["capabilities"]) {
                        if (capability.isString()) {
                            parsed.capabilities.emplace_back(
                                detail::FromRuntimeJsonString(capability.asString()));
                        }
                    }
                }
                parsed.requested_mux_mode = detail::RuntimeJsonString(root, "requested_mux_mode");
                parsed.effective_mux_mode = detail::RuntimeJsonString(root, "effective_mux_mode");
                parsed.mux_receiver_ordering = detail::RuntimeJsonString(root, "mux_receiver_ordering");
                parsed.mux_scheduler = detail::RuntimeJsonString(root, "mux_scheduler");
                parsed.mux_pool_policy = detail::RuntimeJsonString(root, "mux_pool_policy");
                if (root.isMember("mux_turbo") && root["mux_turbo"].isBool()) {
                    parsed.mux_turbo = root["mux_turbo"].asBool();
                }
                if (root.isMember("mux_active_links") && root["mux_active_links"].isUInt()) {
                    parsed.mux_active_links = static_cast<std::uint16_t>(
                        std::min<unsigned int>(root["mux_active_links"].asUInt(), UINT16_MAX));
                }
                parsed.mux_fallback_reason = detail::RuntimeJsonString(root, "mux_fallback_reason");
                parsed.p2p_state = root.isMember("p2p_state")
                    ? ppp::p2p::ParseP2PState(
                        detail::RuntimeJsonString(root, "p2p_state"))
                    : ppp::p2p::P2PState::Disabled;
                detail::ReadRuntimeTraffic(root, parsed.traffic);
                if (root.isMember("connected_monotonic_ms") &&
                    root["connected_monotonic_ms"].isUInt64()) {
                    parsed.connected_monotonic_ms = root["connected_monotonic_ms"].asUInt64();
                }
                detail::ReadRuntimeError(root, parsed.last_error);

                snapshot = std::move(parsed);
                return true;
            }

        }
    }
}
