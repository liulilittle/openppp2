/**
 * @file JsonAuxiliary.cpp
 * @brief Implementation of JSON serialization and typed conversion helpers.
 */
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/diagnostics/Error.h>

#include <cmath>

namespace ppp {
    namespace auxiliary {
        /**
         * @brief Serialize a JSON value into compact JSON text.
         */
        ppp::string JsonAuxiliary::ToString(const Json::Value& json) noexcept {
            Json::FastWriter fw;
            ppp::string s = fw.write(json);
            s = RTrim(s);
            s = LTrim(s);
            return s;
        }

        /**
         * @brief Serialize a JSON value into pretty-printed JSON text.
         */
        ppp::string JsonAuxiliary::ToStyledString(const Json::Value& json) noexcept {
            ppp::string s = json.toStyledString();
            s = RTrim(s);
            s = LTrim(s);
            return s;
        }

        /**
         * @brief Parse JSON from a raw character buffer.
         */
        Json::Value JsonAuxiliary::FromString(const char* json_string, int json_size) noexcept {
            if (NULLPTR == json_string) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::JsonAuxiliaryFromStringNullInput);
                return Json::Value();
            }

            if (json_size < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::JsonAuxiliaryFromStringInvalidSize);
                return Json::Value();
            }

            if (*json_string == '\x0') {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::JsonAuxiliaryFromStringInputEmpty);
                return Json::Value();
            }

            Json::Reader reader;
            Json::Value json;
            if (!reader.parse(json_string, json_string + json_size, json)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::JsonAuxiliaryFromStringParseFailed);
                return Json::Value();
            }

            return json;
        }

        /**
         * @brief Parse JSON from a string object.
         */
        Json::Value JsonAuxiliary::FromString(const ppp::string& json) noexcept {
            return FromString(json.data(), (int)json.size());
        }

        /**
         * @brief Convert scalar JSON values into textual form.
         */
        ppp::string JsonAuxiliary::AsString(const Json::Value& json) noexcept {
            if (json.isNull()) {
                return ppp::string();
            }

            if (json.isUInt64()) {
                return stl::to_string<ppp::string>(json.asUInt64());
            }

            if (json.isInt64()) {
                return stl::to_string<ppp::string>(json.asInt64());
            }

            if (json.isDouble()) {
                double d = json.asDouble();
                if (IsNaN(d)) {
                    d = 0;
                }

                return stl::to_string<ppp::string>(d);
            }

            if (json.isBool()) {
                return json.asBool() ? "true" : "false";
            }

            if (json.isString()) {
                return json.asString();
            }

            return ppp::string();
        }

        /**
         * @brief Convert a JSON value to signed 64-bit integer with fallback.
         */
        Int64 JsonAuxiliary::AsInt64(const Json::Value& json, Int64 default_value) noexcept {
            if (json.isInt64()) {
                return json.asInt64();
            }
            elif(json.isUInt64()) {
                return json.asUInt64();
            }
            elif(json.isBool()) {
                return json.asBool() ? 1 : 0;
            }
            elif(json.isDouble()) {
                double d = json.asDouble();
                /** @brief 2^63 is exactly representable; valid range is [-2^63, 2^63). */
                if (IsNaN(d) || !std::isfinite(d) || d < -9223372036854775808.0 || d >= 9223372036854775808.0) {
                    return default_value;
                }

                return static_cast<Int64>(d);
            }
            else {
                return default_value;
            }
        }

        /**
         * @brief Convert a JSON value to unsigned 64-bit integer.
         */
        UInt64 JsonAuxiliary::AsUInt64(const Json::Value& json) noexcept {
            if (json.isUInt64()) {
                return json.asUInt64();
            }
            elif(json.isInt64()) {
                return json.asInt64();
            }
            elif(json.isBool()) {
                return json.asBool() ? 1 : 0;
            }
            elif(json.isDouble()) {
                double d = json.asDouble();
                if (IsNaN(d)) {
                    return 0;
                }

                return d;
            }
            else {
                return 0;
            }
        }

        /**
         * @brief Convert a JSON value to double precision value.
         */
        double JsonAuxiliary::AsDouble(const Json::Value& json) noexcept {
            if (json.isDouble()) {
                double d = json.asDouble();
                if (IsNaN(d)) {
                    return 0;
                }

                return d;
            }
            elif(json.isInt64()) {
                return json.asInt64();
            }
            elif(json.isUInt64()) {
                return json.asUInt64();
            }
            elif(json.isBool()) {
                return json.asBool() ? 1 : 0;
            }
            else {
                return 0;
            }
        }

        /**
         * @brief Convert a JSON value to 128-bit integer.
         */
        Int128 JsonAuxiliary::AsInt128(const Json::Value& json) noexcept {
            if (json.isDouble()) {
                double d = json.asDouble();
                if (IsNaN(d)) {
                    return 0;
                }

                return (int64_t)d;
            }
            elif(json.isInt64()) {
                return json.asInt64();
            }
            elif(json.isUInt64()) {
                return json.asUInt64();
            }
            elif(json.isBool()) {
                return json.asBool() ? 1 : 0;
            }
            else {
                return 0;
            }
        }

        /**
         * @brief Convert a JSON value into boolean semantics.
         */
        bool JsonAuxiliary::AsBoolean(const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            if (json.isArray()) {
                return true;
            }

            if (json.isObject()) {
                return true;
            }

            if (json.isDouble()) {
                double d = json.asDouble();
                if (IsNaN(d)) {
                    return false;
                }

                return d != 0;
            }

            if (json.isInt64()) {
                return json.asInt64() != 0;
            }

            if (json.isUInt64()) {
                return json.asUInt64() != 0;
            }

            if (json.isBool()) {
                return json.asBool();
            }

            if (json.isString()) {
                ppp::string v = AsString(json);
                if (v.empty()) {
                    return false;
                }

                return ToBoolean(v.data());
            }

            return false;
        }
    }
}
