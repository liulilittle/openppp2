#include <ppp/auxiliary/JsonAuxiliary.h>

namespace ppp {
    namespace auxiliary {
        ppp::string JsonAuxiliary::ToString(const Json::Value& json) noexcept {
            Json::FastWriter fw;
            ppp::string s = fw.write(json);
            s = RTrim(s);
            s = LTrim(s);
            return s;
        }

        ppp::string JsonAuxiliary::ToStyledString(const Json::Value& json) noexcept {
            ppp::string s = json.toStyledString();
            s = RTrim(s);
            s = LTrim(s);
            return s;
        }

        Json::Value JsonAuxiliary::FromString(const char* json_string, int json_size) noexcept {
            if (NULL == json_string) {
                return Json::Value();
            }

            if (json_size < 1) {
                return Json::Value();
            }

            if (*json_string == '\x0') {
                return Json::Value();
            }

            Json::Reader reader;
            Json::Value json;
            return reader.parse(json_string, json_string + json_size, json) ? json : Json::Value();
        }

        Json::Value JsonAuxiliary::FromString(const ppp::string& json) noexcept {
            return FromString(json.data(), (int)json.size());
        }

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

        Int64 JsonAuxiliary::AsInt64(const Json::Value& json) noexcept {
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
                if (IsNaN(d)) {
                    return 0;
                }

                return d;
            }
            else {
                return 0;
            }
        }

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