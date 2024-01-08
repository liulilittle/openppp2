#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <json/json.h>

namespace ppp {
    namespace auxiliary {
        class JsonAuxiliary final {
        public:
            static ppp::string              ToString(const Json::Value& json) noexcept;
            static ppp::string              ToStyledString(const Json::Value& json) noexcept;
            static Json::Value              FromString(const char* json_string, int json_size) noexcept;
            static Json::Value              FromString(const ppp::string& json) noexcept;

        public:
            static ppp::string              AsString(const Json::Value& json) noexcept;
            static Int64                    AsInt64(const Json::Value& json) noexcept;
            static UInt64                   AsUInt64(const Json::Value& json) noexcept;
            static double                   AsDouble(const Json::Value& json) noexcept;
            static Int128                   AsInt128(const Json::Value& json) noexcept;
            static bool                     AsBoolean(const Json::Value& json) noexcept;

        public:
            /* Please note that this template function does not use the if constexpr syntax provided by the C++17/-std=c++1z standard.
             * (which determines the branch of if at compile time). This is because future cross-platform portability considerations, 
             * Such as compiling with the clang++ toolchain provided by the Android NDK, NDK-r20b only support the C++11/14 language standards. 
             * If a higher standard is used, the written C++ code may not compile correctly.
             * 
             * Please note that when writing code for the Android NDK using clang++ with the LLVM libc++ standard library, 
             * It is important to be cautious and thoughtful due to the significant differences compared to VC++ and GNU C++ standard libraries.
             * 
             * Refer: https://developer.android.com/ndk/guides/cpp-support?hl=zh-cn
             */
            template <typename TValue>
            static TValue                   AsValue(const Json::Value& json) noexcept {
                if (std::is_same<TValue, float>::value || std::is_same<TValue, double>::value || std::is_same<TValue, long double>::value) {
                    return AsDouble(json);
                }
                elif(std::is_same<TValue, char>::value || std::is_same<TValue, short>::value || std::is_same<TValue, int>::value || std::is_same<TValue, long>::value || std::is_same<TValue, long long>::value) {
                    return AsInt64(json);
                }
                elif(std::is_same<TValue, bool>::value) {
                    return AsBoolean(json);
                }
                else {
                    return AsUInt64(json);
                }
            }
        };

        template <>
        inline Int128 JsonAuxiliary::AsValue<Int128>(const Json::Value& json) noexcept {
            return AsInt128(json);
        }

        template <>
        inline ppp::string JsonAuxiliary::AsValue<ppp::string>(const Json::Value& json) noexcept {
            return AsString(json);
        }

        template <>
        inline std::string JsonAuxiliary::AsValue<std::string>(const Json::Value& json) noexcept {
            return stl::transform<std::string>(AsString(json));
        }
    }
}