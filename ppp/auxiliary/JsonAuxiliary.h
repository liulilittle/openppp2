/**
 * @file JsonAuxiliary.h
 * @brief JSON conversion helpers for serialization and typed extraction.
 */
#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <json/json.h>
#include <limits.h>

namespace ppp {
    namespace auxiliary {
        /**
         * @brief Utility class for converting between JSON values and native types.
         */
        class JsonAuxiliary final {
        public:
            /**
             * @brief Serialize a JSON value into a compact string.
             * @param json Source JSON value.
             * @return Trimmed compact JSON text.
             */
            static ppp::string              ToString(const Json::Value& json) noexcept;
            /**
             * @brief Serialize a JSON value into a formatted string.
             * @param json Source JSON value.
             * @return Trimmed pretty-printed JSON text.
             */
            static ppp::string              ToStyledString(const Json::Value& json) noexcept;
            /**
             * @brief Parse JSON text from a raw character buffer.
             * @param json_string Pointer to JSON character data.
             * @param json_size Number of bytes to parse.
             * @return Parsed JSON value, or null JSON when parsing fails.
             */
            static Json::Value              FromString(const char* json_string, int json_size) noexcept;
            /**
             * @brief Parse JSON text from a string object.
             * @param json JSON string.
             * @return Parsed JSON value, or null JSON when parsing fails.
             */
            static Json::Value              FromString(const ppp::string& json) noexcept;

        public:
            /**
             * @brief Convert a JSON value to string form.
             * @param json Source JSON value.
             * @return String representation for scalar values; empty string otherwise.
             */
            static ppp::string              AsString(const Json::Value& json) noexcept;
            /**
             * @brief Convert a JSON value to signed 64-bit integer.
             * @param json Source JSON value.
             * @param default_value Fallback value when conversion is not possible.
             * @return Converted integer value or fallback.
             */
            static Int64                    AsInt64(const Json::Value& json, Int64 default_value) noexcept;
            /**
             * @brief Convert a JSON value to signed 64-bit integer.
             * @param json Source JSON value.
             * @return Converted integer value, or 0 when conversion is not possible.
             */
            static Int64                    AsInt64(const Json::Value& json) noexcept {
                return AsInt64(json, 0);
            }

            /**
             * @brief Convert a JSON value to int; returns default_value when the value does not fit in int.
             */
            static int                      AsInt(const Json::Value& json, int default_value) noexcept {
                Int64 v = AsInt64(json, default_value);
                if (v < INT_MIN || v > INT_MAX) {
                    return default_value;
                }

                return static_cast<int>(v);
            }
            /**
             * @brief Convert a JSON value to unsigned 64-bit integer.
             * @param json Source JSON value.
             * @return Converted unsigned integer value, or 0 on failure.
             */
            static UInt64                   AsUInt64(const Json::Value& json) noexcept;
            /**
             * @brief Convert a JSON value to double precision floating point.
             * @param json Source JSON value.
             * @return Converted floating-point value, or 0 on failure.
             */
            static double                   AsDouble(const Json::Value& json) noexcept;
            /**
             * @brief Convert a JSON value to 128-bit integer.
             * @param json Source JSON value.
             * @return Converted 128-bit integer value, or 0 on failure.
             */
            static Int128                   AsInt128(const Json::Value& json) noexcept;
            /**
             * @brief Convert a JSON value to boolean.
             * @param json Source JSON value.
             * @return Boolean interpretation of the value.
             */
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
            /**
             * @brief Convert a JSON value to a target arithmetic/string-like type.
             * @tparam TValue Target type.
             * @param json Source JSON value.
             * @return Converted value based on the target type category.
             */
            static TValue                   AsValue(const Json::Value& json) noexcept {
                if (std::is_same<TValue, float>::value || std::is_same<TValue, double>::value || std::is_same<TValue, long double>::value) {
                    return AsDouble(json);
                }
                elif(std::is_same<TValue, char>::value || std::is_same<TValue, short>::value || std::is_same<TValue, int>::value || std::is_same<TValue, long>::value || std::is_same<TValue, long long>::value) {
                    if (std::is_same<TValue, int>::value) {
                        return static_cast<TValue>(AsInt(json, 0));
                    }

                    return static_cast<TValue>(AsInt64(json));
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
        /**
         * @brief Int128 specialization for AsValue.
         * @param json Source JSON value.
         * @return Converted Int128 value.
         */
        inline Int128 JsonAuxiliary::AsValue<Int128>(const Json::Value& json) noexcept {
            return AsInt128(json);
        }

        template <>
        /**
         * @brief ppp::string specialization for AsValue.
         * @param json Source JSON value.
         * @return Converted string value.
         */
        inline ppp::string JsonAuxiliary::AsValue<ppp::string>(const Json::Value& json) noexcept {
            return AsString(json);
        }

        template <>
        /**
         * @brief std::string specialization for AsValue.
         * @param json Source JSON value.
         * @return Converted std::string value.
         */
        inline std::string JsonAuxiliary::AsValue<std::string>(const Json::Value& json) noexcept {
            return stl::transform<std::string>(AsString(json));
        }
    }
}
