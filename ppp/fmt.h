#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    template <class TString = string>
    class fmt
    {
    public:
        template <typename S, typename ...T>
        static TString                  format(const S& fmt, T ... args) noexcept
        {
            TString str;
            if constexpr (std::is_same<S, TString>::value)
            {
                str = fmt;
            }
            else if constexpr (std::is_same<S, std::string_view>::value)
            {
                str = TString(fmt.data(), fmt.size());
            }
            else if constexpr (std::is_same<S, std::string>::value) 
            {
                str = TString(fmt.data(), fmt.size());
            }
            else if constexpr (std::is_same<S, ppp::string>::value) 
            {
                str = TString(fmt.data(), fmt.size());
            }
            else
            {
                str = fmt;
            }

            (..., format_string(str, args));
            return str;
        }

        template <typename OutputIt, typename ...T>
        static void                     format_to(OutputIt&& out, const TString& fmt, T ... args)
        {
            TString result = format(fmt, std::forward<T&&>(args)...);
            for (char ch : result)
            {
                *out = ch;
            }
        }

    private:
        template <typename T>
        static TString                  to_string(const T& value) noexcept
        {
            if constexpr (std::is_same<T, bool>::value)
            {
                return value ? "true" : "false";
            }
            else if constexpr (std::is_pointer<T>::value)
            {
                using DECAY_T = typename std::decay<T>::type;

                if constexpr (std::is_same<char*, DECAY_T>::value || std::is_same<const char*, DECAY_T>::value)
                {
                    return value ? value : "";
                }
                else
                {
                    if (value)
                    {
                        char buf[sizeof(value) << 2];
                        snprintf(buf, sizeof(buf), "%p", reinterpret_cast<const void*>(value));
                        return buf;
                    }
                    return "null";
                }
            }
            else if constexpr (std::is_same<T, TString>::value)
            {
                return value;
            }
            else if constexpr (std::is_same<T, std::string_view>::value)
            {
                return TString(value.data(), value.size());
            }
            else if constexpr (std::is_same<T, std::string>::value) 
            {
                return TString(value.data(), value.size());
            }
            else if constexpr (std::is_same<T, ppp::string>::value) 
            {
                return TString(value.data(), value.size());
            }
            else
            {
                std::string result = std::to_string(value);
                return TString(result.data(), result.size());
            }
        }

        template <typename T>
        static TString                  to_string(const std::shared_ptr<T>& value) noexcept
        {
            return fmt::to_string(value.get());
        }

        template <typename T>
        static void                     format_string(TString& out, const T& value) noexcept
        {
            replace_string(out, "{}", fmt::to_string(value));
        }

    public:
        static bool                     replace_string(TString& str, const std::string_view& old_string, const std::string_view& new_string) noexcept
        {
            size_t pos = str.find(old_string);
            if (pos == TString::npos)
            {
                return false;
            }

            str.replace(pos, old_string.length(), new_string);
            return true;
        }
    };
}