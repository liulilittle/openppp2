#include <ppp/text/Encoding.h>

#include <locale>
#include <codecvt>
#include <string>
#include <vector>

namespace ppp {
    namespace text {
        std::wstring Encoding::utf8_to_wstring(const std::string& s) noexcept {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            return converter.from_bytes(s);
        }

        std::string Encoding::wstring_to_utf8(const std::wstring& s) noexcept {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            return converter.to_bytes(s);
        }

        std::wstring Encoding::ascii_to_wstring(const std::string& s) noexcept {
            return utf8_to_wstring(s);
        }

        std::wstring Encoding::ascii_to_wstring2(const std::string& s) noexcept {
            std::size_t len = mbstowcs(NULL, s.data(), 0);
            if (len == 0 || len == std::string::npos)
            {
                return std::wstring();
            }

            ppp::vector<wchar_t> buf(len + 1);
            return std::wstring(buf.data(), mbstowcs(&buf[0], s.data(), buf.size()));
        }

        std::string Encoding::wstring_to_ascii(const std::wstring& s) noexcept {
            std::size_t len = wcstombs(NULL, s.data(), 0);
            if (len == 0 || len == std::string::npos)
            {
                return std::string();
            }

            ppp::vector<char> buf(len + 1);
            return std::string(buf.data(), wcstombs(&buf[0], s.data(), buf.size()));
        }
    }
}