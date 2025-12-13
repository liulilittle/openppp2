#include <ppp/text/Encoding.h>

#include <locale>
#include <codecvt>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <atlconv.h>

#include <windows/ppp/win32/Win32Native.h>
#endif

namespace ppp {
    namespace text {
        std::wstring Encoding::utf8_to_wstring(const std::string& s) noexcept {
#if defined(_WIN32)
            return ppp::win32::Win32Native::_A2W(s);
#else
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            try {
                return converter.from_bytes(s);
            }
            catch (const std::exception&) {
                return ascii_to_wstring2(s);
            }
#endif
        }

        std::string Encoding::wstring_to_utf8(const std::wstring& s) noexcept {
#if defined(_WIN32)
            return ppp::win32::Win32Native::_W2A(s);
#else
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            try {
                return converter.to_bytes(s);
            }
            catch (const std::exception&) {
                return wstring_to_ascii(s);
            }
#endif
        }

        std::wstring Encoding::ascii_to_wstring(const std::string& s) noexcept {
            return utf8_to_wstring(s);
        }

        std::wstring Encoding::ascii_to_wstring2(const std::string& s) noexcept {
            std::size_t len = mbstowcs(NULL, s.data(), 0);
            if (len == 0 || len == std::string::npos) {
                return std::wstring();
            }

            ppp::vector<wchar_t> buf(len + 1);
            return std::wstring(buf.data(), mbstowcs(&buf[0], s.data(), buf.size()));
        }

        std::string Encoding::wstring_to_ascii(const std::wstring& s) noexcept {
            std::size_t len = wcstombs(NULL, s.data(), 0);
            if (len == 0 || len == std::string::npos) {
                return std::string();
            }

            ppp::vector<char> buf(len + 1);
            return std::string(buf.data(), wcstombs(&buf[0], s.data(), buf.size()));
        }
    }
}