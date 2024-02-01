#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>

namespace ppp {
    namespace auxiliary {
        class StringAuxiliary final {
        public:
            static unsigned char                        ToHex(unsigned char x) noexcept {
                return x > 9 ? x + 55 : x + 48;
            }
            static unsigned char                        FromHex(unsigned char x) noexcept {
                unsigned char y;
                if (x >= 'A' && x <= 'Z') {
                    y = x - 'A' + 10;
                }
                else if (x >= 'a' && x <= 'z') {
                    y = x - 'a' + 10;
                }
                else if (x >= '0' && x <= '9') {
                    y = x - '0';
                }
                else {
                    y = '\x0';
                }
                return y;
            }

        public:
            static Int128                               GuidStringToInt128(const ppp::string& guid_string) noexcept;
            static ppp::string                          Int128ToGuidString(const Int128& guid) noexcept;
            static bool                                 WhoisIntegerValueString(const ppp::string& integer_string) noexcept;
        };
    }
}