#include <ppp/stdafx.h>

#include <cmath>

namespace ppp {

bool IsNaN(double value) noexcept {
    return std::isnan(value);
}

bool ToBoolean(const char* value) noexcept {
    if (NULLPTR == value || *value == '\x0') {
        return false;
    }

    const char first = value[0];
    return first != '0' && first != ' ' &&
        first != 'f' && first != 'F' &&
        first != 'n' && first != 'N' &&
        first != 'c' && first != 'C';
}

} // namespace ppp
