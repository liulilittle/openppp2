#include "ppp/app/client/xtcp/XtcpDirectBridgePolicy.h"

#include <cstdio>
#include <initializer_list>

int main() {
    struct Case {
        const char* value;
        bool expected_off;
        bool expected_on;
    };
    const Case cases[] = {
        {nullptr, false, true},
        {"", false, true},
        {"1", true, true},
        {"0", false, false},
        {"true", false, false},
        {"01", false, false},
        {"10", false, false},
        {"1 ", false, false},
        {" 1", false, false},
        {"\n", false, false},
    };
    for (const auto& test : cases) {
        for (bool platform_default : {false, true}) {
            const bool expected = platform_default ? test.expected_on : test.expected_off;
            if (ppp::app::client::xtcp::DirectBridgeEnabled(test.value, platform_default) != expected) {
                std::fprintf(stderr, "DirectBridgeEnabled failed: value=%s default=%d\n",
                    test.value ? test.value : "<unset>", platform_default);
                return 1;
            }
        }
    }
    std::puts("XTCP direct bridge policy: 20 checks passed");
    return 0;
}
