#include <common/chnroutes2/chnroutes2.h>
#include <cstdlib>

// Mock exchange tests must never enter the real TLS adapter or read trust paths.
ppp::string chnroutes2_cacertpath_default() noexcept {
    std::abort();
}
