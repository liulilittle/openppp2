#pragma once

#include <iosfwd>
#include <optional>

namespace ppp::app {

class ApplicationPolicyCommand final {
public:
    // An empty result leaves the original arguments to the legacy application.
    static std::optional<int> Dispatch(int argc, const char* const* argv,
        std::ostream& output, std::ostream& error);
};

} // namespace ppp::app
