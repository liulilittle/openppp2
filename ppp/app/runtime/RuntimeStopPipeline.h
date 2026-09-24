#pragma once

#include <functional>

namespace ppp::app::runtime {

enum class RuntimeStopStep {
    None,
    StopInput,
    Dns,
    Exchanger,
    Route,
};

struct RuntimeStopActions final {
    std::function<bool()> stop_input;
    std::function<bool()> close_dns;
    std::function<bool()> dispose_exchanger;
    std::function<bool()> rollback_route;
};

struct RuntimeStopResult final {
    bool success = true;
    RuntimeStopStep first_failed_step = RuntimeStopStep::None;
};

class RuntimeStopPipeline final {
public:
    static RuntimeStopResult Execute(const RuntimeStopActions& actions) noexcept {
        RuntimeStopResult result;
        Run(actions.stop_input, RuntimeStopStep::StopInput, result);
        Run(actions.close_dns, RuntimeStopStep::Dns, result);
        Run(actions.dispose_exchanger, RuntimeStopStep::Exchanger, result);
        Run(actions.rollback_route, RuntimeStopStep::Route, result);
        return result;
    }

private:
    static void Run(
        const std::function<bool()>& action,
        RuntimeStopStep step,
        RuntimeStopResult& result) noexcept {
        bool success = true;
        try {
            success = !action || action();
        }
        catch (...) {
            success = false;
        }
        if (!success && result.success) {
            result.success = false;
            result.first_failed_step = step;
        }
    }
};

}
