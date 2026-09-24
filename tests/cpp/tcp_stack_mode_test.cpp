#define BOOST_TEST_MODULE tcp_stack_mode_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/TcpStackMode.h>

using ppp::app::GetTcpStackModeName;
using ppp::app::ResolveTcpStackMode;
using ppp::app::TcpStackMode;
using ppp::app::TcpStackModeOptions;
using ppp::app::TcpStackModeResult;
using ppp::app::TcpStackModeStatus;

namespace {

TcpStackModeOptions MakeOptions(
    bool platform_default_lwip,
    bool tcp_stack_specified = false,
    std::string_view tcp_stack_value = {},
    bool legacy_lwip_specified = false,
    bool legacy_lwip_value = false,
    bool xtcp_available = false) {
    TcpStackModeOptions options;
    options.PlatformDefaultLwip = platform_default_lwip;
    options.TcpStackSpecified = tcp_stack_specified;
    options.TcpStackValue = tcp_stack_value;
    options.LegacyLwipSpecified = legacy_lwip_specified;
    options.LegacyLwipValue = legacy_lwip_value;
    options.XtcpAvailable = xtcp_available;
    return options;
}

void CheckResult(const TcpStackModeResult& result, TcpStackModeStatus status, TcpStackMode mode) {
    BOOST_TEST(static_cast<int>(result.Status) == static_cast<int>(status));
    BOOST_TEST(static_cast<int>(result.Mode) == static_cast<int>(mode));
}

} // namespace

BOOST_AUTO_TEST_CASE(platform_defaults_preserve_legacy_behavior) {
    CheckResult(ResolveTcpStackMode(MakeOptions(true)), TcpStackModeStatus::Success, TcpStackMode::Lwip);
    CheckResult(ResolveTcpStackMode(MakeOptions(false)), TcpStackModeStatus::Success, TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(legacy_lwip_yes_and_no_override_platform_default) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, false, {}, true, true)),
        TcpStackModeStatus::Success,
        TcpStackMode::Lwip);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(true, false, {}, true, false)),
        TcpStackModeStatus::Success,
        TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(explicit_tcp_stack_values_are_strictly_selected) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(true, true, "native")),
        TcpStackModeStatus::Success,
        TcpStackMode::Native);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "lwip")),
        TcpStackModeStatus::Success,
        TcpStackMode::Lwip);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "xtcp", false, false, true)),
        TcpStackModeStatus::Success,
        TcpStackMode::Xtcp);
}

BOOST_AUTO_TEST_CASE(invalid_tcp_stack_values_are_rejected) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "LWIP")),
        TcpStackModeStatus::InvalidValue,
        TcpStackMode::Native);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "")),
        TcpStackModeStatus::InvalidValue,
        TcpStackMode::Native);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, " lwip")),
        TcpStackModeStatus::InvalidValue,
        TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(same_value_dual_arguments_succeed) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "lwip", true, true)),
        TcpStackModeStatus::Success,
        TcpStackMode::Lwip);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(true, true, "native", true, false)),
        TcpStackModeStatus::Success,
        TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(conflicting_dual_arguments_are_rejected) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "lwip", true, false)),
        TcpStackModeStatus::ExplicitConflict,
        TcpStackMode::Native);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "native", true, true)),
        TcpStackModeStatus::ExplicitConflict,
        TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(xtcp_conflicts_with_any_explicit_legacy_argument) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "xtcp", true, false, true)),
        TcpStackModeStatus::ExplicitConflict,
        TcpStackMode::Native);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "xtcp", true, true, true)),
        TcpStackModeStatus::ExplicitConflict,
        TcpStackMode::Native);
}

BOOST_AUTO_TEST_CASE(xtcp_requires_build_availability) {
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "xtcp", false, false, false)),
        TcpStackModeStatus::XtcpUnavailable,
        TcpStackMode::Xtcp);
    CheckResult(
        ResolveTcpStackMode(MakeOptions(false, true, "xtcp", false, false, true)),
        TcpStackModeStatus::Success,
        TcpStackMode::Xtcp);
}

BOOST_AUTO_TEST_CASE(mode_names_are_stable) {
    BOOST_TEST(std::string(GetTcpStackModeName(TcpStackMode::Native)) == "native");
    BOOST_TEST(std::string(GetTcpStackModeName(TcpStackMode::Lwip)) == "lwip");
    BOOST_TEST(std::string(GetTcpStackModeName(TcpStackMode::Xtcp)) == "xtcp");
}
