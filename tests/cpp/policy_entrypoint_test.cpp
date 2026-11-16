#define BOOST_TEST_MODULE policy_entrypoint_test
#include <boost/test/included/unit_test.hpp>

#include <sstream>

// Compile the real entry point against a counting facade, without the runtime.
#define main PolicyEntryPoint
#include "../../main.cpp"
#undef main

namespace {
int startup_calls = 0;
int forwarded_argc = 0;
char** forwarded_argv = nullptr;

class CaptureOutput final {
public:
    CaptureOutput() : out_(std::cout.rdbuf(output.rdbuf())), err_(std::cerr.rdbuf(error.rdbuf())) {}
    ~CaptureOutput() {
        std::cout.rdbuf(out_);
        std::cerr.rdbuf(err_);
    }
    std::ostringstream output;
    std::ostringstream error;
private:
    std::streambuf* out_;
    std::streambuf* err_;
};
}

namespace ppp::facade {
int RunApplication(int argc, char** argv) noexcept {
    ++startup_calls;
    forwarded_argc = argc;
    forwarded_argv = argv;
    return 37;
}
}

BOOST_AUTO_TEST_CASE(policy_errors_never_enter_runtime) {
    CaptureOutput capture;
    startup_calls = 0;
    char program[] = "ppp";
    char policy[] = "policy";
    char unknown[] = "unknown";
    char* argv[] = {program, policy, unknown};
    BOOST_TEST(PolicyEntryPoint(3, argv) == 2);
    BOOST_TEST(startup_calls == 0);
    char check[] = "check";
    char config[] = "--config";
    char missing[] = "__openppp2_policy_entry_missing__.json";
    char runtime[] = "--runtime";
    char tun[] = "tun";
    char* unavailable[] = {program, policy, check, config, missing, runtime, tun};
    BOOST_TEST(PolicyEntryPoint(7, unavailable) == 3);
    BOOST_TEST(startup_calls == 0);
}

BOOST_AUTO_TEST_CASE(legacy_arguments_reach_original_facade_unchanged) {
    startup_calls = 0;
    char program[] = "ppp";
    char help[] = "--help";
    char* argv[] = {program, help};
    BOOST_TEST(PolicyEntryPoint(2, argv) == 37);
    BOOST_TEST(startup_calls == 1);
    BOOST_TEST(forwarded_argc == 2);
    BOOST_TEST(static_cast<void*>(forwarded_argv) == static_cast<void*>(argv));
}

BOOST_AUTO_TEST_CASE(successful_policy_command_also_stays_offline) {
    CaptureOutput capture;
    startup_calls = 0;
    char program[] = "ppp";
    char policy[] = "policy";
    char check[] = "check";
    char config[] = "--config";
    char path[] = OPENPPP2_POLICY_EXAMPLE_CONFIG;
    char runtime[] = "--runtime";
    char tun[] = "tun";
    char platform[] = "--platform";
    char android[] = "android";
    char* argv[] = {program, policy, check, config, path, runtime, tun, platform, android};
    BOOST_TEST(PolicyEntryPoint(9, argv) == 0);
    BOOST_TEST(startup_calls == 0);
}
