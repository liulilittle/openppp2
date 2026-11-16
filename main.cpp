/**
 * @file main.cpp
 * @brief Program entry point for launching the PPP application.
 */

#include <ppp/facade/ApplicationBootstrap.h>
#include <ppp/app/ApplicationPolicyCommand.h>
#include <ppp/app/client/NetworkRecoveryJournal.h>
#include <iostream>

/**
 * @brief Starts the PPP application and reports startup failures.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return Exit code returned by the application runtime.
 */
int main(int argc, char** argv) {
    if (ppp::app::client::NetworkRecoveryJournal::IsRecoveryCommand(
            argc, const_cast<const char* const*>(argv))) {
        return ppp::app::client::NetworkRecoveryJournal::RunRecoveryCommand(
            argc, const_cast<const char* const*>(argv));
    }
    if (auto result = ppp::app::ApplicationPolicyCommand::Dispatch(argc, argv, std::cout, std::cerr)) {
        return *result;
    }
    return ppp::facade::RunApplication(argc, argv);
}
