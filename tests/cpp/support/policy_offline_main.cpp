#include <ppp/app/ApplicationPolicyCommand.h>

#include <iostream>
#include <vector>

int main(int argc, char** argv) {
    std::vector<const char*> arguments(argv, argv + argc);
    auto result = ppp::app::ApplicationPolicyCommand::Dispatch(
        argc, arguments.data(), std::cout, std::cerr);
    if (result) return *result;
    std::cerr << "Offline policy CLI accepts only policy check and policy explain.\n";
    return 4;
}
