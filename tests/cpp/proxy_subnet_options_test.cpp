#include <ppp/app/ProxySubnetOptions.h>
#include <ppp/diagnostics/Error.h>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void Require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

int main() {
    try {
        const char* defaults[] = {"offline-test"};
        auto options = ppp::app::ParseProxySubnetOptions(1, defaults);
        Require(options.subnet && options.internet && options.forwards.empty(), "defaults");
        for (const char* subnet : {"yes", "no"}) {
            for (const char* internet : {"yes", "no"}) {
                const std::string s = std::string("--proxy-subnet=") + subnet;
                const std::string i = std::string("--proxy-internet=") + internet;
                const char* args[] = {"offline-test", s.c_str(), i.c_str(), "--proxy-forward=22,8080:3000,65535:1"};
                options = ppp::app::ParseProxySubnetOptions(4, args);
                Require(options.subnet == (std::string(subnet) == "yes"), "subnet flag");
                Require(options.internet == (std::string(internet) == "yes"), "internet flag");
                Require(options.forwards.size() == 3 && options.forwards.at(22) == 22 &&
                    options.forwards.at(8080) == 3000 && options.forwards.at(65535) == 1, "forwards");
            }
        }
        const char* separate[] = {"offline-test", "--proxy-subnet", "no", "--proxy-internet", "no",
            "--proxy-forward", "22:2222,22:2223,0,65536,1:0,2:65536,-3,4x,5:6x,7:8:9,999999999999999999999"};
        options = ppp::app::ParseProxySubnetOptions(7, separate);
        Require(!options.subnet && !options.internet, "separate flag values");
        Require(options.forwards.size() == 1 && options.forwards.at(22) == 2223, "invalid ports / last mapping wins");
        for (bool internet : {false, true}) {
            for (bool subnet : {false, true}) {
                Require(ppp::app::ProxyDestinationAllowed(internet, subnet) == (internet || subnet), "refusal matrix");
            }
        }
        const std::string root = OPENPPP2_SOURCE_ROOT;
        for (const char* name : {"VEthernetLocalProxyConnection.cpp", "VEthernetSocksProxyConnection.cpp"}) {
            std::ifstream file(root + "/ppp/app/client/proxys/" + name);
            const std::string source((std::istreambuf_iterator<char>(file)), {});
            const auto gate = source.find("ProxyDestinationAllowed(");
            const auto refusal = source.find("ErrorCode::ProxyInternetDisabled", gate);
            Require(gate != std::string::npos && refusal != std::string::npos, "production refusal gate");
            if (std::string(name) == "VEthernetSocksProxyConnection.cpp") {
                Require(refusal < source.find("exchanger->TrySendToPinned("), "UDP refusal before pinned dispatch");
            }
        }
        std::cout << "proxy subnet options: defaults, 4 modes, forward validation, refusal matrix, 2 production gates passed\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
