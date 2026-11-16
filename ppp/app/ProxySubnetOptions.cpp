#include <ppp/stdafx.h>
#include <ppp/app/ProxySubnetOptions.h>

namespace ppp::app {
    ProxySubnetOptions ParseProxySubnetOptions(int argc, const char* argv[]) noexcept {
        ProxySubnetOptions options;
        options.subnet = ppp::ToBoolean(ppp::GetCommandArgument("--proxy-subnet", argc, argv, "y").data());
        options.internet = ppp::ToBoolean(ppp::GetCommandArgument("--proxy-internet", argc, argv, "y").data());
        const ppp::string forwards = ppp::GetCommandArgument("--proxy-forward", argc, argv);
        auto port_number = [](const ppp::string& text) noexcept -> uint16_t {
            if (text.empty()) return 0;
            unsigned value = 0;
            for (char c : text) {
                if (c < '0' || c > '9') return 0;
                value = value * 10 + static_cast<unsigned>(c - '0');
                if (value > UINT16_MAX) return 0;
            }
            return static_cast<uint16_t>(value);
        };
        for (std::size_t begin = 0; begin < forwards.size();) {
            std::size_t end = forwards.find(',', begin);
            if (end == ppp::string::npos) end = forwards.size();
            const ppp::string item = ppp::RTrim(ppp::LTrim(forwards.substr(begin, end - begin)));
            const std::size_t colon = item.find(':');
            const uint16_t port = port_number(item.substr(0, colon));
            const uint16_t local = colon == ppp::string::npos ? port : port_number(item.substr(colon + 1));
            if (port != 0 && local != 0) options.forwards[port] = local;
            begin = end + 1;
        }
        return options;
    }

}
