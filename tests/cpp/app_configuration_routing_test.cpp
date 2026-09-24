#include <cassert>
#include <fstream>
#include <sstream>
#include <string>

namespace {
    std::string ReadFile(const char* path) {
        std::ifstream stream(path, std::ios::binary);
        assert(stream.is_open());
        std::ostringstream contents;
        contents << stream.rdbuf();
        return contents.str();
    }

    void RequireContains(const std::string& source, const char* text) {
        assert(source.find(text) != std::string::npos);
    }
}

int main() {
    const std::string header = ReadFile("ppp/configurations/AppConfiguration.h");
    const std::string implementation = ReadFile("ppp/configurations/AppConfiguration.cpp");

    RequireContains(header, "bool                                                        tcp_domain_sniff;");
    RequireContains(implementation, "config.routing.tcp_domain_sniff = false;");
    RequireContains(implementation,
        "AssignBoolIfPresent(config.routing.tcp_domain_sniff, json[\"routing\"][\"tcp-domain-sniff\"]);");
    RequireContains(implementation,
        "root[\"routing\"][\"tcp-domain-sniff\"] = config.routing.tcp_domain_sniff;");
    return 0;
}
