#pragma once

#include "PolicyModel.h"
#include <json/json.h>

namespace ppp::app::client::policy {

struct PolicyLoadResult {
    PolicySource source;
    std::vector<PolicyDiagnostic> diagnostics;
    bool Ok() const noexcept {
        for (const auto& item : diagnostics) if (item.severity == "error") return false;
        return true;
    }
};

class PolicySourceLoader final {
public:
    static PolicyLoadResult LoadFile(const std::string& config_path);
    static PolicyLoadResult LoadDeclarationsFile(const std::string& config_path);
    // config_path establishes the resource base directory even for in-memory JSON.
    static PolicyLoadResult Load(const Json::Value& config, const std::string& config_path);
    static PolicyLoadResult LoadDeclarations(const Json::Value& config, const std::string& config_path);

private:
    static PolicyLoadResult LoadInternal(const Json::Value& config, const std::string& config_path,
        bool declarations_only);
    static PolicyLoadResult LoadFileInternal(const std::string& config_path, bool declarations_only);
};

} // namespace ppp::app::client::policy
