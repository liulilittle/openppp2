#pragma once

#include "LegacyPolicyAdapter.h"
#include "PolicyCompiler.h"

#include <json/json.h>

namespace ppp::app::client::policy {

struct LegacyPolicyMigrationResult final {
    std::string rules_text;
    Json::Value policy_config{Json::objectValue};
    Json::Value report{Json::objectValue};
    bool routing_equivalent = false;
    bool complete = false;
};

class LegacyPolicyMigration final {
public:
    static LegacyPolicyMigrationResult CreateDraft(const LegacyPolicyModel& legacy,
        const std::string& output_config_path,
        const std::string& runtime = {}, const std::string& platform = {});
};

} // namespace ppp::app::client::policy
