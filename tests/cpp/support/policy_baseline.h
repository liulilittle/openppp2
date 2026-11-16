#pragma once

// Test-only interchange contract. A future evaluator can emit the same report
// without sharing any of the current implementation's matching/priority code.
#include <json/json.h>

#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace policy_baseline {

inline std::string Text(const Json::String& value) {
    return std::string(value.data(), value.size());
}

inline void Require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

inline Json::Value ReadJson(const std::string& path) {
    std::ifstream input(path);
    Require(input.is_open(), "cannot open fixture/report: " + path);
    Json::CharReaderBuilder builder;
    builder["rejectDupKeys"] = true;
    builder["failIfExtra"] = true;
    Json::Value value;
    Json::String error;
    const bool parsed = Json::parseFromStream(builder, input, &value, &error);
    Require(parsed,
        "invalid JSON in " + path + ": " + Text(error));
    return value;
}

inline std::string Encode(const Json::Value& value) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    return Text(Json::writeString(builder, value));
}

using Results = std::map<std::string, Json::Value>;

inline Results Index(const Json::Value& rows, const char* value_key) {
    Require(rows.isArray() && !rows.empty(), "cases/results must be a nonempty array");
    Results result;
    for (const auto& row : rows) {
        Require(row.isObject() && row["id"].isString() && !row["id"].asString().empty(),
            "case/result must have a nonempty string id");
        const std::string id = Text(row["id"].asString());
        Require(row[value_key].isObject(), id + ": missing object " + value_key);
        Require(result.emplace(id, row[value_key]).second, "duplicate case/result id: " + id);
    }
    return result;
}

inline void ValidateFixture(const Json::Value& fixture) {
    Require(fixture.isObject() && fixture["schema"].isInt() && fixture["schema"].asInt() == 1,
        "unsupported fixture schema");
    Index(fixture["cases"], "expected");
    for (const auto& row : fixture["cases"]) {
        Require(row["kind"].isString() && !row["kind"].asString().empty() && row["input"].isObject(),
            Text(row["id"].asString()) + ": missing kind/input");
    }
}

// Report every changed leaf, not just the first mismatch. Missing/extra cases
// and fields also fail: a future adapter must not silently omit unsupported data.
inline void Diff(const Json::Value& expected, const Json::Value& actual,
    const std::string& path, std::vector<std::string>& differences) {
    // JSON has no unsigned integer type. JsonCpp may store a parsed positive
    // integer as signed and an evaluator's count as unsigned; compare values.
    const bool expected_integer = expected.type() == Json::intValue || expected.type() == Json::uintValue;
    const bool actual_integer = actual.type() == Json::intValue || actual.type() == Json::uintValue;
    if (expected_integer && actual_integer) {
        if (expected.isInt64() && actual.isInt64() && expected.asInt64() == actual.asInt64()) return;
        if (expected.isUInt64() && actual.isUInt64() && expected.asUInt64() == actual.asUInt64()) return;
    }
    if (expected.isObject() && actual.isObject()) {
        for (const auto& key : expected.getMemberNames()) {
            if (!actual.isMember(key)) {
                differences.push_back(path + "/" + Text(key) + ": missing field");
            }
            else {
                Diff(expected[key], actual[key], path + "/" + Text(key), differences);
            }
        }
        for (const auto& key : actual.getMemberNames()) {
            if (!expected.isMember(key)) {
                differences.push_back(path + "/" + Text(key) + ": unexpected field");
            }
        }
        return;
    }
    if (expected.isArray() && actual.isArray() && expected.size() == actual.size()) {
        for (Json::ArrayIndex i = 0; i < expected.size(); ++i) {
            Diff(expected[i], actual[i], path + "/" + std::to_string(i), differences);
        }
        return;
    }
    if (expected.type() != actual.type() || expected != actual) {
        differences.push_back(path + ": expected " + Encode(expected) + ", actual " + Encode(actual));
    }
}

inline std::vector<std::string> Compare(const Json::Value& fixture, const Json::Value& report) {
    ValidateFixture(fixture);
    Require(report.isObject() && report["schema"].isInt() && report["schema"].asInt() == 1,
        "unsupported report schema");
    const Results expected = Index(fixture["cases"], "expected");
    const Results actual = Index(report["results"], "output");
    std::vector<std::string> differences;
    for (const auto& item : expected) {
        const auto found = actual.find(item.first);
        if (found == actual.end()) {
            differences.push_back(item.first + ": missing case");
        }
        else {
            Diff(item.second, found->second, item.first, differences);
        }
    }
    for (const auto& item : actual) {
        if (!expected.count(item.first)) {
            differences.push_back(item.first + ": unexpected case");
        }
    }
    return differences;
}

using Evaluator = std::function<Json::Value(const std::string&, const Json::Value&)>;

inline Json::Value Run(const Json::Value& fixture, const Evaluator& evaluate) {
    ValidateFixture(fixture);
    Json::Value report(Json::objectValue);
    report["schema"] = 1;
    report["results"] = Json::Value(Json::arrayValue);
    for (const auto& row : fixture["cases"]) {
        Json::Value result(Json::objectValue);
        result["id"] = row["id"];
        try {
            result["output"] = evaluate(Text(row["kind"].asString()), row["input"]);
            Require(result["output"].isObject(), "evaluator must return an object");
        }
        catch (const std::exception& error) {
            throw std::runtime_error(Text(row["id"].asString()) + ": " + error.what());
        }
        report["results"].append(std::move(result));
    }
    return report;
}

} // namespace policy_baseline
