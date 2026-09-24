#define BOOST_TEST_MODULE datapath_acceptance_boundary_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/DatapathAcceptanceBoundary.h>

#include <json/json.h>

#if defined(__linux__)
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace runtime = ppp::app::runtime;

#if defined(__linux__)
namespace {

constexpr const char* kEnvironmentNames[] = {
    "OPENPPP2_DATAPATH_ACCEPTANCE_RUN_UUID",
    "OPENPPP2_DATAPATH_ACCEPTANCE_CELL_ID",
    "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_REQUEST",
    "OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_ACK",
};

enum EnvironmentIndex : std::size_t {
    RunUuid = 0,
    CellId = 1,
    RequestPath = 2,
    AcknowledgementPath = 3,
};

class EnvironmentGuard final {
public:
    EnvironmentGuard() {
        for (std::size_t i = 0; i < values_.size(); ++i) {
            const char* value = std::getenv(kEnvironmentNames[i]);
            present_[i] = value != nullptr;
            if (value != nullptr) {
                values_[i] = value;
            }
        }
    }

    ~EnvironmentGuard() noexcept {
        for (std::size_t i = 0; i < values_.size(); ++i) {
            if (present_[i]) {
                (void)::setenv(kEnvironmentNames[i], values_[i].c_str(), 1);
            }
            else {
                (void)::unsetenv(kEnvironmentNames[i]);
            }
        }
    }

    void Set(EnvironmentIndex index, const std::string& value) {
        BOOST_REQUIRE_EQUAL(::setenv(kEnvironmentNames[index], value.c_str(), 1), 0);
    }

    void Clear(EnvironmentIndex index) {
        BOOST_REQUIRE_EQUAL(::unsetenv(kEnvironmentNames[index]), 0);
    }

    void ClearAll() {
        for (std::size_t i = 0; i < values_.size(); ++i) {
            Clear(static_cast<EnvironmentIndex>(i));
        }
    }

private:
    std::array<bool, 4> present_ = {};
    std::array<std::string, 4> values_;
};

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        char pattern[] = "/tmp/openppp2-datapath-acceptance-XXXXXX";
        char* const created = ::mkdtemp(pattern);
        BOOST_REQUIRE(created != nullptr);
        path_ = created;
    }

    ~TemporaryDirectory() noexcept {
        try {
            DIR* const directory = ::opendir(path_.c_str());
            if (directory != nullptr) {
                for (;;) {
                    const dirent* const entry = ::readdir(directory);
                    if (entry == nullptr) {
                        break;
                    }
                    if (std::strcmp(entry->d_name, ".") == 0 ||
                        std::strcmp(entry->d_name, "..") == 0) {
                        continue;
                    }
                    const std::string child = path_ + "/" + entry->d_name;
                    (void)::unlink(child.c_str());
                }
                (void)::closedir(directory);
            }
            (void)::rmdir(path_.c_str());
        }
        catch (...) {
        }
    }

    std::string Path(const char* name) const {
        return path_ + "/" + name;
    }

private:
    std::string path_;
};

void WriteAll(int descriptor, const std::string& contents) {
    const char* current = contents.data();
    std::size_t remaining = contents.size();
    while (remaining != 0) {
        const ssize_t written = ::write(descriptor, current, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        BOOST_REQUIRE_GT(written, 0);
        current += written;
        remaining -= static_cast<std::size_t>(written);
    }
}

void WriteText(const std::string& path, const std::string& contents) {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    BOOST_REQUIRE_GE(descriptor, 0);
    WriteAll(descriptor, contents);
    BOOST_REQUIRE_EQUAL(::close(descriptor), 0);
}

std::string ReadText(const std::string& path) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    BOOST_REQUIRE_GE(descriptor, 0);

    std::string contents;
    char buffer[4096];
    for (;;) {
        const ssize_t read_size = ::read(descriptor, buffer, sizeof(buffer));
        if (read_size < 0 && errno == EINTR) {
            continue;
        }
        BOOST_REQUIRE_GE(read_size, 0);
        if (read_size == 0) {
            break;
        }
        contents.append(buffer, static_cast<std::size_t>(read_size));
    }
    BOOST_REQUIRE_EQUAL(::close(descriptor), 0);
    return contents;
}

bool PathExists(const std::string& path) {
    struct stat metadata = {};
    return ::lstat(path.c_str(), &metadata) == 0;
}

runtime::DatapathAcceptanceBoundaryConfiguration MakeConfiguration(
    const TemporaryDirectory& directory) {
    runtime::DatapathAcceptanceBoundaryConfiguration configuration;
    configuration.run_uuid = "run-uuid";
    configuration.cell_id = "cell-id";
    configuration.request_path = directory.Path("request.json");
    configuration.acknowledgement_path = directory.Path("ack.json");
    configuration.process_pid = 4242;
    configuration.process_start_ticks = 987654321;
    return configuration;
}

void SetEnvironment(EnvironmentGuard& environment,
    const runtime::DatapathAcceptanceBoundaryConfiguration& configuration) {
    environment.Set(RunUuid, configuration.run_uuid);
    environment.Set(CellId, configuration.cell_id);
    environment.Set(RequestPath, configuration.request_path);
    environment.Set(AcknowledgementPath, configuration.acknowledgement_path);
}

Json::String ToJsonString(const std::string& value) {
    return Json::String(value.data(), value.size());
}

std::string FromJsonString(const Json::String& value) {
    return std::string(value.data(), value.size());
}

std::string MakeRequest(const std::string& run_uuid,
    const std::string& cell_id,
    std::uint64_t sequence,
    const std::string& phase) {
    Json::Value request(Json::objectValue);
    request["schema"] = Json::UInt(1);
    request["run_uuid"] = ToJsonString(run_uuid);
    request["cell_id"] = ToJsonString(cell_id);
    request["sequence"] = Json::UInt64(sequence);
    request["phase"] = ToJsonString(phase);
    Json::FastWriter writer;
    const Json::String encoded = writer.write(request);
    return FromJsonString(encoded);
}

std::string MakeRequest(const runtime::DatapathAcceptanceBoundaryConfiguration& configuration,
    std::uint64_t sequence,
    const std::string& phase) {
    return MakeRequest(configuration.run_uuid, configuration.cell_id, sequence, phase);
}

Json::Value ParseStrictJson(const std::string& json) {
    Json::CharReaderBuilder builder;
    Json::CharReaderBuilder::strictMode(&builder.settings_);
    builder["collectComments"] = false;
    builder["failIfExtra"] = true;
    builder["rejectDupKeys"] = true;

    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    BOOST_REQUIRE(reader.get() != nullptr);
    Json::Value root;
    Json::String errors;
    BOOST_REQUIRE_MESSAGE(reader->parse(json.data(), json.data() + json.size(), &root, &errors), errors);
    return root;
}

void CheckRecord(const runtime::DatapathAcceptanceBoundaryRecord& record,
    const runtime::DatapathAcceptanceBoundaryConfiguration& configuration,
    std::uint64_t sequence,
    const std::string& phase) {
    BOOST_TEST(record.run_uuid == configuration.run_uuid);
    BOOST_TEST(record.cell_id == configuration.cell_id);
    BOOST_TEST(record.sequence == sequence);
    BOOST_TEST(record.phase == phase);
    BOOST_TEST(record.process_pid == configuration.process_pid);
    BOOST_TEST(record.process_start_ticks == configuration.process_start_ticks);
}

void CheckAcknowledgement(const std::string& text,
    const runtime::DatapathAcceptanceBoundaryConfiguration& configuration,
    std::uint64_t sequence,
    const std::string& phase,
    std::uint64_t monotonic_ms,
    std::uint64_t xtcp_runtime_instance_id) {
    const Json::Value root = ParseStrictJson(text);
    static const char* const fields[] = {
        "schema",
        "run_uuid",
        "cell_id",
        "sequence",
        "phase",
        "monotonic_ms",
        "process_pid",
        "process_start_ticks",
        "xtcp_runtime_instance_id",
    };
    BOOST_REQUIRE(root.isObject());
    BOOST_REQUIRE_EQUAL(root.size(), static_cast<Json::ArrayIndex>(sizeof(fields) / sizeof(fields[0])));
    for (const char* field : fields) {
        BOOST_REQUIRE(root.isMember(field));
    }
    BOOST_TEST(root["schema"].asUInt() == 1u);
    BOOST_TEST(FromJsonString(root["run_uuid"].asString()) == configuration.run_uuid);
    BOOST_TEST(FromJsonString(root["cell_id"].asString()) == configuration.cell_id);
    BOOST_TEST(root["sequence"].asUInt64() == sequence);
    BOOST_TEST(FromJsonString(root["phase"].asString()) == phase);
    BOOST_TEST(root["monotonic_ms"].asUInt64() == monotonic_ms);
    BOOST_TEST(root["process_pid"].asUInt64() == configuration.process_pid);
    BOOST_TEST(root["process_start_ticks"].asUInt64() == configuration.process_start_ticks);
    BOOST_TEST(root["xtcp_runtime_instance_id"].asUInt64() == xtcp_runtime_instance_id);
}

void CommitAndAcknowledge(runtime::DatapathAcceptanceBoundary& boundary,
    std::uint64_t monotonic_ms,
    std::uint64_t xtcp_runtime_instance_id) {
    BOOST_REQUIRE(boundary.MarkStatsWritten(monotonic_ms, xtcp_runtime_instance_id));
    BOOST_REQUIRE(boundary.HasPendingAcknowledgement());
    BOOST_REQUIRE(boundary.RetryAcknowledgement());
    BOOST_TEST(!boundary.HasPendingAcknowledgement());
}

} // namespace

BOOST_AUTO_TEST_CASE(boundary_is_disabled_when_startup_environment_is_incomplete) {
    EnvironmentGuard environment;
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);

    environment.ClearAll();
    runtime::DatapathAcceptanceBoundary disabled;
    BOOST_TEST(!disabled.ConfigureFromEnvironment());
    BOOST_TEST(!disabled.IsEnabled());

    for (std::size_t missing = 0; missing < 4; ++missing) {
        environment.ClearAll();
        for (std::size_t index = 0; index < 4; ++index) {
            if (index != missing) {
                switch (index) {
                case RunUuid: environment.Set(RunUuid, configuration.run_uuid); break;
                case CellId: environment.Set(CellId, configuration.cell_id); break;
                case RequestPath: environment.Set(RequestPath, configuration.request_path); break;
                case AcknowledgementPath:
                    environment.Set(AcknowledgementPath, configuration.acknowledgement_path);
                    break;
                }
            }
        }
        runtime::DatapathAcceptanceBoundary incomplete;
        BOOST_TEST(!incomplete.ConfigureFromEnvironment());
        BOOST_TEST(!incomplete.IsEnabled());
    }

    SetEnvironment(environment, configuration);
    runtime::DatapathAcceptanceBoundary enabled;
    BOOST_REQUIRE(enabled.ConfigureFromEnvironment());
    BOOST_TEST(enabled.IsEnabled());
}

BOOST_AUTO_TEST_CASE(boundary_snapshots_startup_environment_once) {
    EnvironmentGuard environment;
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    SetEnvironment(environment, configuration);

    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_REQUIRE(boundary.ConfigureFromEnvironment());

    runtime::DatapathAcceptanceBoundaryConfiguration mutated = configuration;
    mutated.run_uuid = "other-run";
    mutated.cell_id = "other-cell";
    mutated.request_path = directory.Path("other-request.json");
    mutated.acknowledgement_path = directory.Path("other-ack.json");
    SetEnvironment(environment, mutated);

    WriteText(configuration.request_path, MakeRequest(configuration, 1, "measurement_start"));
    runtime::DatapathAcceptanceBoundaryRecord record;
    BOOST_REQUIRE(boundary.Poll(record));
    BOOST_TEST(record.process_pid == static_cast<std::uint64_t>(::getpid()));
    BOOST_TEST(record.process_start_ticks != 0u);
    runtime::DatapathAcceptanceBoundaryConfiguration expected = configuration;
    expected.process_pid = record.process_pid;
    expected.process_start_ticks = record.process_start_ticks;
    CheckRecord(record, expected, 1, "measurement_start");

    CommitAndAcknowledge(boundary, 111, 222);
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), expected,
        1, "measurement_start", 111, 222);
    BOOST_TEST(!PathExists(mutated.acknowledgement_path));
}

BOOST_AUTO_TEST_CASE(boundary_validates_explicit_configuration_without_identity_length_limits) {
    TemporaryDirectory directory;
    runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    configuration.run_uuid.assign(2048, 'r');
    configuration.cell_id.assign(2048, 'c');

    runtime::DatapathAcceptanceBoundary valid;
    BOOST_REQUIRE(valid.ConfigureForTesting(configuration));
    BOOST_TEST(valid.IsEnabled());

    runtime::DatapathAcceptanceBoundaryConfiguration invalid = configuration;
    invalid.run_uuid.clear();
    runtime::DatapathAcceptanceBoundary empty_run_uuid;
    BOOST_TEST(!empty_run_uuid.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.cell_id.clear();
    runtime::DatapathAcceptanceBoundary empty_cell_id;
    BOOST_TEST(!empty_cell_id.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.request_path.clear();
    runtime::DatapathAcceptanceBoundary empty_request_path;
    BOOST_TEST(!empty_request_path.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.acknowledgement_path.clear();
    runtime::DatapathAcceptanceBoundary empty_acknowledgement_path;
    BOOST_TEST(!empty_acknowledgement_path.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.acknowledgement_path = invalid.request_path;
    runtime::DatapathAcceptanceBoundary equal_paths;
    BOOST_TEST(!equal_paths.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.process_pid = 0;
    runtime::DatapathAcceptanceBoundary zero_pid;
    BOOST_TEST(!zero_pid.ConfigureForTesting(invalid));

    invalid = configuration;
    invalid.process_start_ticks = 0;
    runtime::DatapathAcceptanceBoundary zero_start_ticks;
    BOOST_TEST(!zero_start_ticks.ConfigureForTesting(invalid));
}

BOOST_AUTO_TEST_CASE(boundary_commits_valid_start_and_end_only_after_stats_write) {
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_REQUIRE(boundary.ConfigureForTesting(configuration));

    WriteText(configuration.request_path, MakeRequest(configuration, 1, "measurement_start"));
    runtime::DatapathAcceptanceBoundaryRecord start;
    BOOST_REQUIRE(boundary.Poll(start));
    CheckRecord(start, configuration, 1, "measurement_start");

    runtime::DatapathAcceptanceBoundaryRecord pending_start;
    BOOST_REQUIRE(boundary.Poll(pending_start));
    CheckRecord(pending_start, configuration, 1, "measurement_start");
    BOOST_TEST(!boundary.HasPendingAcknowledgement());
    BOOST_TEST(!boundary.RetryAcknowledgement());
    BOOST_TEST(!PathExists(configuration.acknowledgement_path));

    BOOST_REQUIRE(boundary.MarkStatsWritten(123456, 9001));
    BOOST_REQUIRE(boundary.HasPendingAcknowledgement());
    runtime::DatapathAcceptanceBoundaryRecord blocked_while_ack_pending;
    BOOST_TEST(!boundary.Poll(blocked_while_ack_pending));
    BOOST_REQUIRE(boundary.RetryAcknowledgement());
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        1, "measurement_start", 123456, 9001);

    WriteText(configuration.request_path, MakeRequest(configuration, 2, "measurement_end"));
    runtime::DatapathAcceptanceBoundaryRecord end;
    BOOST_REQUIRE(boundary.Poll(end));
    CheckRecord(end, configuration, 2, "measurement_end");
    CommitAndAcknowledge(boundary, 123499, 9002);
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        2, "measurement_end", 123499, 9002);
}

BOOST_AUTO_TEST_CASE(boundary_leaves_a_stale_acknowledgement_until_stats_are_committed) {
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_REQUIRE(boundary.ConfigureForTesting(configuration));

    const std::string stale = "stale acknowledgement\n";
    WriteText(configuration.acknowledgement_path, stale);
    WriteText(configuration.request_path, MakeRequest(configuration, 1, "measurement_start"));

    runtime::DatapathAcceptanceBoundaryRecord record;
    BOOST_REQUIRE(boundary.Poll(record));
    BOOST_TEST(ReadText(configuration.acknowledgement_path) == stale);
    BOOST_TEST(!boundary.RetryAcknowledgement());
    BOOST_TEST(ReadText(configuration.acknowledgement_path) == stale);

    BOOST_REQUIRE(boundary.MarkStatsWritten(456, 789));
    BOOST_TEST(ReadText(configuration.acknowledgement_path) == stale);
    BOOST_REQUIRE(boundary.RetryAcknowledgement());
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        1, "measurement_start", 456, 789);
}

BOOST_AUTO_TEST_CASE(boundary_retries_a_failed_symlink_acknowledgement_without_repolling) {
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_REQUIRE(boundary.ConfigureForTesting(configuration));

    const std::string target = directory.Path("ack-target.json");
    WriteText(target, "unchanged target\n");
    BOOST_REQUIRE_EQUAL(::symlink(target.c_str(), configuration.acknowledgement_path.c_str()), 0);

    WriteText(configuration.request_path, MakeRequest(configuration, 1, "measurement_start"));
    runtime::DatapathAcceptanceBoundaryRecord record;
    BOOST_REQUIRE(boundary.Poll(record));
    BOOST_REQUIRE(boundary.MarkStatsWritten(654, 321));
    BOOST_TEST(!boundary.RetryAcknowledgement());
    BOOST_TEST(boundary.HasPendingAcknowledgement());
    BOOST_TEST(ReadText(target) == "unchanged target\n");

    BOOST_REQUIRE_EQUAL(::unlink(configuration.acknowledgement_path.c_str()), 0);
    BOOST_REQUIRE(boundary.RetryAcknowledgement());
    BOOST_TEST(!boundary.HasPendingAcknowledgement());
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        1, "measurement_start", 654, 321);
}

BOOST_AUTO_TEST_CASE(boundary_rejects_non_exact_or_non_matching_requests) {
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    const std::vector<std::string> invalid_requests = {
        MakeRequest("wrong-run", configuration.cell_id, 1, "measurement_start"),
        MakeRequest(configuration.run_uuid, "wrong-cell", 1, "measurement_start"),
        R"({"schema":2,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"unexpected"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start","extra":true})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1})",
        R"({"schema":"1","run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start"})",
        R"({"schema":true,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":17,"cell_id":"cell-id","sequence":1,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":false,"sequence":1,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":"1","phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1.5,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":0,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":-1,"phase":"measurement_start"})",
        R"({"schema":1,"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start"})",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start")",
        R"({"schema":1,"run_uuid":"run-uuid","cell_id":"cell-id","sequence":1,"phase":"measurement_start"} trailing)",
    };

    for (const std::string& request : invalid_requests) {
        runtime::DatapathAcceptanceBoundary boundary;
        BOOST_REQUIRE(boundary.ConfigureForTesting(configuration));
        WriteText(configuration.request_path, request);
        runtime::DatapathAcceptanceBoundaryRecord record;
        BOOST_TEST(!boundary.Poll(record));
        BOOST_TEST(!boundary.MarkStatsWritten(1, 1));
        BOOST_TEST(!boundary.RetryAcknowledgement());
        BOOST_TEST(!boundary.HasPendingAcknowledgement());
        BOOST_TEST(!PathExists(configuration.acknowledgement_path));
    }
}

BOOST_AUTO_TEST_CASE(boundary_enforces_start_end_transitions_and_sequence_monotonicity) {
    TemporaryDirectory directory;
    const runtime::DatapathAcceptanceBoundaryConfiguration configuration = MakeConfiguration(directory);
    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_REQUIRE(boundary.ConfigureForTesting(configuration));

    WriteText(configuration.request_path, MakeRequest(configuration, 1, "measurement_end"));
    runtime::DatapathAcceptanceBoundaryRecord record;
    BOOST_TEST(!boundary.Poll(record));
    BOOST_TEST(!PathExists(configuration.acknowledgement_path));

    WriteText(configuration.request_path, MakeRequest(configuration, 2, "measurement_start"));
    BOOST_REQUIRE(boundary.Poll(record));
    CommitAndAcknowledge(boundary, 200, 20);
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        2, "measurement_start", 200, 20);
    const std::string start_acknowledgement = ReadText(configuration.acknowledgement_path);

    const auto reject_without_new_acknowledgement = [&](std::uint64_t sequence, const char* phase) {
        WriteText(configuration.request_path, MakeRequest(configuration, sequence, phase));
        runtime::DatapathAcceptanceBoundaryRecord rejected;
        BOOST_TEST(!boundary.Poll(rejected));
        BOOST_TEST(!boundary.RetryAcknowledgement());
        BOOST_TEST(ReadText(configuration.acknowledgement_path) == start_acknowledgement);
    };
    reject_without_new_acknowledgement(3, "measurement_start");
    reject_without_new_acknowledgement(2, "measurement_end");
    reject_without_new_acknowledgement(1, "measurement_end");

    WriteText(configuration.request_path, MakeRequest(configuration, 4, "measurement_end"));
    BOOST_REQUIRE(boundary.Poll(record));
    CommitAndAcknowledge(boundary, 400, 40);
    CheckAcknowledgement(ReadText(configuration.acknowledgement_path), configuration,
        4, "measurement_end", 400, 40);
    const std::string end_acknowledgement = ReadText(configuration.acknowledgement_path);

    const auto reject_after_end = [&](std::uint64_t sequence, const char* phase) {
        WriteText(configuration.request_path, MakeRequest(configuration, sequence, phase));
        runtime::DatapathAcceptanceBoundaryRecord rejected;
        BOOST_TEST(!boundary.Poll(rejected));
        BOOST_TEST(!boundary.RetryAcknowledgement());
        BOOST_TEST(ReadText(configuration.acknowledgement_path) == end_acknowledgement);
    };
    reject_after_end(5, "measurement_end");
    reject_after_end(6, "measurement_start");
}

#else

BOOST_AUTO_TEST_CASE(boundary_is_disabled_off_linux) {
    runtime::DatapathAcceptanceBoundary boundary;
    BOOST_TEST(!boundary.ConfigureFromEnvironment());
    BOOST_TEST(!boundary.IsEnabled());
}

#endif
