#include <ppp/app/runtime/DatapathAcceptanceBoundary.h>

#include <json/json.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ppp::app::runtime {
namespace {

constexpr std::size_t kMaximumRequestBytes = 16 * 1024;
constexpr std::size_t kMaximumAcknowledgementBytes = 16 * 1024;

bool IsUsableValue(const std::string& value) noexcept {
    return !value.empty();
}

std::string EnvironmentValue(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

#if defined(__linux__)
bool SameFileMetadata(const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
        left.st_mode == right.st_mode && left.st_size == right.st_size &&
        left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
        left.st_mtim.tv_nsec == right.st_mtim.tv_nsec;
}

bool ReadRegularFileBounded(const std::string& path,
    std::string& contents,
    bool require_stable_size = true) noexcept {
    contents.clear();
    if (path.empty()) {
        return false;
    }

    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }

    struct stat before = {};
    struct stat after = {};
    bool valid = ::fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_size >= 0 &&
        (!require_stable_size || static_cast<std::uintmax_t>(before.st_size) <= kMaximumRequestBytes);
    if (valid && before.st_size > 0) {
        try {
            contents.reserve(static_cast<std::size_t>(before.st_size));
        }
        catch (...) {
            valid = false;
        }
    }

    char buffer[4096];
    while (valid) {
        const ssize_t read_size = ::read(fd, buffer, sizeof(buffer));
        if (read_size == 0) {
            break;
        }
        if (read_size < 0) {
            if (errno == EINTR) {
                continue;
            }
            valid = false;
            break;
        }
        if (contents.size() > kMaximumRequestBytes - static_cast<std::size_t>(read_size)) {
            valid = false;
            break;
        }
        try {
            contents.append(buffer, static_cast<std::size_t>(read_size));
        }
        catch (...) {
            valid = false;
            break;
        }
    }

    const bool after_read = ::fstat(fd, &after) == 0;
    const int close_result = ::close(fd);
    if (!after_read || !SameFileMetadata(before, after) ||
        (require_stable_size && contents.size() != static_cast<std::size_t>(before.st_size)) ||
        close_result != 0) {
        valid = false;
    }
    if (!valid) {
        contents.clear();
    }
    return valid;
}

bool ReadProcessStartTicks(std::uint64_t& ticks) noexcept {
    ticks = 0;
    std::string stat;
    if (!ReadRegularFileBounded("/proc/self/stat", stat, false)) {
        return false;
    }

    const std::size_t closing_parenthesis = stat.rfind(')');
    if (closing_parenthesis == std::string::npos || closing_parenthesis + 2 >= stat.size() ||
        stat[closing_parenthesis + 1] != ' ') {
        return false;
    }

    const char* current = stat.data() + closing_parenthesis + 2;
    const char* const end = stat.data() + stat.size();
    if (current == end || *current == ' ') {
        return false;
    }
    ++current; // Field 3: process state.
    for (unsigned int field = 4; field <= 22; ++field) {
        while (current < end && *current == ' ') {
            ++current;
        }
        if (current == end) {
            return false;
        }
        const char* token = current;
        while (current < end && *current != ' ') {
            ++current;
        }
        if (field != 22) {
            continue;
        }

        std::uint64_t parsed = 0;
        for (const char* digit = token; digit < current; ++digit) {
            const unsigned char character = static_cast<unsigned char>(*digit);
            if (character < '0' || character > '9' ||
                parsed > (std::numeric_limits<std::uint64_t>::max() - (character - '0')) / 10) {
                return false;
            }
            parsed = parsed * 10 + (character - '0');
        }
        if (token == current || parsed == 0) {
            return false;
        }
        ticks = parsed;
        return true;
    }
    return false;
}

bool WriteAll(int fd, const char* data, std::size_t size) noexcept {
    while (size != 0) {
        const ssize_t written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            return false;
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

bool IsSymlink(const std::string& path) noexcept {
    struct stat metadata = {};
    return ::lstat(path.c_str(), &metadata) == 0 && S_ISLNK(metadata.st_mode);
}

bool AtomicWriteAcknowledgement(const std::string& path,
    const std::string& directory,
    const std::string& contents) noexcept {
    if (path.empty() || directory.empty() || contents.empty() ||
        contents.size() > kMaximumAcknowledgementBytes || IsSymlink(path)) {
        return false;
    }

    struct stat directory_metadata = {};
    if (::stat(directory.c_str(), &directory_metadata) != 0 || !S_ISDIR(directory_metadata.st_mode)) {
        return false;
    }

    static std::atomic<std::uint64_t> counter{0};
    char suffix[96] = {};
    const int suffix_length = std::snprintf(suffix, sizeof(suffix),
        ".openppp2-acceptance-%llu-%llu.tmp",
        static_cast<unsigned long long>(::getpid()),
        static_cast<unsigned long long>(counter.fetch_add(1, std::memory_order_relaxed) + 1));
    if (suffix_length <= 0 || static_cast<std::size_t>(suffix_length) >= sizeof(suffix)) {
        return false;
    }

    std::string temporary_path;
    try {
        temporary_path = directory + "/" + suffix;
    }
    catch (...) {
        return false;
    }

    const int fd = ::open(temporary_path.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return false;
    }

    const bool written = WriteAll(fd, contents.data(), contents.size()) && ::fsync(fd) == 0;
    const int close_result = ::close(fd);
    if (!written || close_result != 0) {
        ::unlink(temporary_path.c_str());
        return false;
    }
    if (IsSymlink(path) || ::rename(temporary_path.c_str(), path.c_str()) != 0) {
        ::unlink(temporary_path.c_str());
        return false;
    }
    return true;
}
#endif

std::string FromJsonString(const Json::String& value) {
    return std::string(value.data(), value.size());
}

bool ExactRequest(const Json::Value& root) noexcept {
    if (!root.isObject() || root.size() != 5) {
        return false;
    }
    static const char* const fields[] = {
        "schema", "run_uuid", "cell_id", "sequence", "phase"
    };
    for (const char* field : fields) {
        if (!root.isMember(field)) {
            return false;
        }
    }
    return true;
}

bool ParsePositiveInteger(const Json::Value& value, std::uint64_t& result) noexcept {
    if (value.type() == Json::uintValue) {
        result = value.asUInt64();
        return result != 0;
    }
    if (value.type() == Json::intValue) {
        const Json::Int64 signed_value = value.asInt64();
        if (signed_value <= 0) {
            return false;
        }
        result = static_cast<std::uint64_t>(signed_value);
        return true;
    }
    return false;
}

bool ParseRequest(const std::string& json,
    const std::string& run_uuid,
    const std::string& cell_id,
    DatapathAcceptanceBoundaryRecord& record) noexcept {
    try {
        Json::CharReaderBuilder builder;
        Json::CharReaderBuilder::strictMode(&builder.settings_);
        builder["collectComments"] = false;
        builder["failIfExtra"] = true;
        builder["rejectDupKeys"] = true;
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        Json::Value root;
        Json::String errors;
        std::uint64_t schema = 0;
        std::uint64_t sequence = 0;
        if (!reader || !reader->parse(json.data(), json.data() + json.size(), &root, &errors) ||
            !ExactRequest(root) || !ParsePositiveInteger(root["schema"], schema) || schema != 1 ||
            !root["run_uuid"].isString() || !root["cell_id"].isString() ||
            !ParsePositiveInteger(root["sequence"], sequence) || !root["phase"].isString()) {
            return false;
        }

        const std::string parsed_run_uuid = FromJsonString(root["run_uuid"].asString());
        const std::string parsed_cell_id = FromJsonString(root["cell_id"].asString());
        const std::string phase = FromJsonString(root["phase"].asString());
        if (parsed_run_uuid != run_uuid || parsed_cell_id != cell_id ||
            (phase != "measurement_start" && phase != "measurement_end")) {
            return false;
        }

        record = DatapathAcceptanceBoundaryRecord();
        record.run_uuid = parsed_run_uuid;
        record.cell_id = parsed_cell_id;
        record.sequence = sequence;
        record.phase = phase;
        return true;
    }
    catch (...) {
        return false;
    }
}

std::string SerializeAcknowledgement(const DatapathAcceptanceBoundaryRecord& record) noexcept {
    try {
        Json::Value root(Json::objectValue);
        root["schema"] = DatapathAcceptanceBoundaryRecord::SchemaVersion;
        root["run_uuid"] = Json::String(record.run_uuid.data(), record.run_uuid.size());
        root["cell_id"] = Json::String(record.cell_id.data(), record.cell_id.size());
        root["sequence"] = Json::UInt64(record.sequence);
        root["phase"] = Json::String(record.phase.data(), record.phase.size());
        root["monotonic_ms"] = Json::UInt64(record.monotonic_ms);
        root["process_pid"] = Json::UInt64(record.process_pid);
        root["process_start_ticks"] = Json::UInt64(record.process_start_ticks);
        root["xtcp_runtime_instance_id"] = Json::UInt64(record.xtcp_runtime_instance_id);
        Json::FastWriter writer;
        const Json::String encoded = writer.write(root);
        std::string json(encoded.data(), encoded.size());
        while (!json.empty() && (json.back() == '\n' || json.back() == '\r')) {
            json.pop_back();
        }
        return json;
    }
    catch (...) {
        return std::string();
    }
}

std::string ParentDirectory(const std::string& path) {
    const std::size_t separator = path.rfind('/');
    if (separator == std::string::npos) {
        return ".";
    }
    if (separator == 0) {
        return "/";
    }
    return path.substr(0, separator);
}

} // namespace

void DatapathAcceptanceBoundary::Reset() noexcept {
    enabled_ = false;
    start_committed_ = false;
    end_committed_ = false;
    pending_stats_ = false;
    pending_acknowledgement_ = false;
    last_sequence_ = 0;
    run_uuid_.clear();
    cell_id_.clear();
    request_path_.clear();
    acknowledgement_path_.clear();
    acknowledgement_directory_.clear();
    process_pid_ = 0;
    process_start_ticks_ = 0;
    record_ = DatapathAcceptanceBoundaryRecord();
}

bool DatapathAcceptanceBoundary::Configure(
    const DatapathAcceptanceBoundaryConfiguration& configuration) noexcept {
    Reset();
#if defined(__linux__)
    if (!IsUsableValue(configuration.run_uuid) || !IsUsableValue(configuration.cell_id) ||
        !IsUsableValue(configuration.request_path) || !IsUsableValue(configuration.acknowledgement_path) ||
        configuration.request_path == configuration.acknowledgement_path || configuration.process_pid == 0 ||
        configuration.process_start_ticks == 0) {
        return false;
    }
    try {
        run_uuid_ = configuration.run_uuid;
        cell_id_ = configuration.cell_id;
        request_path_ = configuration.request_path;
        acknowledgement_path_ = configuration.acknowledgement_path;
        acknowledgement_directory_ = ParentDirectory(acknowledgement_path_);
    }
    catch (...) {
        Reset();
        return false;
    }
    process_pid_ = configuration.process_pid;
    process_start_ticks_ = configuration.process_start_ticks;
    enabled_ = !acknowledgement_directory_.empty();
    return enabled_;
#else
    (void)configuration;
    return false;
#endif
}

bool DatapathAcceptanceBoundary::ConfigureFromEnvironment() noexcept {
#if defined(__linux__)
    try {
        DatapathAcceptanceBoundaryConfiguration configuration;
        configuration.run_uuid = EnvironmentValue("OPENPPP2_DATAPATH_ACCEPTANCE_RUN_UUID");
        configuration.cell_id = EnvironmentValue("OPENPPP2_DATAPATH_ACCEPTANCE_CELL_ID");
        configuration.request_path = EnvironmentValue("OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_REQUEST");
        configuration.acknowledgement_path = EnvironmentValue("OPENPPP2_DATAPATH_ACCEPTANCE_BOUNDARY_ACK");
        configuration.process_pid = static_cast<std::uint64_t>(::getpid());
        if (!ReadProcessStartTicks(configuration.process_start_ticks)) {
            Reset();
            return false;
        }
        return Configure(configuration);
    }
    catch (...) {
        Reset();
        return false;
    }
#else
    Reset();
    return false;
#endif
}

bool DatapathAcceptanceBoundary::ConfigureForTesting(
    const DatapathAcceptanceBoundaryConfiguration& configuration) noexcept {
    return Configure(configuration);
}

bool DatapathAcceptanceBoundary::IsEnabled() const noexcept {
    return enabled_;
}

bool DatapathAcceptanceBoundary::Poll(DatapathAcceptanceBoundaryRecord& boundary) noexcept {
    try {
        if (!enabled_ || pending_acknowledgement_) {
            return false;
        }
        if (pending_stats_) {
            boundary = record_;
            return true;
        }

#if defined(__linux__)
        std::string json;
        DatapathAcceptanceBoundaryRecord candidate;
        if (!ReadRegularFileBounded(request_path_, json) ||
            !ParseRequest(json, run_uuid_, cell_id_, candidate) || candidate.sequence <= last_sequence_ ||
            (candidate.phase == "measurement_start" && start_committed_) ||
            (candidate.phase == "measurement_end" && (!start_committed_ || end_committed_))) {
            return false;
        }
        candidate.process_pid = process_pid_;
        candidate.process_start_ticks = process_start_ticks_;
        record_ = std::move(candidate);
        pending_stats_ = true;
        boundary = record_;
        return true;
#else
        (void)boundary;
        return false;
#endif
    }
    catch (...) {
        return false;
    }
}

bool DatapathAcceptanceBoundary::MarkStatsWritten(std::uint64_t monotonic_ms,
    std::uint64_t xtcp_runtime_instance_id) noexcept {
    if (!enabled_ || !pending_stats_ || pending_acknowledgement_) {
        return false;
    }

    record_.monotonic_ms = monotonic_ms;
    record_.xtcp_runtime_instance_id = xtcp_runtime_instance_id;
    last_sequence_ = record_.sequence;
    if (record_.phase == "measurement_start") {
        start_committed_ = true;
    }
    else {
        end_committed_ = true;
    }
    pending_stats_ = false;
    pending_acknowledgement_ = true;
    return true;
}

bool DatapathAcceptanceBoundary::RetryAcknowledgement() noexcept {
    if (!enabled_ || !pending_acknowledgement_) {
        return false;
    }
#if defined(__linux__)
    const std::string acknowledgement = SerializeAcknowledgement(record_);
    if (acknowledgement.empty() || !AtomicWriteAcknowledgement(
            acknowledgement_path_, acknowledgement_directory_, acknowledgement)) {
        return false;
    }
    pending_acknowledgement_ = false;
    return true;
#else
    return false;
#endif
}

bool DatapathAcceptanceBoundary::HasPendingAcknowledgement() const noexcept {
    return pending_acknowledgement_;
}

} // namespace ppp::app::runtime
