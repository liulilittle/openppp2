#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ppp::app::client::policy {

struct DurablePolicySource final {
    std::string name;
    std::string format;
    std::string tag;
    std::string sha256;
    std::string url_redacted;
    std::string url_fingerprint;
    std::string etag;
    std::string last_modified;
    std::string bytes;
    std::int64_t validated_at_ms = 0;
};

struct DurablePolicyBundle final {
    std::uint32_t schema = 1;
    std::string identity_fingerprint;
    std::string rules;
    std::int64_t rules_validated_at_ms = 0;
    std::map<std::string, DurablePolicySource> rule_sets;
};

struct DurablePolicyLoad final {
    DurablePolicyBundle bundle;
    std::string error;
    bool found = false;
    bool Ok() const noexcept { return found && error.empty(); }
};

struct DurablePolicyPointerState final {
    bool current_present = false;
    std::string current_bytes;
    bool previous_present = false;
    std::string previous_bytes;
};

class DurablePolicyWriterLock {
public:
    virtual ~DurablePolicyWriterLock() = default;
};

class DurablePolicyBundleStore {
public:
    virtual ~DurablePolicyBundleStore() = default;
    virtual std::unique_ptr<DurablePolicyWriterLock> AcquireWriterLock(std::string& error) = 0;
    virtual DurablePolicyLoad LoadCurrent(const std::string& identity_fingerprint) = 0;
    virtual DurablePolicyLoad LoadPrevious(const std::string& identity_fingerprint) = 0;
    virtual bool Commit(const DurablePolicyBundle& bundle, std::string& error) = 0;
    virtual bool RefreshCurrent(const DurablePolicyBundle& bundle, std::string& error) = 0;
    virtual bool RestorePreviousAsCurrent(const std::string& identity_fingerprint, std::string& error) = 0;
    virtual bool ClearCurrent(const std::string& identity_fingerprint, std::string& error) = 0;
    virtual bool CapturePointerState(const std::string& identity_fingerprint,
        DurablePolicyPointerState& state, std::string& error) = 0;
    virtual bool RestorePointerState(const std::string& identity_fingerprint,
        const DurablePolicyPointerState& state, std::string& error) = 0;
};

class FileDurablePolicyBundleStore final : public DurablePolicyBundleStore {
public:
    enum class Stage { Write, Flush, Rename, DirectoryFlush };

    struct Options final {
        // Returning false injects an I/O failure immediately before the stage.
        std::function<bool(Stage)> allow_stage;
    };

    explicit FileDurablePolicyBundleStore(std::string root_directory, Options options = {});
    std::unique_ptr<DurablePolicyWriterLock> AcquireWriterLock(std::string& error) override;
    DurablePolicyLoad LoadCurrent(const std::string& identity_fingerprint) override;
    DurablePolicyLoad LoadPrevious(const std::string& identity_fingerprint) override;
    bool Commit(const DurablePolicyBundle& bundle, std::string& error) override;
    bool RefreshCurrent(const DurablePolicyBundle& bundle, std::string& error) override;
    bool RestorePreviousAsCurrent(const std::string& identity_fingerprint, std::string& error) override;
    bool ClearCurrent(const std::string& identity_fingerprint, std::string& error) override;
    bool CapturePointerState(const std::string& identity_fingerprint,
        DurablePolicyPointerState& state, std::string& error) override;
    bool RestorePointerState(const std::string& identity_fingerprint,
        const DurablePolicyPointerState& state, std::string& error) override;

private:
    bool StageAllowed(Stage stage) const;

    std::string root_directory_;
    Options options_;
};

std::string PolicySha256(const std::string& bytes);
std::string RedactPolicySourceUrl(const std::string& url);
std::string PolicyStoreRootForConfig(const std::string& config_path);

} // namespace ppp::app::client::policy
