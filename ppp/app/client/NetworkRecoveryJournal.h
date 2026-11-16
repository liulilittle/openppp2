#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ppp::app::client {

// Durable write-ahead state for network resources modified by the VPN.
// Entries remain present until the caller has verified restoration.
class NetworkRecoveryJournal final {
public:
    enum class Stage {
        DirectoryCreate,
        Lock,
        Write,
        Flush,
        Rename,
        DirectoryFlush,
    };

    struct Options final {
        // Returning false injects an I/O failure before the named stage.
        std::function<bool(Stage)> allow_stage;
    };

    struct Entry final {
        std::string resource;
        std::string target;
        std::string before;
        std::string after;
        bool confirmed = false;
    };

    // Called for each persisted entry during startup or an explicit retry.
    // Returning true means the platform state was verified as restored.  The
    // journal entry is removed only after that callback succeeds and the
    // durable remove itself succeeds; all other entries remain retryable.
    using RecoveryHandler = std::function<bool(const Entry&)>;
    // Selects entries for a resource-specific recovery pass.  The filter is
    // evaluated while the journal lock is held and must not mutate the
    // journal.  Entries outside the selected resource remain untouched.
    using ResourceFilter = std::function<bool(const Entry&)>;

    NetworkRecoveryJournal() = default;
    ~NetworkRecoveryJournal();
    NetworkRecoveryJournal(const NetworkRecoveryJournal&) = delete;
    NetworkRecoveryJournal& operator=(const NetworkRecoveryJournal&) = delete;

    // Opens (and locks) directory/network-recovery.journal. Existing records
    // are validated before the journal is made available to the caller.
    bool Open(const std::string& directory, const std::string& owner,
              const Options& options = {}, std::string* error = nullptr);
    void Close() noexcept;

    // Record the state needed to undo an operation before changing the OS.
    // Re-recording the same resource/target replaces its previous intent.
    bool RecordIntent(const std::string& resource, const std::string& target,
                      const std::string& before, const std::string& after,
                      std::string* error = nullptr);
    // Marks an apply operation complete. The entry is still pending restore.
    bool Confirm(const std::string& resource, const std::string& target,
                std::string* error = nullptr);
    // Atomically upgrades an intent to a platform-specific identity after an
    // add call has returned the complete OS row. The old entry is retained on
    // any write failure.
    bool ReplaceTarget(const std::string& resource,
                       const std::string& old_target,
                       const std::string& new_target,
                       const std::string& after,
                       std::string* error = nullptr);
    // Removes an entry only after restoration has been verified.
    bool Remove(const std::string& resource, const std::string& target,
                std::string* error = nullptr);

    // Replays all pending entries. Returns true only when every entry was
    // restored and removed. A callback failure is not an I/O error: it leaves
    // the entry in the journal and permits a later retry.
    bool RecoverPending(const RecoveryHandler& handler, std::string* error = nullptr);
    // Replays only entries selected by filter. This is the context-safe form
    // for independent resource handlers such as DNS and routes: an unknown or
    // unrelated resource is not reported as a failed recovery by this pass.
    bool RecoverPending(const ResourceFilter& filter,
                        const RecoveryHandler& handler,
                        std::string* error = nullptr);
    bool RecoverPendingFor(const std::string& resource,
                           const RecoveryHandler& handler,
                           std::string* error = nullptr);
    std::vector<Entry> Pending() const;
    std::vector<Entry> PendingFor(const std::string& resource) const;
    bool HasPending() const;
    bool HasPendingFor(const std::string& resource) const;
    bool IsOpen() const noexcept { return open_; }

    // Runs the platform recovery handler without starting a VPN session.
    // The command is intentionally separate from normal configuration loading
    // so a desktop recovery worker can safely run after Core was terminated.
    static bool IsRecoveryCommand(int argc, const char* const* argv) noexcept;
    static int RunRecoveryCommand(int argc, const char* const* argv) noexcept;

private:
    bool StageAllowed(Stage stage) const;
    bool Rewrite(std::string* error);
    void CloseWithLock() noexcept;

    std::string directory_;
    std::string owner_;
    Options options_;
    std::vector<Entry> entries_;
    std::intptr_t lock_handle_ = -1;
    bool open_ = false;
};

} // namespace ppp::app::client
