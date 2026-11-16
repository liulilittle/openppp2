#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace ppp::app::client::dns {

class DurableFakeIpStore final {
public:
    struct Stats final {
        uint64_t fake_ip_mappings = 0;
        uint64_t fake_ip_exhaustions = 0;
        uint64_t fake_ip_persistence_errors = 0;
    };

    enum class Stage {
        Lock,
        DirectoryCreate,
        ParentFlush,
        SnapshotWrite,
        SnapshotFlush,
        SnapshotRename,
        DirectoryFlush,
        JournalAppend,
        JournalFlush,
        JournalRepair,
        JournalRepairFlush,
        JournalTruncate,
        JournalTruncateFlush
    };

    struct Options final {
        // Returning false injects an I/O failure immediately before this stage.
        std::function<bool(Stage)> allow_stage;
    };

    DurableFakeIpStore() = default;
    ~DurableFakeIpStore();
    DurableFakeIpStore(const DurableFakeIpStore&) = delete;
    DurableFakeIpStore& operator=(const DurableFakeIpStore&) = delete;

    bool Open(const std::string& directory, const std::string& identity,
              const std::string& cidr, const Options& options = {},
              std::string* error = nullptr);
    void Close() noexcept;

    // A new mapping is returned only after its journal record is durable.
    bool Allocate(const std::string& hostname, uint32_t& fake_ip_host,
                  std::string* error = nullptr);
    bool LookupHostname(uint32_t fake_ip_host, std::string& hostname) const;
    bool LookupAddress(const std::string& hostname, uint32_t& fake_ip_host) const;
    bool Contains(uint32_t fake_ip_host) const noexcept;
    bool IsOpen() const noexcept;
    bool IsEnabled() const noexcept { return IsOpen(); }
    bool GetRoute(uint32_t& route_network, int& route_prefix) const noexcept;
    Stats SnapshotStats() const noexcept;

    // Writes a compact snapshot atomically, then truncates the journal durably.
    bool Compact(std::string* error = nullptr);

private:
    bool StageAllowed(Stage stage) const;
    void CloseWithIoLock() noexcept;
    bool AppendRecord(uint64_t sequence, uint32_t address, const std::string& hostname,
                     std::string* error);

    mutable std::mutex mutex_;
    mutable std::mutex io_mutex_;
    std::string directory_;
    std::string identity_;
    std::string cidr_;
    uint32_t network_ = 0;
    uint32_t mask_ = 0;
    uint32_t first_ = 0;
    uint32_t last_ = 0;
    uint64_t sequence_ = 0;
    uint64_t mapping_count_ = 0;
    uint64_t pool_exhaustions_ = 0;
    uint64_t persistence_errors_ = 0;
    std::map<std::string, uint32_t> by_hostname_;
    std::map<uint32_t, std::string> by_address_;
    Options options_;
    intptr_t lock_handle_ = -1;
    bool open_ = false;
    bool healthy_ = false;
};

} // namespace ppp::app::client::dns
