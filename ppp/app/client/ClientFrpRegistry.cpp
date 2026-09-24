#include <ppp/stdafx.h>
#include <ppp/app/client/ClientFrpRegistry.h>

namespace ppp::app::client {

ClientFrpRegistry::~ClientFrpRegistry() noexcept {
    ReleaseAll();
}

bool ClientFrpRegistry::Add(
    bool in,
    bool tcp,
    int remote_port,
    const MappingPortPtr& value) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return MappingPort::AddMappingPort(mappings_, in, tcp, remote_port, value);
}

ClientFrpRegistry::MappingPortPtr ClientFrpRegistry::Get(
    bool in,
    bool tcp,
    int remote_port) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return MappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
}

ClientFrpRegistry::MappingPortPtr ClientFrpRegistry::Remove(
    bool in,
    bool tcp,
    int remote_port) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return MappingPort::DeleteMappingPort(mappings_, in, tcp, remote_port);
}

void ClientFrpRegistry::Tick(std::uint64_t now) noexcept {
    ppp::vector<std::pair<std::uint32_t, MappingPortPtr>> candidates;
    ppp::vector<std::pair<std::uint32_t, MappingPortPtr>> stale;
    ppp::vector<MappingPortPtr> release;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        candidates.reserve(mappings_.size());
        for (const auto& item : mappings_) {
            candidates.emplace_back(item.first, item.second);
        }
    }
    for (const auto& item : candidates) {
        if (!item.second || !item.second->Update(now)) {
            stale.emplace_back(item);
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& item : stale) {
            const auto found = mappings_.find(item.first);
            if (found == mappings_.end() || found->second != item.second) {
                continue;
            }
            if (found->second) {
                release.emplace_back(std::move(found->second));
            }
            mappings_.erase(found);
        }
    }
    for (const MappingPortPtr& mapping : release) {
        mapping->Dispose();
    }
}

void ClientFrpRegistry::ReleaseAll() noexcept {
    MappingTable mappings;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mappings.swap(mappings_);
    }
    for (const auto& item : mappings) {
        if (item.second) {
            item.second->Dispose();
        }
    }
}

} // namespace ppp::app::client
