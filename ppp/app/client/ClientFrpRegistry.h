#pragma once

#include <ppp/app/protocol/VirtualEthernetMappingPort.h>

#include <cstdint>
#include <memory>
#include <mutex>

namespace ppp::app::client {

class ClientFrpRegistry final {
public:
    using MappingPort = ppp::app::protocol::VirtualEthernetMappingPort;
    using MappingPortPtr = std::shared_ptr<MappingPort>;
    using MappingTable = ppp::unordered_map<std::uint32_t, MappingPortPtr>;

    ~ClientFrpRegistry() noexcept;

    bool Add(bool in, bool tcp, int remote_port, const MappingPortPtr& value) noexcept;
    MappingPortPtr Get(bool in, bool tcp, int remote_port) noexcept;
    MappingPortPtr Remove(bool in, bool tcp, int remote_port) noexcept;
    void Tick(std::uint64_t now) noexcept;
    void ReleaseAll() noexcept;

private:
    MappingTable mappings_;
    std::mutex mutex_;
};

} // namespace ppp::app::client
