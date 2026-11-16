#pragma once

#include <ppp/app/client/dns/DurableFakeIpStore.h>
#include <boost/asio/io_context.hpp>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

namespace ppp::app::client::dns {

class PolicyFakeIpAsync final {
public:
    using ActiveCheck = std::function<bool()>;
    using Completion = std::function<void(bool, uint32_t)>;
    using PendingObserver = std::function<void(std::ptrdiff_t)>;

    // The callback runs on return_context only after the allocation is durable.
    static bool Allocate(const std::shared_ptr<DurableFakeIpStore>& store,
        const std::shared_ptr<boost::asio::io_context>& return_context,
        const std::string& hostname, ActiveCheck active, Completion completion,
        PendingObserver pending_observer = {}) noexcept;
};

}
