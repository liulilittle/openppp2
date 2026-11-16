#pragma once

#include <boost/asio/io_context.hpp>

#include <functional>
#include <memory>

namespace ppp {
    namespace tap {
        /**
         * @brief Executor binding for one GSO output lane (opt-in XTCP queue mode).
         *
         * The context is the owning shard's io_context; holding the shared_ptr
         * keeps it alive for every asio object the lane constructs on it. An
         * empty binding means "use the TAP's own context" (default behaviour).
         */
        struct TapLaneBinding final {
            std::shared_ptr<boost::asio::io_context> context;
        };

        /** @brief Returns true and fills the binding when lane has a dedicated executor. */
        using TapLaneBindingProvider = std::function<bool(int lane, TapLaneBinding& binding)>;
    }
}
