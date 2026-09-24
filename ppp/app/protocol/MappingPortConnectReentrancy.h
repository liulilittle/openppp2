#pragma once

#include <utility>

namespace ppp::app::protocol {

/**
 * @brief Orders connection publication before a possibly reentrant connect start.
 */
class MappingPortConnectReentrancy final {
public:
    template <typename TPublish, typename TStart, typename TIsPublished, typename TCleanup>
    static bool PublishThenStart(
        TPublish&& publish,
        TStart&& start,
        TIsPublished&& is_published,
        TCleanup&& cleanup) noexcept {
        if (!std::forward<TPublish>(publish)()) {
            return false;
        }

        if (std::forward<TStart>(start)()) {
            return true;
        }

        // A synchronous completion may already have finalized and unpublished
        // the owner while start() was on the stack.
        if (std::forward<TIsPublished>(is_published)()) {
            std::forward<TCleanup>(cleanup)();
        }
        return false;
    }

    template <typename TMap, typename TKey, typename TOwner>
    static bool IsOwner(const TMap& entries, const TKey& key, const TOwner* owner) noexcept {
        auto iterator = entries.find(key);
        return iterator != entries.end() && iterator->second.get() == owner;
    }

    template <typename TMap, typename TKey, typename TOwner>
    static bool EraseIfOwner(TMap& entries, const TKey& key, const TOwner* owner) noexcept {
        auto iterator = entries.find(key);
        if (iterator == entries.end() || iterator->second.get() != owner) {
            return false;
        }

        entries.erase(iterator);
        return true;
    }
};

}
