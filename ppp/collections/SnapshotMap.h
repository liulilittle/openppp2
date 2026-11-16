#pragma once

/**
 * @file SnapshotMap.h
 * @brief Map with locked writers and lock-free readers through published snapshots.
 */

#include <memory>
#include <utility>

namespace ppp {
    namespace collections {
        /** @brief Default snapshot projection: an exact copy of the authoritative map. */
        struct SnapshotMapCopy final {
            template <typename TMap>
            TMap operator()(const TMap& map) const {
                return map;
            }
        };

        /**
         * @brief Read-mostly map whose hot-path lookups do not take the owner's lock.
         *
         * The authoritative map is read and written only while the owner holds its own
         * lock, exactly like a plain member map. Every mutation also publishes an
         * immutable snapshot (optionally re-keyed by @p TProject), which readers load
         * atomically without any lock. Writes copy the map, so this suits tables that
         * change per session but are read per packet.
         *
         * @tparam TMap Authoritative map type.
         * @tparam TSnapshot Snapshot type produced from the map.
         * @tparam TProject Callable converting TMap to TSnapshot.
         */
        template <typename TMap, typename TSnapshot = TMap, typename TProject = SnapshotMapCopy>
        class SnapshotMap final {
        public:
            typedef typename TMap::key_type                             key_type;
            typedef typename TMap::mapped_type                          mapped_type;
            typedef typename TMap::const_iterator                       const_iterator;
            typedef std::shared_ptr<const TSnapshot>                    SnapshotPtr;

        public:
            SnapshotMap() : snapshot_(std::make_shared<TSnapshot>(TProject()(map_))) {}
            SnapshotMap(const SnapshotMap&) = delete;
            SnapshotMap& operator=(const SnapshotMap&) = delete;

        public:
            // Authoritative view; the owner's lock must be held.
            const_iterator                                              find(const key_type& key) const { return map_.find(key); }
            const_iterator                                              begin() const noexcept { return map_.begin(); }
            const_iterator                                              end() const noexcept { return map_.end(); }
            std::size_t                                                 size() const noexcept { return map_.size(); }
            bool                                                        empty() const noexcept { return map_.empty(); }

            std::pair<const_iterator, bool>                             emplace(const key_type& key, const mapped_type& value) {
                auto result = map_.emplace(key, value);
                if (result.second) {
                    Publish();
                }
                return std::pair<const_iterator, bool>(result.first, result.second);
            }

            /** @brief Inserts or replaces the value for @p key. */
            void                                                        assign(const key_type& key, const mapped_type& value) {
                map_[key] = value;
                Publish();
            }

            const_iterator                                              erase(const_iterator position) {
                const_iterator next = map_.erase(position);
                Publish();
                return next;
            }

            std::size_t                                                 erase(const key_type& key) {
                std::size_t erased = map_.erase(key);
                if (erased != 0) {
                    Publish();
                }
                return erased;
            }

            void                                                        clear() {
                if (!map_.empty()) {
                    map_.clear();
                    Publish();
                }
            }

            /** @brief Moves the authoritative map out and leaves this table empty. */
            TMap                                                        take() {
                TMap result = std::move(map_);
                map_.clear();
                Publish();
                return result;
            }

            // Lock-free view for readers that do not hold the owner's lock.
            SnapshotPtr                                                 Snapshot() const noexcept { return std::atomic_load(&snapshot_); }

        private:
            void                                                        Publish() {
                std::atomic_store(&snapshot_, SnapshotPtr(std::make_shared<TSnapshot>(TProject()(map_))));
            }

        private:
            TMap                                                        map_;
            SnapshotPtr                                                 snapshot_;
        };
    }
}
