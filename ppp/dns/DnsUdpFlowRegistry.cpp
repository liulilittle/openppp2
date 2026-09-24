#include <ppp/dns/DnsUdpFlowRegistry.h>

namespace ppp {
    namespace dns {

        void DnsUdpFlowRegistry::PurgeExpired(
            std::chrono::steady_clock::time_point now) noexcept {

            entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                [now](const Entry& entry) noexcept {
                    return entry.expires_at <= now;
                }), entries_.end());
        }

        bool DnsUdpFlowRegistry::Register(
            uint16_t local_port,
            const boost::asio::ip::udp::endpoint& remote,
            std::chrono::milliseconds lifetime) noexcept {

            if (local_port == 0 || remote.address().is_unspecified() || remote.port() == 0 ||
                lifetime.count() <= 0) {
                return false;
            }

            const auto now = std::chrono::steady_clock::now();
            const auto expires_at = now + lifetime;
            std::lock_guard<std::mutex> lock(mutex_);
            PurgeExpired(now);
            for (Entry& entry : entries_) {
                if (entry.local_port == local_port && entry.remote == remote) {
                    entry.expires_at = expires_at;
                    return true;
                }
            }

            entries_.push_back(Entry{ local_port, remote, expires_at });
            return true;
        }

        bool DnsUdpFlowRegistry::Consume(
            uint16_t local_port,
            const boost::asio::ip::udp::endpoint& remote) noexcept {

            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(mutex_);
            PurgeExpired(now);
            const auto found = std::find_if(entries_.begin(), entries_.end(),
                [local_port, &remote](const Entry& entry) noexcept {
                    return entry.local_port == local_port && entry.remote == remote;
                });
            if (found == entries_.end()) {
                return false;
            }

            entries_.erase(found);
            return true;
        }

    }
}
