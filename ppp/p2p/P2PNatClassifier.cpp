/**
 * @file P2PNatClassifier.cpp
 * @brief Server-side NAT type classification implementation.
 *
 * All public methods acquire the internal mutex for thread safety.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PNatClassifier.h>

namespace ppp {
    namespace p2p {

        void P2PNatClassifier::Observe(uint32_t peer_virtual_ip,
                                        const boost::asio::ip::udp::endpoint& source,
                                        const boost::asio::ip::udp::endpoint& destination,
                                        uint64_t now_ms) noexcept {
            if (peer_virtual_ip == 0 || source.port() == 0) {
                return;
            }

            std::lock_guard<std::mutex> lock(mutex_);

            auto& data = peer_data_[peer_virtual_ip];
            data.last_update_ms = now_ms;

            if (static_cast<int>(data.observations.size()) >= MAX_OBSERVATIONS_PER_PEER) {
                data.observations.erase(data.observations.begin());
            }

            P2PNatObservation obs;
            obs.source = source;
            obs.destination = destination;
            obs.timestamp_ms = now_ms;
            data.observations.emplace_back(std::move(obs));
        }

        P2PNatClassification P2PNatClassifier::Classify(uint32_t peer_virtual_ip,
                                                          uint64_t now_ms) noexcept {
            std::lock_guard<std::mutex> lock(mutex_);

            P2PNatClassification result;
            auto it = peer_data_.find(peer_virtual_ip);
            if (it == peer_data_.end() || it->second.observations.empty()) {
                result.type = P2PNatType::Unknown;
                result.confidence = 0;
                result.stale = true;
                return result;
            }

            const auto& data = it->second;
            const auto& observations = data.observations;

            result.stale = (now_ms - data.last_update_ms > 5000);

            ppp::unordered_set<uint32_t> dest_ips;
            ppp::unordered_set<uint64_t> source_endpoints;

            for (const auto& obs : observations) {
                if (obs.destination.address().is_v4()) {
                    uint32_t ip = obs.destination.address().to_v4().to_uint();
                    dest_ips.insert(ip);
                }
                if (obs.source.address().is_v4()) {
                    uint32_t src_ip = obs.source.address().to_v4().to_uint();
                    uint64_t src_key = (static_cast<uint64_t>(src_ip) << 16) | obs.source.port();
                    source_endpoints.insert(src_key);
                }
            }

            result.confidence = static_cast<int>(dest_ips.size());

            // A single UDP destination cannot reveal endpoint-dependent mapping.
            if (dest_ips.size() < 2) {
                result.type = P2PNatType::Unknown;
                return result;
            }

            if (observations.empty()) {
                result.type = P2PNatType::Unknown;
                return result;
            }

            if (source_endpoints.size() == 1) {
                result.type = P2PNatType::FullCone;
                return result;
            }

            ppp::unordered_map<uint32_t, uint16_t> dest_ip_to_src_port;
            bool port_varies_by_endpoint = false;
            for (const auto& obs : observations) {
                if (!obs.destination.address().is_v4() || !obs.source.address().is_v4()) {
                    continue;
                }
                uint32_t dest_ip = obs.destination.address().to_v4().to_uint();
                uint16_t src_port = obs.source.port();
                auto pit = dest_ip_to_src_port.find(dest_ip);
                if (pit == dest_ip_to_src_port.end()) {
                    dest_ip_to_src_port[dest_ip] = src_port;
                } else if (pit->second != src_port) {
                    port_varies_by_endpoint = true;
                }
            }

            if (port_varies_by_endpoint) {
                result.type = P2PNatType::PortRestricted;
            } else if (source_endpoints.size() > dest_ips.size()) {
                result.type = P2PNatType::RestrictedCone;
            } else {
                result.type = P2PNatType::Symmetric;
            }

            return result;
        }

        bool P2PNatClassifier::ShouldAttemptPunch(const P2PNatClassification& source_nat,
                                                   const P2PNatClassification& dest_nat) noexcept {
            // Skip for symmetric-symmetric.
            if (source_nat.type == P2PNatType::Symmetric &&
                dest_nat.type == P2PNatType::Symmetric) {
                return false;
            }

            // Skip if either side is UDP-blocked.
            if (source_nat.type == P2PNatType::UdpBlocked ||
                dest_nat.type == P2PNatType::UdpBlocked) {
                return false;
            }

            // Unknown is allowed — the server can still send offers for probing.
            return true;
        }

        void P2PNatClassifier::Remove(uint32_t peer_virtual_ip) noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            peer_data_.erase(peer_virtual_ip);
        }

        void P2PNatClassifier::PurgeStale(uint64_t now_ms) noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = peer_data_.begin(); it != peer_data_.end(); ) {
                if (now_ms - it->second.last_update_ms > STALE_THRESHOLD_MS) {
                    it = peer_data_.erase(it);
                } else {
                    ++it;
                }
            }
        }

    }
}
