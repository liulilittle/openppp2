#include <ppp/app/P2PCandidateAdapter.h>
#include <ppp/net/IPEndPoint.h>

#include <algorithm>

namespace ppp::app {

bool P2PCandidateFromEndpoint(
    const boost::asio::ip::udp::endpoint& endpoint,
    ppp::p2p::P2PCandidateV1& output) noexcept {
    if (endpoint.address().is_unspecified() || endpoint.port() == 0) {
        return false;
    }

    ppp::p2p::P2PCandidateV1 candidate;
    candidate.port = endpoint.port();
    if (endpoint.address().is_v4()) {
        candidate.address_family = 4;
        candidate.address[10] = 0xff;
        candidate.address[11] = 0xff;
        const auto bytes = endpoint.address().to_v4().to_bytes();
        std::copy(bytes.begin(), bytes.end(), candidate.address.begin() + 12);
    }
    else if (endpoint.address().is_v6()) {
        candidate.address_family = 6;
        const auto bytes = endpoint.address().to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), candidate.address.begin());
    }
    else {
        return false;
    }
    output = candidate;
    return true;
}

std::string P2PEndpointToString(
    const boost::asio::ip::udp::endpoint& endpoint) noexcept {
    if (endpoint.address().is_unspecified() ||
        endpoint.port() <= ppp::net::IPEndPoint::MinPort) {
        return {};
    }

    try {
        const std::string address = endpoint.address().to_string();
        std::string value;
        if (endpoint.address().is_v6()) {
            value.append("[");
            value.append(address.data(), address.size());
            value.append("]");
        }
        else {
            value.append(address.data(), address.size());
        }
        value.append(":");
        value.append(std::to_string(endpoint.port()));
        return value;
    }
    catch (...) {
        return {};
    }
}

bool P2PAppendObservedEndpointCandidate(
    const boost::asio::ip::udp::endpoint& endpoint,
    ppp::vector<ppp::app::protocol::P2PEndpointCandidate>& candidates) noexcept {
    const std::string value = P2PEndpointToString(endpoint);
    if (value.empty()) {
        return false;
    }

    for (const auto& candidate : candidates) {
        if (candidate.endpoint == value.c_str()) {
            return true;
        }
    }

    ppp::app::protocol::P2PEndpointCandidate candidate;
    candidate.endpoint = value.c_str();
    candidate.source = "observed";
    candidates.emplace_back(std::move(candidate));
    return true;
}

}
