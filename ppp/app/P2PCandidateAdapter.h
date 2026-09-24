#pragma once

#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <boost/asio/ip/udp.hpp>
#include <string>

namespace ppp::app {

bool P2PCandidateFromEndpoint(
    const boost::asio::ip::udp::endpoint& endpoint,
    ppp::p2p::P2PCandidateV1& output) noexcept;

std::string P2PEndpointToString(
    const boost::asio::ip::udp::endpoint& endpoint) noexcept;

bool P2PAppendObservedEndpointCandidate(
    const boost::asio::ip::udp::endpoint& endpoint,
    ppp::vector<ppp::app::protocol::P2PEndpointCandidate>& candidates) noexcept;

}
