#pragma once

#include <ppp/stdafx.h>
#include <ppp/app/protocol/PeerPrefixRoute.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#include <boost/asio/ip/address.hpp>

namespace ppp {
namespace app {
namespace server {

/** Minimal allowlist row used by the announce policy (test-friendly). */
struct PeerRouteAllowEntry final {
    ppp::string network;
    int         prefix = 0;
    ppp::string guid;
};

/** Minimal announce row (network/prefix only). */
struct PeerRouteAnnounceEntry final {
    ppp::string network;
    int         prefix = 0;

    bool HasAny() const noexcept {
        return !network.empty() && prefix > 0;
    }
};

inline ppp::app::protocol::PeerPrefixRouteEntry BindPeerRouteGateway(
    const ppp::app::protocol::PeerPrefixRouteEntry& route,
    uint32_t virtual_ip) {
    ppp::app::protocol::PeerPrefixRouteEntry snapshot = route;
    snapshot.via = ppp::net::IPEndPoint::ToAddressString(virtual_ip);
    return snapshot;
}

/** Normalize network+prefix into host-order network base; false if invalid. */
inline bool ParsePeerPrefixNetwork(
    const ppp::string& network_text,
    int prefix,
    uint32_t& network) noexcept {
    network = 0;
    if (network_text.empty() ||
        prefix <= 0 ||
        prefix > ppp::net::native::MAX_PREFIX_VALUE_V4) {
        return false;
    }

    boost::system::error_code ec;
    // Use Asio directly so unit tests need no PPP string helpers.
    const boost::asio::ip::address address =
        boost::asio::ip::make_address(network_text.data(), ec);
    if (ec || !address.is_v4()) {
        return false;
    }

    const uint32_t raw = address.to_v4().to_uint();
    const uint32_t mask = ntohl(ppp::net::IPEndPoint::PrefixToNetmask(prefix));
    network = raw & mask;
    return true;
}

/** Default route and reserved ranges that must never be peer-installed. */
inline bool IsDangerousPeerPrefix(uint32_t network, int prefix) noexcept {
    if (prefix <= 0 || prefix > ppp::net::native::MAX_PREFIX_VALUE_V4) {
        return true;
    }

    const uint32_t mask = ntohl(ppp::net::IPEndPoint::PrefixToNetmask(prefix));
    auto in_range = [&](uint32_t base, int base_prefix) noexcept -> bool {
        const uint32_t base_mask = ntohl(ppp::net::IPEndPoint::PrefixToNetmask(base_prefix));
        return prefix >= base_prefix && (network & base_mask) == (base & base_mask);
    };

    if ((network & mask) == 0) {
        return true;
    }

    return in_range(0x00000000u, 8) ||
        in_range(0x7f000000u, 8) ||
        in_range(0xa9fe0000u, 16) ||
        in_range(0xe0000000u, 4) ||
        in_range(0xf0000000u, 4);
}

/**
 * Normalize a GUID string for allowlist comparison.
 * Lowercase, drop braces.
 */
inline ppp::string NormalizePeerRouteGuid(const ppp::string& guid) noexcept {
    ppp::string out;
    out.reserve(guid.size());
    for (char ch : guid) {
        if (ch == '{' || ch == '}') {
            continue;
        }
        if (ch >= 'A' && ch <= 'Z') {
            out.push_back(static_cast<char>(ch - 'A' + 'a'));
        }
        else {
            out.push_back(ch);
        }
    }
    return LTrim(RTrim(out));
}

/**
 * Fail-closed allowlist check: only exact per-client GUID + network/prefix
 * matches may be announced. Empty allowlist rejects everything.
 */
inline bool IsPeerRouteAnnouncementAllowed(
    const ppp::vector<PeerRouteAllowEntry>& allowed_routes,
    const ppp::string& session_guid,
    const PeerRouteAnnounceEntry& prefix) noexcept {
    const ppp::string session_key = NormalizePeerRouteGuid(session_guid);
    if (session_key.empty() || !prefix.HasAny()) {
        return false;
    }

    uint32_t requested_network = 0;
    if (!ParsePeerPrefixNetwork(prefix.network, prefix.prefix, requested_network) ||
        IsDangerousPeerPrefix(requested_network, prefix.prefix)) {
        return false;
    }

    for (const PeerRouteAllowEntry& allowed : allowed_routes) {
        const ppp::string allowed_guid = NormalizePeerRouteGuid(allowed.guid);
        if (allowed_guid.empty() || allowed_guid != session_key) {
            continue;
        }
        if (allowed.prefix != prefix.prefix) {
            continue;
        }

        uint32_t allowed_network = 0;
        if (ParsePeerPrefixNetwork(allowed.network, allowed.prefix, allowed_network) &&
            allowed_network == requested_network) {
            return true;
        }
    }

    return false;
}

} // namespace server
} // namespace app
} // namespace ppp
