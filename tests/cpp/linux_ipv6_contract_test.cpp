#include <iostream>

#include <linux/ppp/tap/TapLinux.h>
#include <ppp/app/server/IPv6TransitPolicy.h>
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/ipv6/IPv6ClientPolicy.h>

int main() {
    using ppp::app::server::ipv6_transit_policy::IsPacketAllowed;
    using NeighborResult = ppp::tap::TapLinux::NeighborMutationResult;

    int failures = 0;
    auto check = [&failures](bool condition, const char* message) noexcept {
        if (!condition) {
            std::cerr << "FAILED: " << message << std::endl;
            ++failures;
        }
    };

    const auto prefix = boost::asio::ip::make_address_v6("fd42:4242:4242::");
    const auto gateway_v6 = boost::asio::ip::make_address_v6("fd42:4242:4242::1");
    const boost::asio::ip::address gateway(gateway_v6);
    const auto client_source = boost::asio::ip::make_address_v6("fd42:4242:4242::10");
    const auto client_destination = boost::asio::ip::make_address_v6("fd42:4242:4242::20");
    const auto public_source = boost::asio::ip::make_address_v6("2001:db8:ffff::10");
    const auto outside_private_source = boost::asio::ip::make_address_v6("fd99::10");
    const auto outside_destination = boost::asio::ip::make_address_v6("2001:db8:ffff::20");

    check(IsPacketAllowed(public_source, client_destination, prefix, 64, &gateway, true),
        "public source to owned prefix destination must be accepted");
    check(IsPacketAllowed(gateway_v6, client_destination, prefix, 64, &gateway, true),
        "transit gateway source must be accepted");
    check(!IsPacketAllowed(client_source, client_destination, prefix, 64, &gateway, true),
        "prefix source arriving from host transit TAP must be rejected");
    check(!IsPacketAllowed(outside_private_source, client_destination, prefix, 64, &gateway, true),
        "private source outside the managed prefix must be rejected");
    check(!IsPacketAllowed(public_source, client_destination, prefix, 64, &gateway, false),
        "unknown destination must be rejected");
    check(!IsPacketAllowed(public_source, outside_destination, prefix, 64, &gateway, true),
        "destination outside configured prefix must be rejected");
    check(!IsPacketAllowed(boost::asio::ip::address_v6(), client_destination, prefix, 64, &gateway, true),
        "unspecified source must be rejected");

    check(ppp::tap::TapLinux::ClassifyPermanentNeighborAddResult(0, false, false) == NeighborResult::Changed,
        "successful neighbor add must report ownership");
    check(ppp::tap::TapLinux::ClassifyPermanentNeighborAddResult(EEXIST, true, true) == NeighborResult::Unchanged,
        "matching pre-existing neighbor must remain unowned");
    check(ppp::tap::TapLinux::ClassifyPermanentNeighborAddResult(EEXIST, true, false) == NeighborResult::Failed,
        "non-matching existing neighbor must fail");
    check(ppp::tap::TapLinux::ClassifyPermanentNeighborAddResult(EEXIST, false, true) == NeighborResult::Failed,
        "failed existing-neighbor query must fail");
    check(ppp::tap::TapLinux::ClassifyPermanentNeighborAddResult(EPERM, true, true) == NeighborResult::Failed,
        "non-EEXIST add error must fail");

    using ppp::ipv6::client_policy::ClassifyCreateResult;
    using ppp::ipv6::client_policy::GatewayNeighborIdentity;
    using ppp::ipv6::client_policy::IsExactGatewayNeighborMatch;
    using ppp::ipv6::client_policy::OwnershipMutation;
    check(ClassifyCreateResult(0, 0, 183, false, false) == OwnershipMutation::Changed,
        "successful Windows neighbor create must take ownership");
    check(ClassifyCreateResult(183, 0, 183, true, true) == OwnershipMutation::Unchanged,
        "equivalent pre-existing Windows neighbor must remain unowned");
    check(ClassifyCreateResult(183, 0, 183, true, false) == OwnershipMutation::Failed,
        "conflicting Windows neighbor must fail closed");
    check(ClassifyCreateResult(183, 0, 183, false, true) == OwnershipMutation::Failed,
        "unqueryable Windows neighbor must fail closed");

    GatewayNeighborIdentity expected_neighbor;
    expected_neighbor.Address[15] = 1;
    expected_neighbor.ScopeId = 17;
    expected_neighbor.InterfaceLuid = 0x12345678;
    expected_neighbor.InterfaceIndex = 17;
    expected_neighbor.PhysicalAddressLength = 6;
    expected_neighbor.PhysicalAddress[5] = 1;
    expected_neighbor.IsRouter = true;
    expected_neighbor.IsPermanent = true;
    check(IsExactGatewayNeighborMatch(expected_neighbor, expected_neighbor),
        "exact Windows gateway neighbor must be eligible for owned deletion");

    GatewayNeighborIdentity mismatched_neighbor = expected_neighbor;
    ++mismatched_neighbor.Address[15];
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "IPv6-address mismatch must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    ++mismatched_neighbor.ScopeId;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "scope mismatch must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    mismatched_neighbor.IsRouter = false;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "router mismatch must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    ++mismatched_neighbor.InterfaceLuid;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "LUID mismatch must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    ++mismatched_neighbor.InterfaceIndex;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "interface-index mismatch must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    mismatched_neighbor.IsPermanent = false;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "non-permanent neighbor must block Windows gateway neighbor deletion");
    mismatched_neighbor = expected_neighbor;
    mismatched_neighbor.PhysicalAddress[5] = 2;
    check(!IsExactGatewayNeighborMatch(mismatched_neighbor, expected_neighbor),
        "synthetic-MAC mismatch must block Windows gateway neighbor deletion");

    ppp::ipv6::auxiliary::ClientState state;
    check(!state.GatewayNeighborOwned, "client state must start without gateway ownership");
    state.GatewayNeighborOwned = true;
    state.GatewayNeighborInterfaceLuid = expected_neighbor.InterfaceLuid;
    state.GatewayNeighborInterfaceIndex = static_cast<int>(expected_neighbor.InterfaceIndex);
    state.Clear();
    check(!state.GatewayNeighborOwned, "explicit state clear must reset gateway ownership");
    check(state.GatewayNeighborInterfaceLuid == 0,
        "explicit state clear must reset gateway-neighbor LUID");
    check(state.GatewayNeighborInterfaceIndex == -1,
        "explicit state clear must reset gateway-neighbor interface index");

    return failures == 0 ? 0 : 1;
}
