import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening_brace = source.index("{", start)
    depth = 0
    for offset, character in enumerate(source[opening_brace:], opening_brace):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening_brace + 1 : offset]
    raise AssertionError(f"unterminated function: {signature}")


class WindowsIPv6ContractTests(unittest.TestCase):
    def test_wintun_neighbor_uses_exact_ip_helper_ownership(self) -> None:
        source = (ROOT / "windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp").read_text(
            encoding="utf-8"
        )
        apply_body = function_body(source, "bool ApplyClientDefaultRoute")
        deletion = function_body(source, "static bool DeleteOwnedWintunGatewayNeighbor")
        self.assertIn("CreateIpNetEntry2", source)
        self.assertIn("GetIpNetEntry2", source)
        self.assertIn("DeleteIpNetEntry2", source)
        self.assertIn("IsWintunContext(context)", apply_body)
        self.assertIn("GatewayNeighborOwned", apply_body)
        self.assertIn("GetIfEntry2", deletion)
        self.assertIn("owned_interface_luid", deletion)
        self.assertIn("owned_interface_index", deletion)
        self.assertIn("IsEquivalentGatewayNeighbor(existing, expected)", deletion)
        self.assertNotIn("InitializeMibIfRow", source)
        self.assertNotIn("InitializeIpNetEntry", source)

    def test_neighbor_is_limited_to_actual_wintun_instance(self) -> None:
        header = (ROOT / "windows/ppp/tap/TapWindows.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "windows/ppp/tap/TapWindows.cpp").read_text(
            encoding="utf-8"
        )
        auxiliary = (ROOT / "windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("IsWintunBackend()", header)
        self.assertIn("NULLPTR != wintun_adapter_", source)
        self.assertIn("IsWintunContext(context)", auxiliary)

    def test_address_create_and_delete_are_exact_owned_operations(self) -> None:
        auxiliary = (ROOT / "windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp").read_text(
            encoding="utf-8"
        )
        manager = (ROOT / "ppp/app/client/AssignedAddressManager.cpp").read_text(
            encoding="utf-8"
        )
        policy = (ROOT / "ppp/ipv6/IPv6ClientPolicy.h").read_text(
            encoding="utf-8"
        )
        creation = function_body(auxiliary, "static OwnershipMutation AddManagedUnicastAddress")
        deletion = function_body(auxiliary, "static bool DeleteOwnedUnicastAddress")
        restore = function_body(auxiliary, "void RestoreClientConfiguration")

        self.assertIn("CreateUnicastIpAddressEntry", creation)
        self.assertIn("GetUnicastIpAddressEntry", creation)
        self.assertIn("IsEquivalentUnicastAddress", creation)
        self.assertIn("GetIfEntry2", deletion)
        self.assertIn("GetUnicastIpAddressEntry", deletion)
        self.assertIn("IsExactUnicastAddressMatch", deletion)
        self.assertIn("DeleteUnicastIpAddressEntry", deletion)
        self.assertIn("DeleteOwnedUnicastAddress", restore)
        self.assertIn("AddressOwned", manager)
        self.assertIn("UnicastAddressIdentity", policy)
        self.assertNotIn("GetUnicastIpAddressTable", auxiliary)
        self.assertNotIn("CleanupClientStaleAddresses", auxiliary + manager)

    def test_restore_orders_local_cleanup_without_default_route_mutation(self) -> None:
        source = (ROOT / "windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp").read_text(
            encoding="utf-8"
        )
        restore = function_body(source, "void RestoreClientConfiguration")
        positions = [
            restore.index("DeleteIPv6Route"),
            restore.index("DeleteOwnedWintunGatewayNeighbor"),
            restore.index("DeleteOwnedUnicastAddress"),
            restore.index("SetDnsAddressesV6"),
        ]
        self.assertEqual(positions, sorted(positions))
        for forbidden in (
            "SetIPv6DefaultGateway",
            "SetIPv6DefaultRoute",
            "DeleteIPv6DefaultGateway",
            "QueryOriginalDefaultRoute",
        ):
            self.assertNotIn(forbidden, source)

    def test_route_owner_uses_constrained_pin_and_split_takeover(self) -> None:
        source = (ROOT / "windows/ppp/ipv6/WindowsIPv6RouteOwner.cpp").read_text(
            encoding="utf-8"
        )
        stage = function_body(source, "bool WindowsIPv6RouteOwner::StageEgressEndpoint")
        pair = function_body(source, "bool WindowsIPv6RouteOwner::BuildPair")
        deletion = function_body(source, "bool WindowsIPv6RouteOwner::Delete")
        revalidation = function_body(source, "bool WindowsIPv6RouteOwner::RevalidateInterface")

        self.assertIn("GetBestRoute2(&physical_interface_.InterfaceLuid", stage)
        self.assertIn("physical_interface_.InterfaceIndex", stage)
        self.assertIn("best_route.DestinationPrefix.PrefixLength = 128", stage)
        self.assertIn("IsUnsafeExternalAddress", stage)
        self.assertIn("lower.PrefixLength = 1", pair)
        self.assertIn("upper.Destination[0] = 0x80", pair)
        self.assertIn("GetIfEntry2", revalidation)
        self.assertIn("IsExactRouteRowMatch", deletion)
        self.assertNotIn("PrefixLength = 0", source)

    def test_main_transport_stages_external_endpoint_before_sink(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetExchanger.cpp").read_text(
            encoding="utf-8"
        )
        opening = function_body(source, "VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission")
        loopback = function_body(source, "bool VEthernetExchanger::Loopback")

        self.assertIn("TcpTransmissionRole::Main", opening)
        self.assertIn("forwarding->GetProxyEndPoint()", opening)
        self.assertLess(
            opening.index("StageWindowsIPv6Egress"),
            opening.index("EnsureWindowsIPv6Sink"),
        )
        self.assertLess(
            opening.index("EnsureWindowsIPv6Sink"),
            opening.index("NewAsynchronousSocket"),
        )
        self.assertIn("RollbackWindowsIPv6Egress", opening)
        self.assertIn("had_takeover || switcher_->HasPendingWindowsIPv6Cleanup()", opening)
        self.assertIn("CommitWindowsIPv6Egress", loopback)
        self.assertIn("RollbackWindowsIPv6Egress", loopback)

    def test_opener_prepares_forwarding_before_exchanger_coroutine(self) -> None:
        source = (ROOT / "ppp/app/client/ClientConnectionOpener.cpp").read_text(
            encoding="utf-8"
        )
        opening = function_body(source, "bool ClientConnectionOpener::Open")
        positions = [
            opening.index("owner_->exchanger_ = exchanger"),
            opening.index("PrepareForwarding"),
            opening.index("exchanger->Open()"),
            opening.index("AddRemoteEndPointToIPList"),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("BindWindowsIPv6RouteOwner();", opening)
        self.assertNotIn("if (!owner_->BindWindowsIPv6RouteOwner", opening)
        self.assertEqual(opening.count("AddRemoteEndPointToIPList"), 1)

    def test_sink_takeover_requires_a_proven_egress_pin(self) -> None:
        source = (ROOT / "windows/ppp/ipv6/WindowsIPv6RouteOwner.cpp").read_text(
            encoding="utf-8"
        )
        sink = function_body(source, "bool WindowsIPv6RouteOwner::EnsureSinkMode")
        managed = function_body(source, "bool WindowsIPv6RouteOwner::ActivateManagedMode")
        self.assertIn("transaction_.HasEgress()", sink)
        self.assertIn("transaction_.HasEgress()", managed)

    def test_switcher_managed_transition_and_teardown_order(self) -> None:
        switcher = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        teardown = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        members = (ROOT / "ppp/app/client/VEthernetNetworkSwitcherMembers.inc").read_text(
            encoding="utf-8"
        )
        apply_body = function_body(switcher, "bool VEthernetNetworkSwitcher::ApplyAssignedIPv6")
        restore_body = function_body(switcher, "void VEthernetNetworkSwitcher::RestoreAssignedIPv6")
        rollback = function_body(teardown, "actions.rollback_route =")

        self.assertIn("windows_ipv6_route_owner_", members)
        self.assertLess(
            apply_body.index("address_manager_->ApplyAssignedIPv6"),
            apply_body.index("ActivateWindowsManagedIPv6"),
        )
        failed_transition = apply_body[apply_body.index("if (!ActivateWindowsManagedIPv6") :]
        failed_positions = [
            failed_transition.index("EnsureWindowsIPv6Sink"),
            failed_transition.index("address_manager_->RestoreAssignedIPv6"),
            failed_transition.index("return true"),
        ]
        self.assertEqual(failed_positions, sorted(failed_positions))
        self.assertLess(
            restore_body.index("EnsureWindowsIPv6Sink"),
            restore_body.index("address_manager_->RestoreAssignedIPv6"),
        )
        teardown_positions = [
            rollback.index("RestoreAssignedIPv6"),
            rollback.index("StopWindowsIPv6Routes"),
            rollback.index("tun_ni_.reset"),
        ]
        self.assertEqual(teardown_positions, sorted(teardown_positions))

    def test_new_sources_are_in_visual_studio_project_and_filters(self) -> None:
        project = (ROOT / "ppp.vcxproj").read_text(encoding="utf-8")
        filters = (ROOT / "ppp.vcxproj.filters").read_text(encoding="utf-8")
        entries = (
            r"ppp\ipv6\IPv6ClientPolicy.h",
            r"ppp\ipv6\IPv6RouteTransaction.h",
            r"ppp\ipv6\IPv6RouteTransaction.cpp",
            r"windows\ppp\ipv6\WindowsIPv6RouteOwner.h",
            r"windows\ppp\ipv6\WindowsIPv6RouteOwner.cpp",
        )
        for entry in entries:
            self.assertIn(entry, project)
            self.assertIn(entry, filters)

    def test_paper_airplane_acceptors_retain_shared_ownership(self) -> None:
        source = (
            ROOT / "windows/ppp/app/client/lsp/PaperAirplaneController.cpp"
        ).read_text(encoding="utf-8")
        master = function_body(source, "bool PaperAirplaneController::AcceptMasterAcceptor")
        forward = function_body(source, "bool PaperAirplaneController::AcceptForwardAcceptor")
        self.assertIn("PacketInput(socket", master)
        self.assertNotIn("PacketInput(*socket", master)
        self.assertIn("auto acceptor = acceptors_[1]", forward)
        self.assertIn("AcceptLoopbackSchedulerAsync(*acceptor", forward)
        self.assertIn("[self, this, acceptor]", forward)


if __name__ == "__main__":
    unittest.main()
