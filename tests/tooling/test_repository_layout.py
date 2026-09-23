import tempfile
import unittest
from pathlib import Path

from tools import check_repository_layout


ROOT = Path(__file__).resolve().parents[2]


class RepositoryLayoutTests(unittest.TestCase):
    def fixture(self, files: dict[str, str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for relative, contents in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
        return root

    def assert_violation(self, root: Path, expected: str) -> None:
        violations = check_repository_layout.check_repository(root)
        self.assertTrue(
            any(expected in violation for violation in violations),
            f"missing {expected!r} in {violations!r}",
        )

    def test_protocol_cannot_include_client(self) -> None:
        root = self.fixture(
            {
                "ppp/app/protocol/Bad.h": (
                    "#include <ppp/app/client/VEthernetExchanger.h>\n"
                ),
            }
        )
        self.assert_violation(root, "protocol -> client/server")

    def test_client_cannot_include_server(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/Bad.cpp": (
                    "#include <ppp/app/server/VirtualEthernetSwitcher.h>\n"
                ),
            }
        )
        self.assert_violation(root, "client -> server")

    def test_peer_route_snapshot_uses_authenticated_gateway(self) -> None:
        source = (
            ROOT / "ppp/app/server/VirtualEthernetSwitcher.cpp"
        ).read_text(encoding="utf-8")
        snapshot = source[
            source.index("void VirtualEthernetSwitcher::BuildPeerRouteTableSnapshot"):
            source.index("uint32_t VirtualEthernetSwitcher::FindGatewayVirtualIPForDestination")
        ]

        self.assertIn(
            "table.routes.emplace_back(BindPeerRouteGateway(prefix, record.VirtualIP));",
            snapshot,
        )
        self.assertNotIn("route.via.empty()", snapshot)

        policy = (
            ROOT / "ppp/app/server/PeerRouteAnnouncePolicy.h"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "snapshot.via = ppp::net::IPEndPoint::ToAddressString(virtual_ip);",
            policy,
        )

    def test_route_public_header_cannot_expose_switcher(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": (
                    "class VEthernetNetworkSwitcher;\n"
                ),
            }
        )
        self.assert_violation(root, "route/DNS public API exposes concrete host")

    def test_route_public_header_cannot_expose_windows_mib_type(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": "MIB_IPFORWARDTABLE routes;\n",
            }
        )
        self.assert_violation(root, "route public API exposes Windows MIB type")

    def test_route_public_header_cannot_expose_windows_mib_row(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": "MIB_IPFORWARDROW route;\n",
            }
        )
        self.assert_violation(root, "route public API exposes Windows MIB type")

    def test_route_public_header_cannot_expose_windows_mib_aliases_and_tags(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": (
                    "PMIB_IPFORWARDTABLE table;\n"
                    "struct _MIB_IPFORWARDROW row;\n"
                    "MIB_IPFORWARD_ROW2 row2;\n"
                ),
            }
        )
        violations = check_repository_layout.check_repository(root)
        self.assertEqual(
            3,
            sum("route public API exposes Windows MIB type" in item for item in violations),
        )

    def test_switcher_cannot_ignore_route_transaction_result(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/VEthernetNetworkSwitcher.cpp": (
                    "route_coordinator_->AddRoute(input);\n"
                    "ApplyDnsPolicy();\n"
                    "route_coordinator_->ProtectDefaultRoute(input);\n"
                ),
            }
        )
        self.assert_violation(root, "switcher ignores route transaction result")

    def test_switcher_cannot_apply_host_policy_before_route_commit(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/VEthernetNetworkSwitcher.cpp": (
                    "UsePaperAirplaneController();\n"
                    "if (!route_coordinator_->AddRoute(input)) return false;\n"
                ),
            }
        )
        self.assert_violation(root, "host policy precedes route transaction")

    def test_dns_public_header_cannot_expose_exchanger(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/dns/Bad.h": "class VEthernetExchanger;\n",
            }
        )
        self.assert_violation(root, "route/DNS public API exposes concrete host")

    def test_route_ports_cannot_return_mutable_container_pointer(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/Bad.h": (
                    "ppp::function<ppp::unordered_set<uint32_t>*()> values;\n"
                ),
            }
        )
        self.assert_violation(root, "mutable container pointer in public API")

    def test_new_inc_fragment_is_rejected(self) -> None:
        root = self.fixture(
            {"ppp/app/client/NewMembers.inc": "int value_;\n"}
        )
        self.assert_violation(root, "new .inc declaration fragment")

    def test_existing_switcher_inc_fragments_are_grandfathered(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/VEthernetNetworkSwitcherMembers.inc": (
                    "int value_;\n"
                ),
            }
        )
        self.assertEqual([], check_repository_layout.check_repository(root))

    def test_linux_route_manager_cannot_use_route_host_ports(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/RouteCoordinator_linux.cpp": (
                    "route::RouteHostPorts ports = owner_->BuildRouteHostPorts();\n"
                ),
            }
        )
        self.assert_violation(root, "Linux route manager bypasses RouteState")

    def test_route_coordinator_cannot_retain_switcher_owner(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/RouteCoordinator_linux.cpp": (
                    "auto tap = owner_->GetTap();\n"
                ),
            }
        )
        self.assert_violation(root, "route coordinator retains concrete host owner")

    def test_switcher_delete_route_cannot_bypass_coordinator_peer_rollback(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/VEthernetNetworkSwitcher.cpp": (
                    "bool VEthernetNetworkSwitcher::DeleteRoute() noexcept {\n"
                    "    ClearPeerPrefixRoutes();\n"
                    "    return route_coordinator_->DeleteRoute();\n"
                    "}\n"
                ),
            }
        )
        self.assert_violation(root, "peer route teardown bypasses coordinator undo")

    def test_legacy_route_table_manager_is_removed(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/RouteTableManager.h": (
                    "class RouteTableManager {};\n"
                ),
            }
        )
        self.assert_violation(root, "legacy RouteTableManager intermediary")

    def test_route_table_manager_symbol_is_rejected_in_any_ppp_source(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/LegacyRouteOwner.cpp": (
                    "RouteTableManager manager;\n"
                ),
            }
        )
        self.assert_violation(root, "legacy RouteTableManager intermediary")

    def test_any_route_source_cannot_retain_owner_wrapper(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/RouteWorker.cpp": (
                    "auto tap = owner_->GetTap();\n"
                ),
            }
        )
        self.assert_violation(root, "route coordinator retains concrete host owner")

    def test_route_host_ports_are_removed(self) -> None:
        root = self.fixture(
            {"ppp/app/client/Legacy.cpp": "route::RouteHostPorts ports;\n"}
        )
        self.assert_violation(root, "legacy RouteHostPorts service locator")

    def test_dns_host_service_locator_is_removed(self) -> None:
        root = self.fixture(
            {"ppp/app/client/Legacy.cpp": "DnsHostPorts cache; IDnsHost* host;\n"}
        )
        self.assert_violation(root, "legacy DNS host service locator")

    def test_route_manager_platform_source_requires_stdafx_first(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/RouteCoordinator_linux.cpp": (
                    "#include <ppp/app/client/route/RouteCoordinator.h>\n"
                    "#include <ppp/stdafx.h>\n"
                ),
            }
        )
        self.assert_violation(root, "platform source must include stdafx first")

    def test_linux_route_platform_requires_complete_route_entry(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/LinuxRoutePlatform.cpp": (
                    "#include <ppp/stdafx.h>\n"
                    "auto next_hop = entry.NextHop;\n"
                ),
            }
        )
        self.assert_violation(root, "Linux route adapter requires complete RouteEntry")

    def test_linux_eexist_requires_exact_query_and_production_classifier(self) -> None:
        degraded_blocks = (
            "return ClassifyRouteAddResult(err, true, true);\n",
            (
                "bool exists = false;\n"
                "TryRouteExists(ifrName, address, prefix, gw, exists);\n"
                "return exists ? RouteMutationResult::Unchanged : "
                "RouteMutationResult::Failed;\n"
            ),
            (
                "bool exists = false;\n"
                "TryRouteExists(ifrName, address, prefix, gw, exists);\n"
                "ClassifyRouteAddResult(err, true, exists);\n"
                "return RouteMutationResult::Unchanged;\n"
            ),
        )
        for degraded in degraded_blocks:
            with self.subTest(degraded=degraded):
                root = self.fixture(
                    {
                        "linux/ppp/tap/TapLinux.cpp": (
                            "TapLinux::RouteMutationResult TapLinux::AddRouteStatus() {\n"
                            "if (EEXIST == err) {\n"
                            f"{degraded}"
                            "}\n"
                            "}\n"
                        ),
                    }
                )
                self.assert_violation(
                    root,
                    "Linux route EEXIST bypasses exact production classifier",
                )

    def test_darwin_system_route_probe_must_bind_tap_exact_query(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/DarwinRoutePlatform.cpp": (
                    "operations.route_exists = [](const RouteSpec&, bool&) {\n"
                    "    return TapDarwin::TryFindAllDefaultGatewayRoutes();\n"
                    "};\n"
                ),
            }
        )
        self.assert_violation(
            root,
            "Darwin system route probe bypasses exact route query",
        )

    def test_darwin_route_query_must_use_all_route_identity_helper(self) -> None:
        degraded_methods = (
            (
                "FetchAllRouteNtreeStuff([](int, uint32_t ip, uint32_t gw, "
                "uint32_t mask) { return ip == address; });\n"
            ),
            (
                "TryFindAllDefaultGatewayRoutes({}, routes);\n"
                "return IsExactRoute(address, prefix, gw, ip, mask, next_hop);\n"
            ),
        )
        for degraded in degraded_methods:
            with self.subTest(degraded=degraded):
                root = self.fixture(
                    {
                        "darwin/ppp/tap/TapDarwin.cpp": (
                            "bool TapDarwin::TryRouteExists() {\n"
                            f"{degraded}"
                            "}\n"
                        ),
                    }
                )
                self.assert_violation(
                    root,
                    "Darwin route query bypasses all-route production identity",
                )

    def test_windows_gateway_requires_allocator_safe_string_conversion(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/WindowsRoutePlatform.cpp": (
                    "ppp::vector<ppp::string>{ underlying_gateway };\n"
                ),
            }
        )
        self.assert_violation(root, "Windows gateway crosses string allocator boundary")

    def test_windows_route_add_cannot_probe_or_delete_preexisting_routes(self) -> None:
        root = self.fixture(
            {
                "ppp/app/client/route/WindowsRoutePlatform.cpp": (
                    "operations.add = [](const RouteSpec& route) noexcept {\n"
                    "    Router::GetBestRoute(route.network, best);\n"
                    "    Router::Delete(best);\n"
                    "};\n"
                    "operations.restore_default = [](const auto& route) noexcept {\n"
                    "    Router::Delete(route);\n"
                    "};\n"
                ),
            }
        )
        violations = check_repository_layout.check_repository(root)
        self.assertEqual(
            2,
            sum(
                "Windows route Add mutates pre-existing route" in item
                for item in violations
            ),
        )


if __name__ == "__main__":
    unittest.main()
