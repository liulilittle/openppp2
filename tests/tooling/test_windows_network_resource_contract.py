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


class WindowsNetworkResourceContractTests(unittest.TestCase):
    def test_firewall_application_cleanup_is_ownership_and_compare_gated(self) -> None:
        header = (ROOT / "windows/ppp/win32/network/Firewall.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "windows/ppp/win32/network/Win32Firewall.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("struct ApplicationOwnership", header)
        self.assertIn("CaptureApplicationOwnership", header)
        self.assertIn("AddApplicationOwned", header)
        self.assertIn("RestoreApplicationOwned", header)
        self.assertIn("ownership->added = !ownership->existed", source)
        self.assertIn("FW_ApplicationRuleState::Conflict", source)
        self.assertIn("conflictingNameFound", source)
        self.assertIn("if (state != FW_ApplicationRuleState::Exact) return false", source)
        self.assertIn("FW_FindApplicationRule(wideName, widePath) ==", source)

    def test_firewall_ownership_is_durably_journaled_and_replayed(self) -> None:
        firewall_header = (ROOT / "windows/ppp/win32/network/Firewall.h").read_text(
            encoding="utf-8"
        )
        firewall_source = (ROOT / "windows/ppp/win32/network/Win32Firewall.cpp").read_text(
            encoding="utf-8"
        )
        journal = (ROOT / "ppp/app/client/NetworkRecoveryJournal.cpp").read_text(
            encoding="utf-8"
        )
        initialize = (ROOT / "ppp/app/ApplicationInitialize.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("SerializeApplicationOwnership", firewall_header)
        self.assertIn('"fw-app-v1|"', firewall_source)
        self.assertIn("DeserializeApplicationOwnership", journal)
        self.assertIn('RecoverPendingFor(\n        "windows-firewall"', journal)
        self.assertIn('RecordIntent("windows-firewall"', initialize)
        self.assertIn("if (before.existed) return true", initialize)
        self.assertIn('Confirm("windows-firewall"', initialize)
        self.assertIn("RecoverWindowsFirewallJournal", initialize)
        self.assertIn("ApplyWindowsFirewallRule", initialize)

    def test_wintun_ownership_uses_supported_handle_cleanup(self) -> None:
        header = (ROOT / "windows/ppp/tap/WintunAdapter.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "windows/ppp/tap/WintunAdapter.cpp").read_text(
            encoding="utf-8"
        )
        open_body = function_body(source, "bool WintunAdapter::Open()")
        finalize_body = function_body(source, "void WintunAdapter::Finalize()")
        self.assertIn("bool OwnsAdapter() const noexcept", header)
        self.assertIn("adapter = WintunOpenAdapter", open_body)
        self.assertIn("owns_adapter = adapter != NULL", open_body)
        self.assertIn("owns_adapter_ = owns_adapter", open_body)
        self.assertNotIn("WintunDeleteAdapter", source)
        self.assertIn("WintunEndSession(session)", finalize_body)
        self.assertIn("WintunCloseAdapter(adapter)", finalize_body)
        self.assertLess(finalize_body.index("WintunEndSession(session)"),
                        finalize_body.index("WintunCloseAdapter(adapter)"))

    def test_wintun_recovery_uses_durable_identity_marker_without_delete_api(self) -> None:
        header = (ROOT / "windows/ppp/tap/WintunAdapter.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "windows/ppp/tap/WintunAdapter.cpp").read_text(
            encoding="utf-8"
        )
        journal = (ROOT / "ppp/app/client/NetworkRecoveryJournal.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("static bool RecoverPending() noexcept", header)
        self.assertIn("static bool HasPendingRecovery() noexcept", header)
        self.assertIn('kRecoveryMarkerHeader = "WINTUN-RECOVERY|1"', source)
        self.assertIn('kRecoveryMarkerName = "wintun-adapter.pending"', source)
        self.assertIn("WriteRecoveryMarker", source)
        self.assertIn("MoveFileExW", source)
        self.assertIn("FlushFileBuffers", source)
        self.assertIn("ConvertInterfaceLuidToIndex", source)
        self.assertIn("VerifyAdapterIdentity", source)
        self.assertIn("WintunStartSession(adapter, 0x100000)", source)
        self.assertIn("GetProcessState", source)
        self.assertIn("WintunAdapter::RecoverPending()", journal)
        self.assertNotIn("WintunDeleteAdapter", source)

    def test_default_gateway_cleanup_owns_exact_default_routes(self) -> None:
        header = (ROOT / "windows/ppp/win32/network/NetworkInterface.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "windows/ppp/win32/network/NetworkInterface.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(source, "bool DeleteAllDefaultGatewayRoutes(boost::asio::ip::address gw)")

        self.assertIn("bool                                                DeleteAllDefaultGatewayRoutes", header)
        self.assertIn("Router::GetIpForwardTable()", body)
        self.assertIn("Router::Delete(route)", body)
        self.assertIn("Router::Add(previous)", body)
        self.assertIn('inet_addr("128.0.0.0")', body)
        self.assertIn("route.dwForwardDest == ppp::net::IPEndPoint::AnyAddress", body)
        self.assertIn("route.dwForwardDest == half", body)
        self.assertNotIn("Win32Native::Echo", body)

    def test_hosted_route_apply_propagates_default_route_failure(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(
            source, "bool VEthernetNetworkSwitcher::TryApplyHostedNetworkRoutes(bool allow_pre_established)"
        )
        cleanup = body[body.index("DeleteAllDefaultGatewayRoutes") :]
        self.assertIn("rollback();", cleanup)
        self.assertIn("return false;", cleanup)

    def test_system_proxy_apply_checks_each_write_and_readback(self) -> None:
        source = (ROOT / "windows/ppp/net/proxies/HttpProxy.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(
            source,
            "bool HttpProxy::SetSystemProxy(const std::wstring& server",
        )
        self.assertIn("bool ok = true;", body)
        self.assertGreaterEqual(body.count("&& ok"), 6)
        self.assertIn("GetRegistryValueString", body)
        self.assertIn("GetRegistryValueDword", body)
        self.assertIn("HttpProxyApplyFailed", body)
        self.assertNotIn("std::regex_match", body)

    def test_core_proxy_persists_complete_snapshot_before_writes(self) -> None:
        source = (ROOT / "windows/ppp/net/proxies/HttpProxy.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('SYSTEM_PROXY_RECOVERY_PATH', source)
        self.assertIn('OriginalServerPresent', source)
        self.assertIn('OriginalEnablePresent', source)
        self.assertIn('OriginalPacPresent', source)
        self.assertIn('OriginalOverridePresent', source)
        self.assertIn('STATIC_CaptureSystemProxySnapshot()', source)
        self.assertIn('STATIC_RestoreSystemProxy(false)', source)
        emergency = function_body(source, "void HttpProxy::EmergencyRestoreSystemProxy()")
        self.assertIn('STATIC_RestoreSystemProxy(false)', emergency)
        self.assertNotIn('ProxyEnable", 0', emergency)
        self.assertNotIn('ProxyServer", 0', emergency)

    def test_core_proxy_snapshot_has_independent_worker_replay(self) -> None:
        proxy_header = (ROOT / "windows/ppp/net/proxies/HttpProxy.h").read_text(
            encoding="utf-8"
        )
        proxy_source = (ROOT / "windows/ppp/net/proxies/HttpProxy.cpp").read_text(
            encoding="utf-8"
        )
        journal = (ROOT / "ppp/app/client/NetworkRecoveryJournal.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("RecoverSystemProxy()", proxy_header)
        self.assertIn("STATIC_RestoreSystemProxy(false)", proxy_source)
        self.assertIn("HttpProxy::RecoverSystemProxy()", proxy_source)
        self.assertIn("HttpProxy::RecoverSystemProxy()", journal)
        self.assertIn("system_proxy_recovered", journal)

    def test_desktop_proxy_record_is_versioned_and_verified(self) -> None:
        source = (ROOT / "desktop/client/src-tauri/src/windows.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn('PROXY_BACKUP_SCHEMA', source)
        self.assertIn('proxy_backup_owner()', source)
        self.assertIn('System proxy apply was not confirmed', source)
        self.assertIn('System proxy restore was not confirmed', source)
        self.assertIn('Unsupported or foreign system proxy recovery record', source)

    def test_proxy_setup_failure_is_not_reported_as_success(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(source, "bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv()")
        failed = body[body.index("if (!bok)") :]
        self.assertIn("ClearHttpProxyToSystemEnv();", failed)
        self.assertIn("return false;", failed)


if __name__ == "__main__":
    unittest.main()
