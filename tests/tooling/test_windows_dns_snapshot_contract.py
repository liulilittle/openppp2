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


class WindowsDnsSnapshotContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (
            ROOT / "windows/ppp/win32/network/NetworkInterface.cpp"
        ).read_text(encoding="utf-8")

    def test_apply_is_limited_to_captured_authorization_set(self) -> None:
        apply_body = function_body(
            self.source,
            "int SetAllNicsDnsAddresses(ppp::vector<boost::asio::ip::address>& servers",
        )
        self.assertIn("for (const auto& [interface_index, ignored] : addresses)", apply_body)
        self.assertIn("SetDnsAddresses(interface_index, servers_string)", apply_body)
        self.assertNotIn("SetDnsAddresses(ni->InterfaceIndex, servers_string)", apply_body)
        self.assertNotIn("addresses.clear()", apply_body)

    def test_failed_restore_keeps_snapshot_for_retry(self) -> None:
        restore_body = function_body(
            self.source,
            "int SetAllNicsDnsAddresses(ppp::unordered_map<int, ppp::vector<boost::asio::ip::address>>& addresses)",
        )
        self.assertIn("it = addresses.erase(it)", restore_body)
        self.assertIn("Retain failed snapshots", restore_body)
        self.assertNotIn("addresses.clear()", restore_body)

    def test_snapshot_records_stable_identity_and_dns_mode(self) -> None:
        header = (ROOT / "windows/ppp/win32/network/NetworkInterface.h").read_text(
            encoding="utf-8"
        )
        source = self.source
        self.assertIn("NetworkDnsSnapshot", header)
        self.assertIn("InterfaceLuid", header)
        self.assertIn("bool                                            DnsAutomatic", header)
        self.assertIn("CaptureDnsSnapshot", header)
        self.assertIn("SetDnsAddressesWithSnapshot", header)
        self.assertIn("RestoreDnsSnapshot", header)
        self.assertIn("ConvertInterfaceIndexToLuid", source)
        self.assertIn("current->Guid.data(), snapshot.Guid.data()", source)
        self.assertIn("current->InterfaceLuid != snapshot.InterfaceLuid", source)

    def test_restore_preserves_dns_automatic_mode_without_using_ip_dhcp_flag(self) -> None:
        body = function_body(self.source, "bool RestoreDnsSnapshot(")
        self.assertIn("if (snapshot.DnsAutomatic)", body)
        self.assertIn("servers.clear()", body)
        self.assertIn("SetDnsAddresses(snapshot.InterfaceIndex, servers)", body)
        self.assertIn("restored_automatic != snapshot.DnsAutomatic", body)
        self.assertNotIn("snapshot.DhcpEnabled", body)

    def test_production_apply_targets_tap_and_uses_owned_snapshot(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        start = source.index(
            "bool VEthernetNetworkSwitcher::TryApplyHostedNetworkRoutes(bool allow_pre_established)"
        )
        end = source.index(
            "/** @brief Creates concrete TCP/IP stack implementation",
            start,
        )
        body = source[start:end]
        self.assertIn("SetDnsAddressesWithSnapshot", body)
        self.assertIn("tun_ni_->Index", body)
        self.assertIn("ni_dns_snapshots_", body)
        self.assertNotIn("SetAllNicsDnsAddresses", body)

    def test_restore_checks_current_dns_ownership(self) -> None:
        body = function_body(self.source, "bool RestoreDnsSnapshot(")
        self.assertIn("snapshot.DnsApplyAttempted", body)
        self.assertIn("snapshot.AppliedDnsAddresses", body)
        self.assertIn("current_dns != snapshot.AppliedDnsAddresses", body)
        self.assertIn("current_dns == snapshot.DnsAddresses", body)

    def test_restore_owns_dns_mode_as_well_as_server_values(self) -> None:
        body = function_body(self.source, "bool RestoreDnsSnapshot(")
        self.assertIn("GetDnsAutomaticByGuid(current->Guid, current_automatic)", body)
        self.assertIn("snapshot.DnsAutomatic && current_automatic", body)
        self.assertIn("current_automatic == snapshot.DnsAutomatic", body)
        self.assertIn("current_automatic && !snapshot.AppliedDnsAddresses.empty()", body)

    def test_restore_verifies_wmi_result_before_releasing_recovery_record(self) -> None:
        body = function_body(self.source, "bool RestoreDnsSnapshot(")
        write = body.index("if (!SetDnsAddresses(snapshot.InterfaceIndex, servers))")
        verify = body.index("GetNetworkInterfaceByInterfaceIndex(snapshot.InterfaceIndex)", write)
        mode = body.index("restored_automatic != snapshot.DnsAutomatic", verify)
        self.assertLess(write, verify)
        self.assertLess(verify, mode)
        self.assertIn("return restored_dns == snapshot.DnsAddresses", body)

    def test_apply_captures_before_writing_and_marks_owned_values(self) -> None:
        body = function_body(self.source, "bool SetDnsAddressesWithSnapshot(")
        self.assertLess(body.index("CaptureDnsSnapshot"), body.index("SetDnsAddresses(interface_index, servers)"))
        self.assertLess(
            body.index("GetNetworkInterfaceByInterfaceIndex(interface_index)"),
            body.index("SetDnsAddresses(interface_index, servers)"),
        )
        self.assertIn("current->Guid.data(), snapshot.Guid.data()", body)
        self.assertIn("current->InterfaceLuid != snapshot.InterfaceLuid", body)
        self.assertIn("snapshot.AppliedDnsAddresses", body)
        self.assertIn("snapshot.DnsApplyAttempted = true", body)
        self.assertIn("snapshot.DnsApplied = SetDnsAddresses(interface_index, servers)", body)

    def test_hosted_apply_only_retains_owned_dns_snapshot(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        start = source.index(
            "bool VEthernetNetworkSwitcher::TryApplyHostedNetworkRoutes(bool allow_pre_established)"
        )
        end = source.index(
            "/** @brief Creates concrete TCP/IP stack implementation",
            start,
        )
        body = source[start:end]
        retained = body[body.index("// Preserve the snapshot even when the WMI write fails."):]
        self.assertIn("snapshot.DnsApplyAttempted", retained)
        self.assertNotIn("network_recovery_journal_->HasPending()", retained)
        # The intent is marked owned before the OS write, so a partial write
        # still has a compare-and-restore target.
        self.assertLess(
            body.index("snapshot.DnsApplyAttempted = true"),
            body.index("SetDnsAddressesWithSnapshot(", body.index("snapshot.DnsApplyAttempted = true")),
        )

    def test_teardown_retries_each_snapshot_independently(self) -> None:
        source = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("owner_->ni_dns_snapshots_.begin()", source)
        self.assertIn("RestoreDnsSnapshot(it->second)", source)
        self.assertIn("owner_->ni_dns_snapshots_.erase(it)", source)
        self.assertNotIn("SetAllNicsDnsAddresses", source)

    def test_teardown_keeps_snapshot_when_journal_remove_is_not_durable(self) -> None:
        source = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(source, "actions.rollback_route =")
        self.assertIn("const bool journal_removed", body)
        self.assertIn("network_recovery_journal_->Remove", body)
        self.assertIn("if (journal_removed)", body)
        self.assertIn("dns_restore_complete = false", body)
        # A successful OS restore alone must not erase the in-memory retry
        # target when the durable remove did not complete.
        self.assertLess(
            body.index("if (journal_removed)"),
            body.index("owner_->ni_dns_snapshots_.erase(it)"),
        )

        switcher = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        rollback = function_body(
            switcher, "auto rollback = [this, &dns_attempted]() noexcept"
        )
        self.assertIn("const bool journal_removed", rollback)
        self.assertIn("if (journal_removed)", rollback)
        self.assertIn("ni_dns_snapshots_.erase(it)", rollback)

    def test_route_failure_does_not_skip_dns_restore(self) -> None:
        source = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        body = function_body(source, "actions.rollback_route =")
        dns = body.index("RestoreDnsSnapshot")
        route = body.index("owner_->DeleteRoute()")
        self.assertLess(dns, route)
        self.assertIn("route_cleanup_complete = owner_->DeleteRoute()", body)
        self.assertIn("return route_cleanup_complete && dns_restore_complete", body)

    def test_dns_mutation_is_write_ahead_journaled_and_replayed(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("EnsureNetworkRecoveryJournal()", source)
        self.assertIn("NetworkRecoveryJournal::RunRecoveryCommand", source)
        intent = source.index("RecordIntent(")
        apply = source.index("SetDnsAddressesWithSnapshot(", intent)
        confirm = source.index("Confirm(", apply)
        self.assertLess(intent, apply)
        self.assertLess(apply, confirm)
        self.assertIn('"windows-dns"', source[intent:confirm])
        # The original snapshot must be serialized before the target DNS list
        # is populated; otherwise crash recovery would have no before value.
        self.assertIn("const std::string before_dns = SerializeDnsSnapshot(snapshot);", source)
        self.assertLess(
            source.index("before_dns = SerializeDnsSnapshot"),
            source.index("snapshot.AppliedDnsAddresses.clear()"),
        )
        self.assertIn("before_dns,\n                                    SerializeDnsSnapshot(snapshot)", source)
        teardown = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('Remove(\n                                        "windows-dns"', teardown)

    def test_core_startup_recovery_uses_complete_worker_and_fail_closed_gate(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        ensure = function_body(
            source, "bool VEthernetNetworkSwitcher::EnsureNetworkRecoveryJournal()"
        )
        self.assertIn("journal->Close()", ensure)
        self.assertIn("NetworkRecoveryJournal::RunRecoveryCommand", ensure)
        self.assertIn("journal->Open(directory", ensure)
        self.assertIn("network_recovery_journal_->HasPending()", ensure)
        self.assertNotIn("assigned_ipv4_unsupported", ensure)
        self.assertNotIn("assigned_ipv6_unsupported", ensure)


if __name__ == "__main__":
    unittest.main()
