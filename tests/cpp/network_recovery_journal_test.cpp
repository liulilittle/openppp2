#include <ppp/app/client/NetworkRecoveryJournal.h>

#include <cassert>
#include <filesystem>
#include <iostream>

using ppp::app::client::NetworkRecoveryJournal;

int main() {
    const auto root = std::filesystem::temp_directory_path() / "openppp2-network-recovery-journal-test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);

    NetworkRecoveryJournal journal;
    assert(journal.Open(root.string(), "test-owner"));
    assert(journal.RecordIntent("dns", "if:7", "dhcp", "1.1.1.1"));
    assert(journal.HasPending());
    assert(journal.Pending().front().before == "dhcp");
    assert(journal.Confirm("dns", "if:7"));
    journal.Close();

    NetworkRecoveryJournal reopened;
    assert(reopened.Open(root.string(), "test-owner"));
    auto pending = reopened.Pending();
    assert(pending.size() == 1 && pending.front().confirmed);
    assert(reopened.Remove("dns", "if:7"));
    reopened.Close();

    NetworkRecoveryJournal empty;
    assert(empty.Open(root.string(), "test-owner"));
    assert(!empty.HasPending());
    empty.Close();

    const auto worker_root = root / "worker";
    const std::string recovery_dir_arg = "--network-recovery-dir=" + worker_root.string();
    const char* recovery_argv[] = {"ppp", "--network-recovery", recovery_dir_arg.c_str()};
    assert(NetworkRecoveryJournal::IsRecoveryCommand(3, recovery_argv));
    assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 0);

    NetworkRecoveryJournal unsupported_recovery;
    assert(unsupported_recovery.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(unsupported_recovery.RecordIntent("route", "if:7", "old", "new"));
    unsupported_recovery.Close();
    assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 2);
    NetworkRecoveryJournal retained_route;
    assert(retained_route.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(retained_route.HasPendingFor("route"));
    assert(retained_route.Remove("route", "if:7"));
    retained_route.Close();

    // A route-shaped target must still fail closed when its stable snapshot
    // cannot be decoded. The independent worker must leave it retryable.
    NetworkRecoveryJournal malformed_route;
    assert(malformed_route.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(malformed_route.RecordIntent(
        "route", "created-v2:malformed", "old", "malformed"));
    malformed_route.Close();
    assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 2);
    NetworkRecoveryJournal retained_malformed;
    assert(retained_malformed.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(retained_malformed.HasPendingFor("route"));
    assert(retained_malformed.Remove("route", "created-v2:malformed"));
    retained_malformed.Close();

    for (const char* resource : {"proxy", "firewall", "assigned-ipv4", "assigned-ipv6", "future-resource"}) {
        NetworkRecoveryJournal unsupported;
        assert(unsupported.Open(worker_root.string(), "openppp2-core-network-v1"));
        assert(unsupported.RecordIntent(resource, "target", "old", "new"));
        unsupported.Close();
        assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 2);
        NetworkRecoveryJournal retained;
        assert(retained.Open(worker_root.string(), "openppp2-core-network-v1"));
        assert(retained.HasPendingFor(resource));
        assert(retained.Remove(resource, "target"));
        retained.Close();
    }
    // assigned-ipv4 records use a versioned GUID/LUID/index identity. A
    // syntactically valid record must remain durable when the worker cannot
    // prove adapter identity or compare-and-restore state.
    NetworkRecoveryJournal assigned_ipv4_contract;
    assert(assigned_ipv4_contract.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(assigned_ipv4_contract.RecordIntent(
        "assigned-ipv4", "{adapter-guid}",
        "ipv4-v2|{adapter-guid}|luid:1|7|10.0.0.2|255.255.255.252|10.0.0.1",
        "ipv4-v2|{adapter-guid}|luid:1|7|10.0.0.3|255.255.255.0|10.0.0.1"));
    assigned_ipv4_contract.Close();
    assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 2);
    NetworkRecoveryJournal retained_assigned_ipv4;
    assert(retained_assigned_ipv4.Open(worker_root.string(),
        "openppp2-core-network-v1"));
    assert(retained_assigned_ipv4.HasPendingFor("assigned-ipv4"));
    assert(retained_assigned_ipv4.Remove("assigned-ipv4", "{adapter-guid}"));
    retained_assigned_ipv4.Close();
    assert(NetworkRecoveryJournal::RunRecoveryCommand(3, recovery_argv) == 0);

    NetworkRecoveryJournal replay;
    assert(replay.Open(root.string(), "test-owner"));
    assert(replay.RecordIntent("dns", "if:7", "dhcp", "1.1.1.1"));
    assert(replay.RecordIntent("route", "if:7", "old", "new"));
    // A post-add platform row can be promoted atomically without exposing a
    // window where a crash loses the original intent.
    assert(replay.ReplaceTarget(
        "route", "if:7", "created-v2:stable-row", "stable-row"));
    auto promoted = replay.PendingFor("route");
    assert(promoted.size() == 1);
    assert(promoted.front().target == "created-v2:stable-row");
    assert(promoted.front().after == "stable-row");
    assert(!promoted.front().confirmed);
    assert(replay.Confirm("route", "created-v2:stable-row"));
    assert(replay.HasPendingFor("dns"));
    assert(replay.HasPendingFor("route"));
    assert(!replay.HasPendingFor("proxy"));
    assert(replay.PendingFor("dns").size() == 1);
    assert(replay.PendingFor("proxy").empty());
    bool saw_dns = false;
    assert(!replay.RecoverPending([&](const NetworkRecoveryJournal::Entry& entry) {
        if (entry.resource == "dns") { saw_dns = true; return true; }
        return false;
    }));
    assert(saw_dns);
    assert(replay.Pending().size() == 1);
    assert(replay.Pending().front().resource == "route");
    assert(replay.RecoverPending([](const NetworkRecoveryJournal::Entry&) { return true; }));
    assert(!replay.HasPending());
    replay.Close();

    // Resource-scoped recovery must leave unrelated entries untouched. This
    // is required when DNS, route and firewall handlers run independently.
    NetworkRecoveryJournal scoped;
    assert(scoped.Open(root.string(), "test-owner"));
    assert(scoped.RecordIntent("dns", "if:8", "dhcp", "9.9.9.9"));
    assert(scoped.RecordIntent("route", "if:8", "old", "new"));
    assert(scoped.RecoverPendingFor(
        "dns", [](const NetworkRecoveryJournal::Entry& entry) {
            return entry.resource == "dns";
        }));
    assert(!scoped.HasPendingFor("dns"));
    assert(scoped.HasPendingFor("route"));
    assert(scoped.HasPending());
    assert(scoped.RecoverPending(
        [](const NetworkRecoveryJournal::Entry& entry) {
            return entry.resource == "route";
        },
        [](const NetworkRecoveryJournal::Entry&) { return true; }));
    assert(!scoped.HasPending());
    scoped.Close();

    NetworkRecoveryJournal::Options options;
    options.allow_stage = [](NetworkRecoveryJournal::Stage stage) {
        return stage != NetworkRecoveryJournal::Stage::Rename;
    };

    NetworkRecoveryJournal remove_source;
    assert(remove_source.Open(root.string(), "test-owner"));
    assert(remove_source.RecordIntent("dns", "if:9", "dhcp", "9.9.9.9"));
    remove_source.Close();
    NetworkRecoveryJournal remove_fault;
    assert(remove_fault.Open(root.string(), "test-owner", options));
    assert(!remove_fault.RecoverPending([](const NetworkRecoveryJournal::Entry&) { return true; }));
    assert(remove_fault.HasPending());
    remove_fault.Close();
    NetworkRecoveryJournal remove_cleanup;
    assert(remove_cleanup.Open(root.string(), "test-owner"));
    assert(remove_cleanup.Remove("dns", "if:9"));
    remove_cleanup.Close();

    NetworkRecoveryJournal faulted;
    assert(faulted.Open(root.string(), "test-owner", options));
    assert(!faulted.RecordIntent("route", "if:7", "old", "new"));
    assert(!faulted.HasPending());
    faulted.Close();

    NetworkRecoveryJournal rewrite_fault;
    assert(rewrite_fault.Open(root.string(), "test-owner"));
    assert(rewrite_fault.RecordIntent("route", "if:7", "old", "new"));
    rewrite_fault.Close();
    NetworkRecoveryJournal rewrite_retry;
    assert(rewrite_retry.Open(root.string(), "test-owner", options));
    assert(!rewrite_retry.RecordIntent("route", "if:7", "mutated", "value"));
    assert(rewrite_retry.Pending().front().before == "old");
    rewrite_retry.Close();

    NetworkRecoveryJournal wrong_owner;
    assert(!wrong_owner.Open(root.string(), "other-owner"));
    std::filesystem::remove_all(root, ec);
    std::cout << "network recovery journal tests passed\n";
}
