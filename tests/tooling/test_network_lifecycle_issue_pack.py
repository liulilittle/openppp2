import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ISSUE_PACK = ROOT / "docs/architecture/NETWORK_LIFECYCLE_ISSUES.md"


class NetworkLifecycleIssuePackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = ISSUE_PACK.read_text(encoding="utf-8")
        cls.normalized = " ".join(cls.body.split())

    def test_pack_declares_local_publish_boundary(self) -> None:
        self.assertIn("local issue pack", self.body)
        self.assertIn("does not claim that these bodies have been published", self.body)
        self.assertIn("when remote access is available", self.body)

    def test_canonical_epic_and_child_issue_keys_are_present(self) -> None:
        for key in ("#82", "#83", "#84", "#85", "#86", "#87"):
            self.assertIn(f"| {key} |", self.body)
        for follow_up in (
            "Follow-up issue A",
            "Follow-up issue B",
            "Follow-up issue C",
            "Follow-up issue D",
            "Follow-up issue E",
            "Follow-up issue F",
            "Follow-up issue G",
            "Follow-up issue H",
        ):
            self.assertIn(f"## {follow_up}", self.body)

    def test_close_gates_require_evidence_and_do_not_equate_build_with_restore(
        self,
    ) -> None:
        self.assertIn(
            "A passing compile or static contract test alone does not close a host-network issue.",
            self.normalized,
        )
        self.assertIn(
            "The report distinguishes offline evidence from privileged runtime evidence.",
            self.normalized,
        )
        self.assertIn("Windows host evidence", self.normalized)
        self.assertIn("Linux namespace tests need explicit privilege", self.normalized)

    def test_mandatory_matrix_covers_failure_conflict_and_process_lifecycle(
        self,
    ) -> None:
        required_fragments = (
            "static IPv4 DNS",
            "static IPv6 DNS",
            "DHCP/automatic DNS",
            "adapter that is down or disappears",
            "route add/delete failure",
            "DNS failure while route cleanup still runs",
            "Core timeout",
            "forced termination",
            "restart recovery",
            "corrupted pending marker",
            "second-VPN DNS/route changes",
            "two OpenPPP2 sessions contending",
            "Wi-Fi/interface change",
        )
        for fragment in required_fragments:
            self.assertIn(fragment, self.normalized)

    def test_recovery_invariants_and_unverified_platform_scope_are_explicit(
        self,
    ) -> None:
        required_fragments = (
            "intent before the OS call",
            "confirmation after the call",
            "verified removal after restore",
            "failed or unverified restore leaves a retryable journal entry",
            "preserves the later external value",
            "Windows host DNS/route acceptance | no current job | Required gap",
            "optional platform coverage is marked `unverified` rather than passed",
        )
        for fragment in required_fragments:
            self.assertIn(fragment, self.normalized)


if __name__ == "__main__":
    unittest.main()
