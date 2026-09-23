import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class VmuxTransportBoundaryTests(unittest.TestCase):
    def test_vmux_core_does_not_depend_on_concrete_hosts(self) -> None:
        source = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "ppp/app/mux/vmux.h",
                "ppp/app/mux/vmux_net.h",
                "ppp/app/mux/vmux_net.cpp",
                "ppp/app/mux/vmux_skt.cpp",
            )
        )
        self.assertIn("IMuxTransport", source)
        self.assertNotIn("ppp/app/client/", source)
        self.assertNotIn("ppp/app/server/", source)
        self.assertNotIn("VirtualEthernetTcpipConnection", source)
        self.assertNotIn("VirtualEthernetNetworkTcpipConnection", source)

    def test_exchanger_public_headers_hide_vmux_implementation(self) -> None:
        for relative in (
            "ppp/app/client/VEthernetExchanger.h",
            "ppp/app/server/VirtualEthernetExchanger.h",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("vmux_net", source, relative)
            self.assertNotIn("<ppp/app/mux/vmux_net.h>", source, relative)

    def test_mux_coordinator_owns_session_and_runtime_projection(self) -> None:
        header = (ROOT / "ppp/app/mux/MuxCoordinator.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("class MuxCoordinator final", header)
        self.assertIn("std::shared_ptr<vmux::vmux_net> session_", header)
        self.assertIn("MuxRuntimeState RuntimeState()", header)
        self.assertIn("void Stop()", header)

        client = (ROOT / "ppp/app/client/VEthernetExchanger.h").read_text(
            encoding="utf-8"
        )
        server = (ROOT / "ppp/app/server/VirtualEthernetExchanger.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("std::unique_ptr<ppp::app::mux::MuxCoordinator>", client)
        self.assertIn("std::unique_ptr<ppp::app::mux::MuxCoordinator>", server)

    def test_vmux_boundary_check_runs_in_ci(self) -> None:
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertIn(
            "python3 -m unittest tests.tooling.test_vmux_transport_boundary -v",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
