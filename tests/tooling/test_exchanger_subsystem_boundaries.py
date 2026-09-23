import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ExchangerSubsystemBoundaryTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_frp_registry_owns_mapping_table(self) -> None:
        header = self.source("ppp/app/client/ClientFrpRegistry.h")
        self.assertIn("class ClientFrpRegistry final", header)
        self.assertIn("MappingTable mappings_", header)
        self.assertIn("std::mutex mutex_", header)
        for method in ("Add(", "Get(", "Remove(", "Tick(", "ReleaseAll("):
            self.assertIn(method, header)
        self.assertNotIn("VEthernetExchanger", header)
        self.assertNotIn("owner_", header)

    def test_exchanger_delegates_frp_storage_and_keepalive_state(self) -> None:
        header = self.source("ppp/app/client/VEthernetExchanger.h")
        source = self.source("ppp/app/client/VEthernetExchanger.cpp")
        self.assertNotIn("VirtualEthernetMappingPortTable mappings_", header)
        self.assertIn("std::unique_ptr<ClientFrpRegistry>", header)
        self.assertIn("frp_registry_->Tick(now)", source)
        self.assertIn("frp_registry_->ReleaseAll()", source)
        self.assertIn("ClientKeepAlivePolicy", header)
        self.assertNotIn("sekap_last_", header)
        self.assertNotIn("sekap_next_", header)

    def test_static_echo_channel_owns_its_domain_state(self) -> None:
        channel = self.source("ppp/app/client/ExchangerStaticEchoChannel.h")
        exchanger = self.source("ppp/app/client/VEthernetExchanger.h")
        for field in (
            "static_echo_sockets_",
            "static_echo_protocol_",
            "static_echo_transport_",
            "static_echo_session_id_",
            "static_echo_remote_port_",
            "static_echo_timeout_",
            "static_echo_server_ep_balances_",
            "static_echo_server_ep_set_",
        ):
            self.assertIn(field, channel)
            self.assertNotIn(field, exchanger)
        self.assertIn("std::mutex syncobj_", channel)


if __name__ == "__main__":
    unittest.main()
