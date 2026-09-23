import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ProxyOnlyStaticWiringTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_desktop_and_android_normalize_static_mode(self) -> None:
        desktop = self.source("ppp/app/ApplicationClientBootstrap.cpp")
        desktop_bootstrap = desktop[
            desktop.index("bool PrepareClientLoopbackEnvironment(") :
        ]
        self.assertIn(
            "NormalizeClientStaticMode(network_interface->StaticMode, "
            "proxy_only_runtime)",
            desktop_bootstrap,
        )

        android_source = self.source("android/libopenppp2.cpp")
        self.assertIn(
            "#include <ppp/app/ApplicationClientBootstrap.h>", android_source
        )
        android_bootstrap = android_source[
            android_source.index("libopenppp_try_open_ethernet_switcher_new(") :
            android_source.index("libopenppp2_try_open_ethernet_switcher(")
        ]
        normalized = (
            "ppp::app::NormalizeClientStaticMode(network_interface->StaticMode, "
            "proxy_only_runtime)"
        )
        self.assertIn(normalized, android_bootstrap)
        self.assertLess(
            android_bootstrap.index(normalized),
            android_bootstrap.index("client->StaticMode(&static_mode)"),
        )
        self.assertLess(
            android_bootstrap.index("client->StaticMode(&static_mode)"),
            android_bootstrap.index("client->ProxyOnly(&proxy_only_flag)"),
        )

    def test_ipv4_request_uses_normalized_switcher_mode(self) -> None:
        exchanger = self.source("ppp/app/client/VEthernetExchanger.cpp")
        request = exchanger[
            exchanger.index("ClientIPv4Request ipv4_req;") :
            exchanger.index("request.ClientIPv4Req = ipv4_req;")
        ]
        self.assertIn("switcher->StaticMode(NULLPTR)", request)
        self.assertIn('ipv4_req.mode = "manual";', request)
        self.assertGreaterEqual(request.count('ipv4_req.mode = "auto";'), 2)

    def test_existing_docs_describe_the_boundary(self) -> None:
        guide = self.source("docs/guides/PROXY_MODE.md")
        cli = self.source("docs/reference/CLI_REFERENCE.md")
        for document in (guide, cli):
            self.assertIn("STATIC`/`STATICACK", document)
            self.assertIn("automatic", document)


if __name__ == "__main__":
    unittest.main()
