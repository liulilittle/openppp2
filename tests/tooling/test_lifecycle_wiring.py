import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class LifecycleWiringTests(unittest.TestCase):
    def test_client_teardown_uses_runtime_stop_pipeline(self) -> None:
        source = (ROOT / "ppp/app/client/ClientConnectionTeardown.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("RuntimeStopPipeline::Execute", source)
        positions = [
            source.index("stop_input"),
            source.index("close_dns"),
            source.index("dispose_exchanger"),
            source.index("rollback_route"),
        ]
        self.assertEqual(positions, sorted(positions))

    def test_client_teardown_result_is_retained_by_switcher(self) -> None:
        source = (ROOT / "ppp/app/client/VEthernetNetworkSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        header = (ROOT / "ppp/app/client/VEthernetNetworkSwitcherPublicMethods.inc").read_text(
            encoding="utf-8"
        )
        self.assertIn("last_teardown_success_.store", source)
        self.assertIn("WasTeardownSuccessful", header)

    def test_application_stop_owner_completes_with_teardown_result(self) -> None:
        main_loop = (ROOT / "ppp/app/ApplicationMainLoop.cpp").read_text(
            encoding="utf-8"
        )
        release = (ROOT / "ppp/app/ApplicationInitialize.cpp").read_text(
            encoding="utf-8"
        )
        dispose = main_loop[
            main_loop.index("void PppApplication::Dispose()"):
            main_loop.index("bool PppApplication::GetTransmissionStatistics")
        ]
        self.assertIn("if (!runtime_lifecycle_.TryBeginStop", dispose)
        self.assertIn("client->Dispose(std::move(completion))", dispose)
        self.assertIn("runtime_lifecycle_.CompleteStop", dispose)
        self.assertNotIn("runtime_lifecycle_.CompleteStop", release)

    def test_android_stop_completion_is_owned_and_reports_cleanup(self) -> None:
        source = (ROOT / "android/libopenppp2.cpp").read_text(encoding="utf-8")
        release = source[
            source.index("libopenppp2_application::Release()"):
            source.index("libopenppp2_application::ExecJNI")
        ]
        self.assertIn("const bool stop_owner", release)
        self.assertIn("client->Dispose(std::move(completion))", release)
        self.assertIn("if (stop_owner)", release)

        self.assertIn("Release(false", source)

    def test_ios_stop_completion_is_owned_and_reports_cleanup(self) -> None:
        source = (ROOT / "ios/OpenPPP2PacketTunnelBridge.cpp").read_text(
            encoding="utf-8"
        )
        stop = source[
            source.index("int openppp2_ios_tap_stop"):
            source.index("int openppp2_ios_tap_input")
        ]
        self.assertIn("const bool stop_owner", stop)
        self.assertIn("client->Dispose(cleanup_complete)", stop)
        self.assertIn("if (stop_owner)", stop)

        start = source[
            source.index("int openppp2_ios_tap_start"):
            source.index("const char* stop_reason_name")
        ]
        self.assertIn("if (tap->runtime_lifecycle.TryBeginStop(", start)

    def test_mobile_stop_timeout_is_presentation_only(self) -> None:
        dart = (ROOT / "android/lib/runtime/runtime_controls.dart").read_text(
            encoding="utf-8"
        )
        swift = (ROOT / "ios/App/OpenPPP2/Runtime/RuntimeControls.swift").read_text(
            encoding="utf-8"
        )
        self.assertIn("stopTakingTooLong", dart)
        self.assertIn("停止耗时过长", dart)
        self.assertIn("stopTakingTooLong", swift)
        self.assertIn('"home.stopTakingTooLong"', swift)

    def test_client_dispose_completion_follows_real_finalize(self) -> None:
        exchanger = (ROOT / "ppp/app/client/VEthernetExchanger.cpp").read_text(
            encoding="utf-8"
        )
        dispose = exchanger[
            exchanger.index("void VEthernetExchanger::Dispose()"):
            exchanger.index("template <typename TTransmission>")
        ]
        self.assertIn("boost::asio::dispatch", dispose)
        self.assertNotIn("boost::asio::post", dispose)

        switcher_header = (
            ROOT / "ppp/app/client/VEthernetNetworkSwitcherPublicMethods.inc"
        ).read_text(encoding="utf-8")
        self.assertIn("Dispose(ppp::function<void(bool)>", switcher_header)

    def test_android_start_failure_releases_before_completion(self) -> None:
        source = (ROOT / "android/libopenppp2.cpp").read_text(encoding="utf-8")
        run = source[
            source.index("Java_supersocksr_ppp_android_c_libopenppp2_run"):
            source.index("Java_supersocksr_ppp_android_c_libopenppp2_stop")
        ]
        self.assertIn("app->Release(false", run)
        self.assertNotIn("runtime_lifecycle_.CompleteStop", run)

    def test_ios_stop_uses_dispose_completion(self) -> None:
        source = (ROOT / "ios/OpenPPP2PacketTunnelBridge.cpp").read_text(
            encoding="utf-8"
        )
        stop = source[
            source.index("int openppp2_ios_tap_stop"):
            source.index("int openppp2_ios_tap_input")
        ]
        self.assertIn("client->Dispose(", stop)
        self.assertIn("cleanup_complete", stop)

    def test_server_dispose_has_completion_before_idle(self) -> None:
        header = (ROOT / "ppp/app/server/VirtualEthernetSwitcher.h").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "ppp/app/server/VirtualEthernetSwitcher.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("Dispose(ppp::function<void()>", header)
        dispose = source[
            source.index("void VirtualEthernetSwitcher::Dispose()"):
            source.index("bool VirtualEthernetSwitcher::IsDisposed")
        ]
        self.assertIn("boost::asio::dispatch", dispose)
        self.assertIn("Finalize(std::move(completion))", dispose)
        self.assertIn("(*completion_holder)()", source)
        exchanger_header = (
            ROOT / "ppp/app/server/VirtualEthernetExchanger.h"
        ).read_text(encoding="utf-8")
        connection_header = (
            ROOT / "ppp/app/server/VirtualEthernetNetworkTcpipConnection.h"
        ).read_text(encoding="utf-8")
        self.assertIn("Dispose(ppp::function<void()>", exchanger_header)
        self.assertIn("Dispose(ppp::function<void()>", connection_header)
        self.assertIn("exchanger->Dispose(child_complete)", source)
        self.assertIn("connection->Dispose(child_complete)", source)
        self.assertIn("boost::asio::post(*tap_context, child_complete)", source)

    def test_mobile_ui_coalesces_stop_per_generation(self) -> None:
        dart = (ROOT / "android/lib/pages/home_page.dart").read_text(
            encoding="utf-8"
        )
        swift = (ROOT / "ios/App/OpenPPP2/HomeViewController.swift").read_text(
            encoding="utf-8"
        )
        self.assertIn("_pendingStopGeneration", dart)
        self.assertIn("_pendingStopGeneration == generation", dart)
        self.assertIn("pendingStopGeneration", swift)
        self.assertIn("pendingStopGeneration != generation", swift)


if __name__ == "__main__":
    unittest.main()
