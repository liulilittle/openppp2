import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RuntimeUIWiringTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_client_readiness_uses_live_adapter_and_committed_route(self) -> None:
        source = self.source("ppp/app/client/VEthernetNetworkSwitcher.cpp")
        self.assertIn("tap->IsOpen()", source)
        self.assertIn("tap->IsHostedNetwork()", source)
        self.assertIn("facts.route_applied = route_snapshot.applied", source)
        self.assertIn(
            "facts.policy_negotiated = facts.session_established", source
        )
        readiness = source[
            source.index("VEthernetNetworkSwitcher::GetRuntimeReadiness") :
            source.index("void VEthernetNetworkSwitcher::RequestedIPv6")
        ]
        self.assertNotIn("GetInformation()", readiness)
        self.assertIn("BuildClientRuntimeReadiness(facts)", source)

        mobile = self.source("ppp/app/client/route/RouteCoordinator_mobile.cpp")
        self.assertIn("state_.MarkApplied(true)", mobile)

    def test_server_exposes_actual_running_state(self) -> None:
        header = self.source("ppp/app/server/VirtualEthernetSwitcher.h")
        source = self.source("ppp/app/server/VirtualEthernetSwitcher.cpp")
        self.assertIn("IsRunning()", header)
        self.assertIn("running_.store(bany", source)
        self.assertIn("running_.store(false", source)

    def test_application_server_readiness_is_not_hardcoded(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        self.assertIn("BuildServerRuntimeReadiness(server_->IsRunning())", source)
        self.assertNotIn("readiness.session = true", source)

    def test_application_explicitly_enters_applying_policy(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        established = source.index("NetworkState::NetworkState_Established")
        readiness = source.index("client->GetRuntimeReadiness()", established)
        path = source[established:readiness]
        self.assertIn("RuntimePhase::ApplyingPolicy", path)

    def test_tui_lifecycle_status_is_rendered_from_snapshot(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        self.assertIn("#include <ppp/app/tui/TuiRuntimeAdapter.h>", source)
        self.assertIn("BuildStatusLines(runtime)", source)

        on_tick = source.index("bool PppApplication::OnTick")
        statistics = source.index(
            "const bool has_transmission_statistics = GetTransmissionStatistics",
            on_tick,
        )
        status_path = source[
            statistics:source.index("ConsoleUI::GetInstance().UpdateStatus", statistics)
        ]
        self.assertNotIn("GetNetworkState()", status_path)
        self.assertNotIn("vpn_state", status_path)

    def test_android_home_does_not_subscribe_to_legacy_link_state(self) -> None:
        source = self.source("android/lib/pages/home_page.dart")
        self.assertNotIn("linkStateStream", source)
        self.assertNotIn("getLinkState()", source)
        self.assertNotIn("_linkState", source)
        self.assertIn("_pendingStartGeneration", source)
        self.assertNotIn("_connectInFlight", source)
        self.assertIn("controls.buttonEnabled && !commandPending", source)

    def test_mobile_decode_failure_does_not_retain_stale_connected_state(self) -> None:
        android = self.source("android/lib/vpn_service.dart")
        ios = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        self.assertIn("decodeRuntimeOrdering", android)
        self.assertIn("runtimeStore.applyUnknown", android)
        self.assertIn("_markRuntimeUnavailable", android)
        # An unreadable mirror ends the session instead of leaving the last
        # connected snapshot on screen.
        self.assertIn("runtimeStore.endSession()", android)
        self.assertIn("decodeOrdering", ios)
        self.assertIn("runtimeStore.applyUnknown", ios)
        self.assertIn("runtimeStore.markUnknown()", ios)
        self.assertIn("runtimeDecodeError", ios)

    def test_ios_start_waits_for_runtime_snapshot(self) -> None:
        source = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        start = source.index("@objc private func toggleConnection()")
        end = source.index("@objc private func openProfiles()", start)
        self.assertNotIn("statusCard.apply", source[start:end])
        self.assertIn("pendingStartGeneration", source[start:end])
        self.assertIn("guard pendingStartGeneration == nil", source[start:end])
        self.assertIn("runtimeStore.state.generation", source[start:end])
        self.assertIn("controls.buttonEnabled = false", source)
        self.assertIn("controls.configEditable = false", source)

    def test_android_state_is_not_derived_from_log_text(self) -> None:
        activity = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/MainActivity.kt"
        )
        # The old getState scanned the log with lastIndexOf("failed") and friends,
        # so any benign log line containing "failed" reported a disconnect.
        self.assertNotIn("lastIndexOf", activity)
        self.assertNotIn("vpnThread started", activity)
        self.assertNotIn('"getState"', activity)
        self.assertIn("getRuntimeSnapshotIfAlive", activity)
        # Statics of a service running in `:vpn` are always zero here, and the
        # EventChannel sink it wrote to never existed in that process.
        self.assertNotIn("PppVpnService.isRunning", activity)
        self.assertNotIn("PppVpnService.currentState", activity)
        self.assertNotIn("EventChannel", activity)

        home = self.source("android/lib/pages/home_page.dart")
        self.assertNotIn("vpnThread started", home)

        settings = self.source("android/lib/pages/settings_page.dart")
        self.assertNotIn("VpnState", settings)
        self.assertIn("controlsFor(_runtimeStore.state.phase)", settings)

    def test_android_ui_reads_only_the_runtime_snapshot(self) -> None:
        dart = self.source("android/lib/vpn_service.dart")
        # The legacy four-value state, the key-guessing statistics parser, and
        # the cross-process EventChannel are all gone.
        self.assertNotIn("enum VpnState", dart)
        self.assertNotIn("VpnStatistics", dart)
        self.assertNotIn("EventChannel", dart)
        self.assertNotIn("outgoingTraffic", dart)
        self.assertIn("RuntimeTrafficRate", dart)

        home = self.source("android/lib/pages/home_page.dart")
        self.assertNotIn("VpnState", home)
        self.assertNotIn("VpnStatistics", home)
        self.assertNotIn("_connectedAt", home)
        self.assertIn("connectedElapsedMs(_runtimeStore.state)", home)
        self.assertIn("_vpnService.traffic.txBytesPerSecond", home)

        service = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppVpnService.kt"
        )
        self.assertNotIn("MainActivity.sendEvent", service)

    def test_android_service_mirrors_runtime_state_across_processes(self) -> None:
        service = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppVpnService.kt"
        )
        # MainActivity.sendEvent touches a process-local sink, so every event
        # published from `:vpn` needs a file mirror to reach the UI process.
        self.assertIn("PppStateStore.setRuntimeSnapshot(this, value)", service)
        self.assertIn("PppStateStore.setLastError(this, message)", service)
        self.assertIn("updateNotificationForSnapshot(value)", service)
        self.assertNotIn('updateNotification("已连接")', service)

        store = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppStateStore.kt"
        )
        self.assertIn("createTempFile", store)
        self.assertIn("renameTo", store)
        self.assertNotIn("writeText(value.toString())", store)

        dart = self.source("android/lib/vpn_service.dart")
        self.assertIn("applyRuntimeSnapshotPoll", dart)
        self.assertIn("runtimeStore.beginSession()", dart)
        self.assertIn("runtimeStore.endSession()", dart)
        self.assertIn("getRuntimeSnapshot", dart)
        self.assertIn("getLastError", dart)

        store_dart = self.source("android/lib/runtime/runtime_store.dart")
        self.assertIn("resetForNewSession", store_dart)

    def test_ios_reads_traffic_and_connect_time_from_the_snapshot(self) -> None:
        home = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        self.assertNotIn("VpnStatistics", home)
        self.assertNotIn("connectedAt =", home)
        self.assertIn("connectedElapsedMs(runtimeStore.state)", home)
        self.assertIn("RuntimeTrafficRate.between", home)

        models = self.source("ios/App/OpenPPP2/AppModels.swift")
        self.assertNotIn("VpnStatistics", models)
        self.assertNotIn("outgoingTraffic", models)

        controller = self.source("ios/App/OpenPPP2/VPNController.swift")
        self.assertNotIn("fetchStatistics", controller)

        # The traffic C ABI and its provider message are gone; diagnostics
        # carry the runtime snapshot, which already holds the totals.
        for relative in (
            "ios/OpenPPP2PacketTunnelBridge.h",
            "ios/OpenPPP2PacketTunnelBridge.cpp",
            "ios/App/OpenPPP2PacketTunnel/OpenPPP2PacketTunnelAdapter.swift",
            "ios/App/OpenPPP2PacketTunnel/PacketTunnelProvider.swift",
            "ios/App/OpenPPP2PacketTunnel/PacketFlowDiagnostics.swift",
        ):
            source = self.source(relative)
            self.assertNotIn("openppp2_ios_tap_get_statistics", source)
            self.assertNotIn("statistics_writer", source)
            self.assertNotIn("statisticsJson", source)
        self.assertIn(
            "runtimeSnapshotJson",
            self.source("ios/App/OpenPPP2PacketTunnel/PacketFlowDiagnostics.swift"),
        )

        self.assertTrue(
            (ROOT / "ios/App/OpenPPP2/Runtime/RuntimeTrafficRate.swift").is_file()
        )
        self.assertIn(
            "Runtime/RuntimeTrafficRate.swift",
            self.source("ios/App/Package.swift"),
        )

        # Both platforms must reject the same degenerate inputs.
        for relative in (
            "ios/App/OpenPPP2/Runtime/RuntimeTrafficRate.swift",
            "android/lib/runtime/runtime_traffic_rate.dart",
        ):
            source = self.source(relative)
            self.assertIn("generation", source)
            self.assertIn("moved backwards", source)

    def test_android_native_pushes_runtime_snapshots(self) -> None:
        native = self.source("android/libopenppp2.cpp")
        self.assertIn("runtime_lifecycle_.Subscribe(", native)
        self.assertIn('GetStaticMethodID(clazz, "runtime_snapshot"', native)
        # FindClass on an attached native thread cannot see application
        # classes, so the class is resolved while JNI_OnLoad still holds the
        # loader, and every publish attaches its own thread.
        self.assertIn("libopenppp2_cache_runtime_snapshot_method(vm, env)", native)
        self.assertIn("AttachCurrentThread", native)
        self.assertIn("NewGlobalRef", native)

        publish = native[
            native.index("static void") :
            native.index("JNIEXPORT jint JNICALL JNI_OnLoad")
        ]
        # PostJNI drops work once client_ is null, which is exactly the window
        # the terminal Idle/Failed snapshot is published in.
        self.assertNotIn("PostJNI", publish)

        bridge = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/c/libopenppp2.kt"
        )
        self.assertIn("fun runtime_snapshot(json: String)", bridge)
        # Traffic rides the snapshot now, so the separate statistics payload
        # and its JNI callback are gone from every layer.
        self.assertNotIn("fun statistics(", bridge)
        self.assertNotIn("StatisticsJNI", native)
        self.assertNotIn(
            "getStatistics",
            self.source(
                "android/android/app/src/main/kotlin/supersocksr/ppp/android/MainActivity.kt"
            ),
        )
        self.assertNotIn(
            "setStatistics",
            self.source(
                "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppStateStore.kt"
            ),
        )

        service = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppVpnService.kt"
        )
        # Pushes carry no cross-thread ordering guarantee.
        self.assertIn("fun onRuntimeSnapshot(json: String)", service)
        self.assertIn("lastSnapshotGeneration", service)
        self.assertIn("lastSnapshotMonotonicMs", service)

        dart = self.source("android/lib/vpn_service.dart")
        self.assertIn("didChangeAppLifecycleState", dart)

    def test_runtime_contract_docs_are_governed_and_indexed(self) -> None:
        paths = (
            "docs/adr/0001-runtime-ui-contract.md",
            "docs/reference/UI_RUNTIME_CONTRACT.md",
            "docs/reference/UI_RUNTIME_CONTRACT_CN.md",
        )
        for relative in paths:
            self.assertTrue((ROOT / relative).is_file(), relative)

        index = self.source("docs/README.md")
        self.assertIn("reference/UI_RUNTIME_CONTRACT.md", index)
        self.assertIn("reference/UI_RUNTIME_CONTRACT_CN.md", index)

    def test_vmux_ui_uses_snapshot_capabilities_and_next_connection_config(self) -> None:
        android_model = self.source("android/lib/runtime/runtime_snapshot.dart")
        android_view = self.source("android/lib/pages/options_advanced_page.dart")
        android_selector = self.source("android/lib/widgets/vmux_mode_selector.dart")
        android_config = self.source("android/lib/services/profile_store.dart")
        ios_model = self.source("ios/App/OpenPPP2/Runtime/RuntimeSnapshot.swift")
        ios_view = self.source("ios/App/OpenPPP2/OptionsViewController.swift")
        ios_config = self.source("ios/App/OpenPPP2/ProfileStore.swift")

        for source in (android_model, ios_model):
            self.assertIn("capabilities", source)
            self.assertIn("stripe", source)
            self.assertIn("Compatibility mode", source)
        self.assertIn("capabilities.contains('mux.$mode')", android_model)
        self.assertIn('capabilities.contains("mux.\\($0)")', ios_model)

        self.assertIn("Takes effect on next connection", android_view)
        self.assertIn("Takes effect on next connection", ios_view)
        self.assertIn("VmuxModeSelector", android_view)
        self.assertIn("availableMuxModes", android_selector)
        self.assertIn("availableMuxModes", ios_view)
        self.assertIn("muxMode", android_config)
        self.assertIn('mux["mode"]', ios_config)
        self.assertNotIn("setMuxMode", android_view)
        self.assertNotIn("setMuxMode", ios_view)

    def test_mobile_native_runtime_publishes_vmux_state(self) -> None:
        for relative in ("android/libopenppp2.cpp", "ios/OpenPPP2PacketTunnelBridge.cpp"):
            source = self.source(relative)
            self.assertIn('"mux.compat", "mux.flow", "mux.balance", "mux.stripe"', source)
            self.assertIn("GetMuxRuntimeState()", source)
            self.assertIn("UpdateMuxState(", source)
        ios = self.source("ios/OpenPPP2PacketTunnelBridge.cpp")
        missing_exchanger = ios[ios.index("if (exchanger == nullptr)"):ios.index("UpdateMuxState(")]
        self.assertIn("return;", missing_exchanger)

    def test_vmux_selector_and_home_are_wired_for_normal_ui(self) -> None:
        selector = self.source("android/lib/widgets/vmux_mode_selector.dart")
        android_home = self.source("android/lib/pages/home_page.dart")
        android_model = self.source("android/lib/runtime/runtime_snapshot.dart")
        android_store = self.source("android/lib/runtime/runtime_store.dart")
        ios_home = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        ios_model = self.source("ios/App/OpenPPP2/Runtime/RuntimeSnapshot.swift")
        ios_store = self.source("ios/App/OpenPPP2/Runtime/RuntimeStore.swift")

        self.assertIn("availableMuxModes", selector)
        self.assertIn("Takes effect on next connection", selector)
        self.assertIn("effectiveMuxDisplayName", selector)
        self.assertIn("effectiveMuxDisplayName", android_home)
        self.assertIn("effectiveMuxDisplayName", ios_home)
        self.assertIn("bundledCapabilities", self.source("ios/App/OpenPPP2/OptionsViewController.swift"))
        self.assertIn("bundledCapabilities", android_store)
        self.assertIn("bundledCapabilities", ios_store)
        self.assertIn("json.containsKey('capabilities')", android_model)
        self.assertIn("container.contains(.capabilities)", ios_model)

        swift_test = ROOT / "ios/App/Tests/OpenPPP2LogicTests/VMuxPresentationTests.swift"
        self.assertTrue(swift_test.is_file())
        self.assertIn("import OpenPPP2Logic", swift_test.read_text(encoding="utf-8"))
        self.assertFalse((ROOT / "ios/App/OpenPPP2Tests").exists())


if __name__ == "__main__":
    unittest.main()
