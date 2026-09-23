import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class P2PCapabilityWiringTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_manual_validation_tracks_gate_and_device_evidence(self) -> None:
        manual = self.source("docs/archive/status/P2P_MANUAL_VALIDATION.md")
        plan = self.source("docs/archive/plans/P2P_NETWORKING_PLAN.md")

        self.assertIn("ProductionAuthenticatedControlV1Ready = false", manual)
        self.assertIn("29526592987", manual)
        self.assertIn("physical device", manual)
        self.assertNotIn("Since there is no automated test harness", manual)
        self.assertIn("ProductionAuthenticatedControlV1Ready = false", plan)
        self.assertIn("29526592987", plan)

    def test_client_register_is_guarded_by_authenticated_capabilities(self) -> None:
        source = self.source("ppp/app/client/VEthernetExchanger.cpp")
        register = source[source.index("const auto p2p_capability") :]
        self.assertIn("P2PCapabilityGate::Evaluate", register)
        self.assertIn("transmission->HasAuthenticatedSessionExporter()", register)
        self.assertIn("protector->IsReady()", register)
        self.assertIn("ProductionAuthenticatedControlV1Ready", register)
        self.assertIn("if (p2p_capability.allowed)", register)

    def test_client_capability_state_reaches_the_runtime_snapshot(self) -> None:
        header = self.source("ppp/app/client/VEthernetExchanger.h")
        exchanger = self.source("ppp/app/client/VEthernetExchanger.cpp")
        main_loop = self.source("ppp/app/ApplicationMainLoop.cpp")

        self.assertIn("GetRuntimeState()", header)
        self.assertIn("runtime_state_mutex_", header)
        self.assertIn("std::atomic<ppp::p2p::P2PState>", header)
        capability_store = exchanger[
            exchanger.index("const auto p2p_capability") :
            exchanger.index("if (p2p_capability.allowed)")
        ]
        self.assertIn("runtime_state_mutex_", capability_store)
        self.assertIn("disposed_.load", capability_store)
        self.assertIn("p2p_state_.store(p2p_capability.state", capability_store)
        self.assertIn(
            "runtime_lifecycle_.UpdateP2PState(", main_loop
        )
        p2p_update = main_loop[main_loop.index("runtime_lifecycle_.UpdateP2PState(") :]
        self.assertIn("exchanger_runtime.p2p_state", p2p_update)
        self.assertIn("exchanger_runtime.network_state", p2p_update)
        reconnect = exchanger[
            exchanger.index("void VEthernetExchanger::ExchangeToConnectingState") :
            exchanger.index("bool VEthernetExchanger::RegisterAllMappingPorts")
        ]
        self.assertGreaterEqual(
            reconnect.count("p2p_state_.store(configured_p2p_state_"), 2
        )

    def test_client_authenticated_offer_stays_relay_until_control_ack(self) -> None:
        header = self.source("ppp/app/client/VEthernetExchanger.h")
        exchanger = self.source("ppp/app/client/VEthernetExchanger.cpp")

        self.assertIn("<ppp/p2p/P2PClientOfferSession.h>", header)
        self.assertIn("P2PClientOfferSession", header)
        self.assertIn("<ppp/p2p/P2PDirectDataPath.h>", header)
        self.assertIn("P2PDirectDataPath", header)
        self.assertNotIn("std::optional<ppp::p2p::P2PAuthenticatedProbeAck>", header)
        self.assertIn("p2p_registered_candidates_", header)
        self.assertIn("p2p_offer_generation_", header)
        self.assertIn("p2p_transport_registration_id_", header)
        self.assertIn("p2p_peer_candidate_", header)
        self.assertIn("p2p_peer_virtual_ip_", header)

        register = exchanger[
            exchanger.index("const auto p2p_capability") :
            exchanger.index("if (!configuration->client.peer_route_announce.empty())")
        ]
        for required in (
            "CreateNativeSocketP2PDatagramTransportFactory",
            "GetUnderlyingNetworkInterface",
            "candidate_transport->Start",
            "HandleP2PDatagram",
            "candidate_transport->LocalEndpoint()",
            "request.P2P.candidates = gathered",
            "StartP2PStunGatherAsync",
            "p2p_zero_rtt_cache_.Lookup",
            "p2p_candidate_transport_",
        ):
            self.assertIn(required, register)
        self.assertNotIn("P2PStunClient::Query", register)
        self.assertIn("P2PStunClient::Query", exchanger)
        self.assertIn("std::thread(", exchanger)
        self.assertIn("ApplyP2PStunMappedCandidate", exchanger)
        self.assertIn("p2p_registered_candidates_ = request.P2P.candidates", register)
        self.assertIn("p2p_direct_data_path_.Reset(candidate_generation)", register)

        handler = exchanger[
            exchanger.index("void VEthernetExchanger::HandleP2PRelayOffer") :
            exchanger.index("bool VEthernetExchanger::OnInformation(",
                            exchanger.index("void VEthernetExchanger::HandleP2PRelayOffer"))
        ]
        for required in (
            'action != "offer-v1"',
            "ppp::app::P2PCandidateFromEndpoint",
            "HashP2PCandidateSet",
            "Executors::Post(context, strand",
            "ExportAuthenticatedSessionKey",
            "p2p_offer_session_.Accept",
            "P2PState::Eligible",
        ):
            self.assertIn(required, handler)
        self.assertNotIn("StartProbing", handler)
        self.assertIn("CreateAuthenticatedProbeDatagram", handler)
        self.assertIn("candidate_transport->SendTo", handler)

        datagram_handler = exchanger[
            exchanger.index("void VEthernetExchanger::HandleP2PDatagram") :
            exchanger.index("void VEthernetExchanger::HandleP2PRelayOffer")
        ]
        for required in (
            "Executors::Post(context, strand",
            "HandleAuthenticatedControlDatagram",
            "P2PControlDatagramAction::Reply",
            "transport->SendTo",
            "p2p_direct_data_path_.StageAuthenticatedAck",
            "p2p_direct_data_path_.Activate(transport->IsReady()",
            "P2PDataPacketHeader::HeaderSize",
            "sender != p2p_peer_candidate_",
            "p2p_direct_data_path_.Open",
            "AllowsInboundPacket",
            "p2p_peer_virtual_ip_",
            "OnNat(transmission",
            "p2p_offer_generation_",
            "p2p_transport_registration_id_",
        ):
            self.assertIn(required, datagram_handler)
        self.assertNotIn("StartProbing", datagram_handler)
        self.assertNotIn("Activate(true", datagram_handler)
        transport_error = datagram_handler[
            datagram_handler.index("P2PDatagramReceiveStatus::Error") :
            datagram_handler.index("P2PDatagramReceiveStatus::Packet")
        ]
        self.assertIn("p2p_transport_registration_id_", transport_error)
        self.assertIn("p2p_offer_session_.ResetGeneration", transport_error)
        self.assertIn("p2p_direct_data_path_.Fallback", transport_error)
        self.assertIn("P2PFallbackReason::SocketError", transport_error)
        self.assertIn("p2p_state_.store(ppp::p2p::P2PState::Relay", transport_error)
        self.assertIn("transport->Close()", transport_error)

        probe_failure = handler[handler.index("const bool sent =") :]
        self.assertIn("p2p_direct_data_path_.Begin(generation)", probe_failure)
        self.assertIn("p2p_peer_candidate_ = peer_candidate", probe_failure)
        self.assertIn("p2p_peer_virtual_ip_ = message.peer_virtual_ip", probe_failure)
        self.assertIn("p2p_state_.store(ppp::p2p::P2PState::Relay", probe_failure)
        self.assertNotIn("Activate(true", handler)

        accepted_offer = handler[
            handler.index("if (!p2p_offer_session_.Accept(") :
            handler.index('Count("p2p.offer_v1.accepted"')
        ]
        self.assertIn("p2p_peer_candidate_ = {}", accepted_offer)
        self.assertIn("p2p_peer_virtual_ip_ = 0", accepted_offer)
        self.assertIn("p2p_direct_data_path_.Reset(generation)", accepted_offer)

        update = exchanger[
            exchanger.index("bool VEthernetExchanger::Update()") :
            exchanger.index("bool VEthernetExchanger::DoKeepAlived")
        ]
        self.assertIn("P2PFallbackReason::Timeout", update)
        self.assertIn("p2p_direct_data_path_.Fallback", update)
        self.assertIn("expired_transport->Close()", update)

        reconnect = exchanger[
            exchanger.index("void VEthernetExchanger::Finalize") :
            exchanger.index("bool VEthernetExchanger::RegisterAllMappingPorts")
        ]
        self.assertGreaterEqual(reconnect.count("p2p_offer_session_.AdvanceGeneration"), 3)
        self.assertGreaterEqual(reconnect.count("++p2p_offer_generation_"), 3)

    def test_offer_v1_data_codec_is_session_owned_and_not_production_enabled(self) -> None:
        session_header = self.source("ppp/p2p/P2PClientOfferSession.h")
        session_source = self.source("ppp/p2p/P2PClientOfferSession.cpp")
        codec = self.source("ppp/p2p/P2PDataDatagram.cpp")
        exchanger = self.source("ppp/app/client/VEthernetExchanger.cpp")
        capability = self.source("ppp/p2p/P2PCapabilityGate.h")

        for required in ("SealData(", "OpenData(", "data_authorized_"):
            self.assertIn(required, session_header)
        for required in (
            "SelectP2PV1Direction",
            "next_tx_sequence_",
            "rx_replay_window_",
            "BuildP2PV1Nonce",
        ):
            self.assertIn(required, session_source)
        self.assertIn("EVP_chacha20_poly1305()", codec)
        self.assertIn("P2PDataPacketHeader::HeaderSize", codec)
        self.assertIn("p2p_direct_data_path_.Send", exchanger)
        self.assertIn("p2p_direct_data_path_.Open", exchanger)
        self.assertNotIn("Activate(true", exchanger)
        self.assertIn("ProductionAuthenticatedControlV1Ready = false", capability)

        nat = exchanger[
            exchanger.index("bool VEthernetExchanger::Nat(") :
            exchanger.index("int VEthernetExchanger::EchoLanToRemoteExchanger")
        ]
        self.assertLess(
            nat.index("p2p_direct_data_path_.Send"), nat.index("DoNat(")
        )
        self.assertIn("P2PFallbackReason::SocketError", nat)
        self.assertIn("AllowsOutboundPacket", nat)
        self.assertIn("p2p_peer_virtual_ip_", nat)

    def test_server_registration_and_offers_are_guarded(self) -> None:
        header = self.source("ppp/app/server/VirtualEthernetSwitcher.h")
        capability = self.source("ppp/p2p/P2PCapabilityGate.h")
        source = self.source("ppp/app/server/VirtualEthernetSwitcher.cpp")
        registration = source[
            source.index("bool VirtualEthernetSwitcher::UpdateP2PPeer") :
            source.index("bool VirtualEthernetSwitcher::DeleteP2PPeer")
        ]
        offers = source[
            source.index("bool VirtualEthernetSwitcher::OfferP2PPeerHints") :
            source.index("bool VirtualEthernetSwitcher::DeleteNatInformation", source.index("bool VirtualEthernetSwitcher::OfferP2PPeerHints"))
        ]
        self.assertIn("P2PCapabilityGate::Evaluate", registration)
        self.assertIn("HasAuthenticatedSessionExporter()", registration)
        self.assertIn("response.P2P.enabled = p2p_capability.allowed", registration)
        self.assertNotIn("CreateSocketProtector", registration)
        self.assertIn("P2PCapabilityGate::Evaluate", offers)
        self.assertGreaterEqual(offers.count("HasAuthenticatedSessionExporter()"), 2)
        self.assertNotIn("CreateSocketProtector", offers)
        self.assertGreaterEqual(
            offers.count("ProductionAuthenticatedControlV1Ready"), 2
        )
        self.assertIn("HashP2PCandidateSet", offers)
        self.assertIn("CreateP2PRelayOfferBundleAsync", offers)
        self.assertGreaterEqual(offers.count("ScheduleP2PSessionExporter"), 2)
        self.assertGreaterEqual(offers.count("ExportAuthenticatedSessionKey"), 2)
        self.assertGreaterEqual(offers.count('action = "offer-v1"'), 2)
        self.assertGreaterEqual(offers.count("authenticated_offer_v1"), 2)
        self.assertIn("YieldContext::Spawn", offers)
        self.assertNotIn("P2PNewToken", offers)
        self.assertNotIn("source_offer.token", offers)
        self.assertNotIn("destination_offer.token", offers)
        self.assertIn("LastOfferGeneration", header)
        self.assertIn("p2p_offer_generation_", header)
        self.assertIn("LastOfferGeneration == offer_generation", offers)
        self.assertNotIn("LastOfferAt == now", offers)
        self.assertIn("ProductionAuthenticatedControlV1Ready = false", capability)

    def test_server_uses_authenticated_static_echo_udp_observations(self) -> None:
        header = self.source("ppp/app/server/VirtualEthernetSwitcher.h")
        source = self.source("ppp/app/server/VirtualEthernetSwitcher.cpp")
        registration = source[
            source.index("bool VirtualEthernetSwitcher::UpdateP2PPeer") :
            source.index("bool VirtualEthernetSwitcher::DeleteP2PPeer")
        ]
        static_echo = source[
            source.index("bool VirtualEthernetSwitcher::StaticEchoPacketInput") :
            source.index("VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContextPtr")
        ]
        candidates = source[
            source.index("static ppp::vector<ppp::app::protocol::P2PEndpointCandidate> P2PBuildCandidates") :
            source.index("static bool P2PAppendCanonicalCandidates")
        ]

        self.assertIn("ObserveP2PUdpEndpoint", header)
        self.assertIn("ObserveP2PUdpEndpoint(exchanger, packet->SourceIP, sourceEP)", static_echo)
        self.assertIn("P2PAppendObservedEndpointCandidate", candidates)
        self.assertNotIn("transmission->GetRemoteEndPoint()", registration)

    def test_channel_protects_before_receive_and_probe(self) -> None:
        channel = self.source("ppp/p2p/P2PChannel.cpp")
        transport = self.source("ppp/p2p/P2PDatagramTransport.cpp")
        start = transport[
            transport.index("bool Start(const P2PDatagramReceiveCallback") :
            transport.index("boost::asio::ip::udp::endpoint LocalEndpoint")
        ]
        protection = start.index("ProtectP2PSocket")
        self.assertLess(protection, start.index("StartReceive()"))
        probing = channel[
            channel.index("void P2PChannel::StartProbing") :
            channel.index("bool P2PChannel::SendProbe")
        ]
        self.assertLess(probing.index("transport_->Start("), probing.index("SendProbe("))
        self.assertNotIn("boost::asio::ip::udp::socket", channel)

    def test_channel_forwards_data_only_while_direct(self) -> None:
        source = self.source("ppp/p2p/P2PChannel.cpp")
        receive = source[
            source.index("void P2PChannel::HandleTier2") :
            source.index("bool P2PChannel::SendFrame")
        ]
        receive_gate = receive[: receive.index("if (sender != peer_endpoint_)")]
        self.assertIn("CanProcessAuthenticatedP2PTier2(current_state)", receive_gate)

        payload_gate = receive[
            receive.index("if (IsHeartbeatAck(header.flags))") :
            receive.index("if (IsCoalesced(header.flags))")
        ]
        self.assertIn("if (!CanForwardP2PPayload(current_state))", payload_gate)

        send = source[
            source.index("bool P2PChannel::SendFrame") :
            source.index("void P2PChannel::OnHeartbeatTimer")
        ]
        self.assertGreaterEqual(
            send.count("state_.load(std::memory_order_acquire) != P2PChannelState::Direct"),
            2,
        )

    def test_channel_errors_use_one_fallback_cleanup_path(self) -> None:
        header = self.source("ppp/p2p/P2PChannel.h")
        source = self.source("ppp/p2p/P2PChannel.cpp")
        self.assertIn("void FallbackToRelay(P2PFallbackReason reason)", header)
        self.assertIn("void ResetAttemptState()", header)
        self.assertIn("bool SendProbe(const boost::asio::ip::udp::endpoint& ep)", header)

        cleanup = source[
            source.index("void P2PChannel::ResetAttemptState") :
            source.index("bool P2PChannel::BuildTier1TokenInput")
        ]
        for required in (
            "OPENSSL_cleanse(base_session_key_",
            "OPENSSL_cleanse(tx_session_key_",
            "OPENSSL_cleanse(rx_session_key_",
            "OPENSSL_cleanse(token_key_",
            "offer_token_.clear()",
            "replay_window_.Reset()",
            "candidates_.clear()",
            "transport_.reset()",
        ):
            self.assertIn(required, cleanup)

        probe_timeout = source[
            source.index("void P2PChannel::OnProbeTimeout") :
            source.index("void P2PChannel::OnProbeAck")
        ]
        suspect_timeout = source[
            source.index("void P2PChannel::OnSuspectTimeout") :
            source.index("uint64_t P2PChannel::NextChannelNonce")
        ]
        self.assertIn("FallbackToRelay(P2PFallbackReason::Timeout)", probe_timeout)
        self.assertIn("FallbackToRelay(P2PFallbackReason::Timeout)", suspect_timeout)

        probing = source[
            source.index("void P2PChannel::StartProbing") :
            source.index("void P2PChannel::SendProbe")
        ]
        after_initial_probes = probing[
            probing.index("for (const auto& cand : candidates)") :
            probing.index("probe_timer_ =")
        ]
        self.assertIn("closed_.load(std::memory_order_acquire)", after_initial_probes)
        self.assertIn("if (!SendProbe(cand.endpoint)) return", after_initial_probes)

        retry_probes = probe_timeout[
            probe_timeout.index("for (const auto& cand : candidates_)") :
            probe_timeout.index("if (probe_timer_)")
        ]
        self.assertIn("closed_.load(std::memory_order_acquire)", retry_probes)
        self.assertIn("if (!SendProbe(cand.endpoint)) return", retry_probes)

        probing_receive = probing[
            probing.index("transport_->Start(") : probing.index("TransitionTo(")
        ]
        self.assertIn(
            "FallbackToRelay(P2PFallbackReason::SocketError)", probing_receive
        )

        tier1 = source[
            source.index("void P2PChannel::HandleTier1") :
            source.index("void P2PChannel::HandleTier2")
        ]
        invalid_token = tier1[
            tier1.index("if (!VerifyTier1Token(header))") :
            tier1.index("P2PChannelState current_state")
        ]
        self.assertNotIn("FallbackToRelay", invalid_token)

        encrypt = source[
            source.index("bool P2PChannel::EncryptAndSendTier2") :
            source.index("void P2PChannel::OnHeartbeatTimer")
        ]
        missing_transport = encrypt[: encrypt.index("bool is_heartbeat")]
        self.assertIn(
            "FallbackToRelay(P2PFallbackReason::SocketError)", missing_transport
        )

        send_probe = source[
            source.index("bool P2PChannel::SendProbe(") :
            source.index("void P2PChannel::SendProbeAck(")
        ]
        send_ack = source[
            source.index("void P2PChannel::SendProbeAck(") :
            source.index("bool P2PChannel::VerifyTier1Token")
        ]
        for control_send in (send_probe, send_ack):
            self.assertIn("if (!TokenGenerate", control_send)
            self.assertGreaterEqual(
                control_send.count(
                    "FallbackToRelay(P2PFallbackReason::AuthenticationFailure)"
                ),
                3,
            )

        verify_token = source[
            source.index("bool P2PChannel::VerifyTier1Token") :
            source.index("void P2PChannel::OnProbeTimeout")
        ]
        self.assertIn("OPENSSL_cleanse(token_input, sizeof(token_input))", verify_token)

    def test_android_protector_reuses_the_vpn_service_bridge(self) -> None:
        bridge_header = self.source("android/OpenPPP2VpnProtectBridge.h")
        bridge_source = self.source("android/OpenPPP2VpnProtectBridge.cpp")
        kotlin = self.source(
            "android/android/app/src/main/kotlin/"
            "supersocksr/ppp/android/c/libopenppp2.kt"
        )
        protector_header = self.source("ppp/p2p/P2PSocketProtector.h")
        protector_source = self.source("ppp/p2p/P2PSocketProtector.cpp")

        self.assertIn("IsProtectBridgeReady()", bridge_header)
        self.assertIn('GetStaticMethodID(local_clazz, "isProtectReady", "()Z")', bridge_source)
        self.assertIn("fun isProtectReady(): Boolean", kotlin)
        self.assertIn("PppVpnService.instance != null", kotlin)
        service = self.source(
            "android/android/app/src/main/kotlin/"
            "supersocksr/ppp/android/PppVpnService.kt"
        )
        self.assertIn("@Volatile\n        var instance: PppVpnService?", service)
        self.assertIn("bool IsReady() const noexcept override", protector_header)
        self.assertNotIn("void Initialize(void* env, void* vpn_service)", protector_header)
        self.assertIn("<android/OpenPPP2VpnProtectBridge.h>", protector_source)
        self.assertIn("ppp::android::IsProtectBridgeReady()", protector_source)
        self.assertIn("ppp::android::ProtectSocketFd(fd)", protector_source)
        protect_call = bridge_source[bridge_source.index("bool ProtectSocketFd(int fd)") :]
        self.assertIn("NewLocalRef(state.clazz)", protect_call)
        self.assertIn("DeleteLocalRef(clazz)", protect_call)

    def test_android_app_exposes_native_protection_smoke_entrypoints(self) -> None:
        kotlin = self.source(
            "android/android/app/src/main/kotlin/"
            "supersocksr/ppp/android/c/libopenppp2.kt"
        )
        self.assertIn(
            "external fun set_protect_enabled(enabled: Boolean): Boolean", kotlin
        )
        self.assertIn("external fun protect_socket_fd(fd: Int): Boolean", kotlin)

    def test_android_debug_variant_runs_vpn_protect_instrumentation(self) -> None:
        gradle = self.source("android/android/app/build.gradle")
        debug_manifest = self.source(
            "android/android/app/src/debug/AndroidManifest.xml"
        )
        instrumentation = self.source(
            "android/android/app/src/androidTest/kotlin/supersocksr/ppp/android/"
            "P2PSocketProtectionTest.kt"
        )
        workflow = self.source(".github/workflows/build-android.yml")

        self.assertIn(
            'testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"',
            gradle,
        )
        self.assertIn(
            'androidTestImplementation "androidx.test.ext:junit:1.2.1"', gradle
        )
        self.assertIn(
            'androidTestImplementation "androidx.test:runner:1.6.2"', gradle
        )
        self.assertIn('debug {\n            ndk {\n                abiFilters "x86_64"', gradle)
        self.assertIn('release {\n            ndk {\n                abiFilters "arm64-v8a"', gradle)
        self.assertNotIn('"lib/x86_64/**"', gradle)
        self.assertIn('tools:remove="android:process"', debug_manifest)
        self.assertIn("DatagramSocket()", instrumentation)
        self.assertIn("@RunWith(AndroidJUnit4::class)", instrumentation)
        self.assertIn("ACTIVATE_VPN allow", instrumentation)
        self.assertIn("VpnService.prepare(context) == null", instrumentation)
        self.assertIn("serviceInstance.Builder()", instrumentation)
        self.assertIn(".establish()", instrumentation)
        self.assertIn("ParcelFileDescriptor.fromDatagramSocket(socket)", instrumentation)
        self.assertIn("assertFalse(libopenppp2.protect_socket_fd(fd))", instrumentation)
        self.assertIn("assertTrue(libopenppp2.protect_socket_fd(fd))", instrumentation)
        self.assertIn("assertFalse(libopenppp2.isProtectReady())", instrumentation)
        self.assertIn("device-test:", workflow)
        self.assertIn("openppp2-android-x86_64.zip", workflow)
        self.assertIn("reactivecircus/android-emulator-runner@v2", workflow)
        self.assertIn("api-level: 34", workflow)
        self.assertIn("arch: x86_64", workflow)
        self.assertIn("gradle/actions/setup-gradle@v4", workflow)
        self.assertIn("gradle-version: '8.14'", workflow)
        self.assertIn("gradle :app:connectedDebugAndroidTest", workflow)
        self.assertNotIn("flutter build apk --debug", workflow)
        self.assertIn("timeout 15s adb logcat -d", workflow)

    def test_ios_uses_provider_owned_udp_transport(self) -> None:
        header = self.source("ios/OpenPPP2PacketTunnelBridge.h")
        bridge = self.source("ios/OpenPPP2PacketTunnelBridge.cpp")
        adapter = self.source(
            "ios/App/OpenPPP2PacketTunnel/OpenPPP2PacketTunnelAdapter.swift"
        )
        provider_transport = self.source(
            "ios/App/OpenPPP2PacketTunnel/ProviderOwnedP2PDatagramTransport.swift"
        )
        native_transport = self.source("ppp/p2p/P2PDatagramTransport.cpp")
        exchanger = self.source("ppp/app/client/VEthernetExchanger.cpp")
        tap_header = self.source("ios/ppp/tap/TapIos.h")

        self.assertIn("openppp2_ios_tap_set_p2p_datagram_provider", header)
        self.assertIn("CreateIosProviderP2PDatagramTransportFactory", bridge)
        self.assertIn("install(on: createdTap)", adapter)
        self.assertIn("uninstall(from: tap)", adapter)
        self.assertLess(
            adapter.index("install(on: createdTap)"),
            adapter.index("startNativeTap(createdTap"),
        )
        self.assertLess(
            adapter.index("uninstall(from: tap)"),
            adapter.index("openppp2_ios_tap_destroy(tap)"),
        )
        self.assertIn("createUDPSession", provider_transport)
        self.assertIn("setReadHandler", provider_transport)
        self.assertIn("writeDatagram", provider_transport)
        self.assertIn("SetP2PDatagramTransportFactory", bridge)
        self.assertIn("GetP2PDatagramTransportFactory", tap_header)
        iphone_candidate = exchanger[
            exchanger.index("#if defined(_IPHONE)", exchanger.index("candidate_generation")) :
            exchanger.index("#else", exchanger.index("candidate_generation"))
        ]
        self.assertIn("dynamic_pointer_cast<ppp::tap::TapIos>", iphone_candidate)
        self.assertIn("GetP2PDatagramTransportFactory()", iphone_candidate)
        self.assertNotIn("CreateNativeSocketP2PDatagramTransportFactory", iphone_candidate)
        android_candidate = exchanger[
            exchanger.index("#elif defined(_ANDROID)", exchanger.index("candidate_generation")) :
            exchanger.index("#else", exchanger.index("#elif defined(_ANDROID)", exchanger.index("candidate_generation")))
        ]
        self.assertIn("Socket::GetBestInterfaceIP", android_candidate)
        self.assertNotIn("GetUnderlyingNetworkInterface", android_candidate)
        iphone_factory = native_transport[native_transport.index("#if defined(_IPHONE)") :]
        self.assertIn("return nullptr", iphone_factory)

        workflow = self.source(".github/workflows/test.yml")
        self.assertIn("Typecheck PacketTunnel P2P provider transport", workflow)
        self.assertIn("ProviderOwnedP2PDatagramTransport.swift", workflow)
        self.assertIn("swiftc -typecheck", workflow)

    def test_authenticated_exporter_is_carrier_bound_and_disposal_safe(self) -> None:
        exporter_header = self.source("ppp/ssl/TlsSessionExporter.h")
        binding_header = self.source(
            "ppp/transmissions/IAuthenticatedCarrierBinding.h"
        )
        base_header = self.source("ppp/transmissions/ITransmission.h")
        websocket_header = self.source("ppp/transmissions/IWebsocketTransmission.h")
        websocket_source = self.source("ppp/transmissions/IWebsocketTransmission.cpp")
        tcp_header = self.source("ppp/transmissions/ITcpipTransmission.h")
        tls_header = self.source("ppp/net/asio/websocket.h")
        tls_close = self.source(
            "ppp/net/asio/websocket/websocket_ssl_close_websocket.cpp"
        )

        self.assertIn("class IAuthenticatedCarrierBinding", binding_header)
        self.assertIn("virtual ~IAuthenticatedCarrierBinding() noexcept", binding_header)
        self.assertIn("HasAuthenticatedSessionExporter() const noexcept = 0", binding_header)
        self.assertIn("ExportAuthenticatedSessionKey", binding_header)
        self.assertIn("public IAuthenticatedCarrierBinding", base_header)
        self.assertIn("IsHandshakeComplete() const noexcept", base_header)
        self.assertIn(
            "HasAuthenticatedSessionExporter() const noexcept override;",
            base_header,
        )
        self.assertIn("ExportAuthenticatedSessionKey", base_header)
        self.assertIn("InstallNoiseAuthenticatedCarrierBinding", base_header)
        self.assertIn("AuthenticatedCarrierKind::Tcp", tcp_header)
        self.assertIn("AuthenticatedCarrierKind::WebSocket", websocket_header)
        ssl_class = websocket_header[websocket_header.index("class ISslWebsocketTransmission") :]
        plain_class = websocket_header[
            websocket_header.index("class IWebsocketTransmission") :
            websocket_header.index("class ISslWebsocketTransmission")
        ]
        self.assertIn("HasAuthenticatedSessionExporter() const noexcept override", ssl_class)
        self.assertIn("ExportAuthenticatedSessionKey", ssl_class)
        self.assertIn("void Dispose() noexcept override", ssl_class)
        self.assertIn("exporter_disabled_", ssl_class)
        self.assertNotIn("HasAuthenticatedSessionExporter", plain_class)
        self.assertNotIn("HasAuthenticatedSessionExporter", tcp_header)
        self.assertIn("IsHandshakeComplete()", websocket_source)
        self.assertIn("socket->HasSessionExporter()", websocket_source)
        self.assertIn("socket->ExportSessionKey(", websocket_source)
        dispose = websocket_source[
            websocket_source.index("void ISslWebsocketTransmission::Dispose()") :
            websocket_source.index("bool ISslWebsocketTransmission::HasAuthenticatedSessionExporter")
        ]
        self.assertLess(
            dispose.index("exporter_disabled_.store(true"),
            dispose.index("WebSocket::Dispose()"),
        )
        self.assertIn("std::mutex", tls_header)
        self.assertIn("exporter_mutex_", tls_header)
        self.assertIn("tls_handshake_complete_", tls_header)
        tls_export = self.source(
            "ppp/net/asio/websocket/websocket_ssl_websocket.cpp"
        )
        has_exporter = tls_export[
            tls_export.index("bool sslwebsocket::HasSessionExporter") :
            tls_export.index("bool sslwebsocket::ExportSessionKey")
        ]
        export_key = tls_export[
            tls_export.index("bool sslwebsocket::ExportSessionKey") :
            tls_export.index("sslwebsocket::IPEndPoint sslwebsocket::GetLocalEndPoint")
        ]
        self.assertNotIn("native_handle()", has_exporter)
        self.assertIn("tls_handshake_complete_", has_exporter)
        self.assertIn("running_in_this_thread()", export_key)
        self.assertIn("std::lock_guard<std::mutex>", tls_close)
        shift = tls_close[tls_close.index("bool sslwebsocket::ShiftToScheduler") :]
        self.assertIn("exporter_ready && ok && !disposed_", shift)
        self.assertIn("struct ssl_st;", exporter_header)
        self.assertIn("::ssl_st*", exporter_header)
        self.assertNotIn("openssl/types.h", exporter_header)


if __name__ == "__main__":
    unittest.main()
