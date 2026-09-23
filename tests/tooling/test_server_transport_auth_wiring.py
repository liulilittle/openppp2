import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SWITCHER = (ROOT / "ppp/app/server/VirtualEthernetSwitcher.cpp").read_text(
    encoding="utf-8"
)
EXCHANGER = (ROOT / "ppp/app/server/VirtualEthernetExchanger.cpp").read_text(
    encoding="utf-8"
)
HEADER = (ROOT / "ppp/app/server/VirtualEthernetSwitcher.h").read_text(
    encoding="utf-8"
)
TRANSMISSION = (ROOT / "ppp/transmissions/ITransmission.cpp").read_text(
    encoding="utf-8"
)
WEBSOCKET = (ROOT / "ppp/transmissions/IWebsocketTransmission.cpp").read_text(
    encoding="utf-8"
)


def body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


class ServerTransportAuthWiringTest(unittest.TestCase):
    def test_private_helper_runs_immediately_after_transport_handshake(self) -> None:
        self.assertRegex(
            HEADER,
            re.compile(
                r"private:\s.*AuthenticatePlainTransport\(",
                re.DOTALL,
            ),
        )
        run = body(
            SWITCHER,
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
            "bool VirtualEthernetSwitcher::Accept(const ContextPtr& context",
        )
        handshake = run.index("transmission->HandshakeClient(y, mux)")
        authenticate = run.index("AuthenticatePlainTransport(transmission, session_id, y)")
        connect = run.index("Connect(transmission, session_id, y)")
        establish = run.index("Establish(transmission, session_id")
        managed = run.index("AuthenticationToManagedServer")
        self.assertLess(handshake, authenticate)
        self.assertLess(authenticate, connect)
        self.assertLess(authenticate, establish)
        self.assertLess(authenticate, managed)

    def test_decision_gate_skips_legacy_disabled_and_wss(self) -> None:
        helper = body(
            SWITCHER,
            "bool VirtualEthernetSwitcher::AuthenticatePlainTransport(",
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
        )
        self.assertIn(
            "kind == AuthenticatedCarrierKind::Tcp ||\n"
            "                    kind == AuthenticatedCarrierKind::WebSocket",
            helper,
        )
        gate = helper.index("if (!plain_carrier ||")
        bypass = helper.index("return true;", gate)
        read = helper.index("ReadInformation(")
        self.assertLess(gate, bypass)
        self.assertLess(bypass, read)
        self.assertIn("!configuration_->server.transport_auth.enabled", helper)
        self.assertIn("!transmission->PeerSupportsTransportAuthV1()", helper)
        self.assertIn("!transmission->PeerEnablesTransportAuthV1()", helper)
        self.assertNotIn("TransportAuthCarrier::TlsWebSocket", helper)

    def test_server_responder_enforces_strict_info_sequence(self) -> None:
        helper = body(
            SWITCHER,
            "bool VirtualEthernetSwitcher::AuthenticatePlainTransport(",
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
        )
        self.assertIn("auth_context.token.clear()", helper)
        self.assertIn("extensions.TransportAuth.Clear()", helper)
        self.assertIn("control.HasAny() && !extensions.HasAny()", helper)
        advertise = helper.index("responder.ConsumeAdvertisement(")
        select = helper.index("authenticated = send_control(response);", advertise)
        proof = helper.index("responder.ConsumeClientProof(")
        take = helper.index("responder.TakeNoiseResult(result)")
        install = helper.index("InstallNoiseAuthenticatedCarrierBinding(")
        acknowledgement = helper.index("authenticated = send_control(response);", install)
        self.assertLess(advertise, select)
        self.assertLess(select, proof)
        self.assertLess(proof, take)
        self.assertLess(take, install)
        self.assertLess(install, acknowledgement)
        self.assertIn("advertisement_received && !reject_sent", helper)
        self.assertIn('control.reason = "authentication-failed"', helper)

    def test_negotiation_timeout_disposes_and_is_cancelled(self) -> None:
        helper = body(
            SWITCHER,
            "bool VirtualEthernetSwitcher::AuthenticatePlainTransport(",
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
        )
        self.assertIn("configuration_->transport_auth.handshake_timeout_ms", helper)
        self.assertIn("boost::asio::steady_timer", helper)
        self.assertIn("transmission->Dispose()", helper)
        self.assertIn("handshake_timer->cancel()", helper)
        self.assertIn("ErrorCode::SocketTimeout", helper)

    def test_recovery_carriers_require_exact_kind_method_and_exporter(self) -> None:
        for source, start, end in (
            (
                SWITCHER,
                "static bool IsEligibleAuthenticatedRecoveryCarrier(",
                "static bool DeriveSessionResumeCandidateBinding(",
            ),
            (
                EXCHANGER,
                "static bool IsConfiguredRecoveryCarrier(",
                "static SessionResumeExporter MakeSessionResumeExporter(",
            ),
        ):
            predicate = body(source, start, end)
            self.assertIn("IsServerLoopbackIngress()", predicate)
            self.assertIn("IsAuthenticatedCarrierBindingActive()", predicate)
            self.assertIn("HasAuthenticatedSessionExporter()", predicate)
            self.assertIn("AuthenticatedCarrierKind::TlsWebSocket", predicate)
            self.assertIn("AuthenticatedCarrierMethod::TlsExporterV1", predicate)
            self.assertIn("AuthenticatedCarrierKind::Tcp", predicate)
            self.assertIn("AuthenticatedCarrierKind::WebSocket", predicate)
            self.assertIn("AuthenticatedCarrierMethod::NoisePskV1", predicate)
            self.assertNotIn("dynamic_pointer_cast", predicate)
        configured = body(
            EXCHANGER,
            "static bool IsConfiguredRecoveryCarrier(",
            "static SessionResumeExporter MakeSessionResumeExporter(",
        )
        self.assertIn("configuration->server.session_resume.enabled", configured)

    def test_loopback_ingress_is_marked_and_excluded_before_noise(self) -> None:
        accept = body(
            SWITCHER,
            "VirtualEthernetSwitcher::ITransmissionPtr VirtualEthernetSwitcher::Accept(",
            "void VirtualEthernetSwitcher::Dispose() noexcept",
        )
        self.assertIn("socket->remote_endpoint(remote_endpoint_error)", accept)
        self.assertIn("remote_endpoint_error || remote_endpoint.address().is_loopback()", accept)
        self.assertIn("transmission->MarkServerLoopbackIngress()", accept)

        helper = body(
            SWITCHER,
            "bool VirtualEthernetSwitcher::AuthenticatePlainTransport(",
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
        )
        loopback_gate = helper.index("transmission->IsServerLoopbackIngress()")
        read = helper.index("ReadInformation(")
        self.assertLess(loopback_gate, read)

        server_advertisement = body(
            TRANSMISSION,
            "Int128 ITransmission::InternalHandshakeClient(",
            "bool ITransmission::InternalHandshakeServer(",
        )
        self.assertIn("!IsServerLoopbackIngress()", server_advertisement)
        for signature in (
            "bool ITransmission::IsAuthenticatedCarrierBindingActive()",
            "bool ITransmission::ExportAuthenticatedSessionKey(",
            "bool ITransmission::InstallNoiseAuthenticatedCarrierBinding(",
        ):
            self.assertIn("IsServerLoopbackIngress()", TRANSMISSION[TRANSMISSION.index(signature):])
        self.assertGreaterEqual(WEBSOCKET.count("IsServerLoopbackIngress()"), 2)

    def test_late_transport_auth_control_fails_closed(self) -> None:
        on_information = body(
            EXCHANGER,
            "bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information",
            "bool VirtualEthernetExchanger::OnStatic(",
        )
        transport_auth = on_information.index("request.TransportAuth.HasAny()")
        ordinary_info = on_information.index("return OnInformation(transmission, information.Base, y)")
        self.assertLess(transport_auth, ordinary_info)
        self.assertIn("ErrorCode::ProtocolPacketActionInvalid", on_information)
        self.assertIn("return false;", on_information[transport_auth:ordinary_info])

    def test_accepted_transmission_has_a_strand_before_handshake(self) -> None:
        accept = body(
            SWITCHER,
            "bool VirtualEthernetSwitcher::Accept(const ContextPtr& context",
            "bool VirtualEthernetSwitcher::FlowerArrangement(",
        )
        self.assertIn("auto& strand = transmission->GetStrand()", accept)
        self.assertIn("context->get_executor()", accept)
        self.assertIn("YieldContext::Spawn(allocator.get(), *context, strand.get()", accept)

    def test_authentication_failure_cannot_enter_establish(self) -> None:
        run = body(
            SWITCHER,
            "int VirtualEthernetSwitcher::Run(const ContextPtr& context",
            "bool VirtualEthernetSwitcher::Accept(const ContextPtr& context",
        )
        failure = run.index("if (!AuthenticatePlainTransport(")
        failure_return = run.index("return STATUS_ERROR;", failure)
        first_establish = run.index("Establish(transmission, session_id", failure)
        self.assertLess(failure_return, first_establish)


if __name__ == "__main__":
    unittest.main()
