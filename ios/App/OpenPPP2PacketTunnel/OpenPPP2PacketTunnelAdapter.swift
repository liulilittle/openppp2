import Foundation
import NetworkExtension
import OpenPPP2

final class OpenPPP2PacketTunnelAdapter {
    private static let readBackpressureDelay: TimeInterval = 0.005

    private let flow: NEPacketTunnelFlow
    private let packetFlowDiagnostics: PacketFlowDiagnostics
    private let outputQueue: PacketFlowOutputQueue
    private let packetFlowConsoleLoggingEnabled: Bool
    private let p2pDatagramProvider: ProviderOwnedP2PDatagramTransport
    private var tap: OpaquePointer?
    private var isRunning = false
    private let statsQueue = DispatchQueue(label: "io.github.openppp2.packet-tunnel.stats")
    private var latestRuntimeSnapshotJson = "{}"
    private var heartbeatTimer: DispatchSourceTimer?
    private var dataplane = "ctcp"

    init(provider: NEPacketTunnelProvider, flow: NEPacketTunnelFlow, telemetry: TelemetrySettings = .disabled, debug: DebugSettings = DebugSettings()) {
        self.flow = flow
        p2pDatagramProvider = ProviderOwnedP2PDatagramTransport(provider: provider)
        packetFlowConsoleLoggingEnabled = debug.packetFlowConsoleLoggingEnabled
        packetFlowDiagnostics = PacketFlowDiagnostics(telemetry: telemetry, debug: debug)
        outputQueue = PacketFlowOutputQueue(flow: flow, consoleLoggingEnabled: debug.packetFlowConsoleLoggingEnabled)
        outputQueue.onBatchWritten = { [weak self] batch, ok in
            guard let self else { return }
            if self.packetFlowDiagnostics.noteOutputBatch(batch, ok: ok) {
                self.persistDiagnosticsSnapshot()
            }
        }
    }

    func start(configJson: String, options: PacketTunnelOptions) -> Bool {
        guard tap == nil else {
            return true
        }

        let userData = Unmanaged.passUnretained(self).toOpaque()
        guard let createdTap = openppp2_ios_tap_create(openPPP2PacketWriter, userData) else {
            return false
        }

        guard p2pDatagramProvider.install(on: createdTap) else {
            openppp2_ios_tap_destroy(createdTap)
            return false
        }

        guard startNativeTap(createdTap, configJson: configJson, options: options, userData: userData) else {
            p2pDatagramProvider.uninstall(from: createdTap)
            openppp2_ios_tap_destroy(createdTap)
            return false
        }

        tap = createdTap
        dataplane = options.lwip ? "lwip" : "ctcp"
        packetFlowDiagnostics.setDataplane(dataplane)
        isRunning = true
        startHeartbeat()
        persistDiagnosticsSnapshot()
        readPackets()
        return true
    }

    func stop(stopReason: Int32 = -1) {
        isRunning = false
        stopHeartbeat()
        outputQueue.flush(force: true)

        if let tap {
            openppp2_ios_tap_stop(tap, stopReason)
            if let snapshot = readNativeRuntimeSnapshot() {
                TunnelSharedState.writeRuntimeSnapshotJson(snapshot)
            }
            p2pDatagramProvider.uninstall(from: tap)
            openppp2_ios_tap_destroy(tap)
            self.tap = nil
        }
        persistDiagnosticsSnapshot()
    }

    func telemetryStopAttributes() -> [String: OTLPAttributeValue] {
        [
            "openppp2.link_state": .int(Int64(linkState())),
            "openppp2.dataplane": .string(dataplaneName()),
            "openppp2.input_packet_count": .int(Int64(packetFlowDiagnostics.inputPacketCountSnapshot())),
            "openppp2.output_packet_count": .int(Int64(packetFlowDiagnostics.outputPacketCountSnapshot())),
            "openppp2.output_dropped_count": .int(Int64(outputQueue.droppedCountSnapshot())),
            "openppp2.pending_output_depth": .int(Int64(outputQueue.pendingDepthSnapshot())),
        ]
    }

    /// Diagnostics carry the runtime snapshot rather than a separate traffic
    /// payload: it already holds the totals plus the phase, mux and P2P state.
    func runtimeSnapshotJson() -> String {
        if let text = readNativeRuntimeSnapshot() {
            statsQueue.sync {
                latestRuntimeSnapshotJson = text
            }
            return text
        }
        return statsQueue.sync { latestRuntimeSnapshotJson }
    }

    func linkState() -> Int32 {
        guard let tap else {
            return 2
        }
        return openppp2_ios_tap_get_link_state(tap)
    }

    func diagnosticsJson() -> String {
        packetFlowDiagnostics.diagnosticsJson(
            linkState: Int(linkState()),
            startStage: startStage(),
            lastError: openPPP2LastErrorText(),
            outputDroppedCount: outputQueue.droppedCountSnapshot(),
            pendingOutputDepth: outputQueue.pendingDepthSnapshot(),
            runtimeSnapshotJson: runtimeSnapshotJson()
        )
    }

    func writePacket(
        _ packet: UnsafeRawPointer?,
        size: Int32,
        packetContext: UnsafeMutableRawPointer?,
        release: openppp2_ios_packet_release?
    ) -> Int32 {
        guard let packet, size > 0 else {
            return 0
        }
        return outputQueue.enqueue(packet: packet, size: size, packetContext: packetContext, release: release)
    }

    private func startNativeTap(
        _ tap: OpaquePointer,
        configJson: String,
        options: PacketTunnelOptions,
        userData: UnsafeMutableRawPointer
    ) -> Bool {
        let rootPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? NSTemporaryDirectory()
        let bypassIpList = options.effectiveBypassIpList

        return configJson.withCString { configPtr in
            options.tunIp.withCString { ipPtr in
                options.tunMask.withCString { maskPtr in
                    bypassIpList.withCString { bypassPtr in
                        options.dnsRulesList.withCString { rulesPtr in
                            rootPath.withCString { rootPtr in
                                options.dns1.withCString { dns1Ptr in
                                    options.dns2.withCString { dns2Ptr in
                                        var nativeOptions = openppp2_ios_tunnel_options(
                                            mux: Int32(options.mux),
                                            vnet: options.vnet ? 1 : 0,
                                            lwip: options.lwip ? 1 : 0,
                                            block_quic: options.blockQuic ? 1 : 0,
                                            static_mode: options.staticMode ? 1 : 0,
                                            ip: ipPtr,
                                            mask: maskPtr,
                                            bypass_ip_list: bypassPtr,
                                            dns_rules_list: rulesPtr,
                                            root_path: rootPtr,
                                            packet_logging: packetFlowConsoleLoggingEnabled ? 1 : 0,
                                            dns1: dns1Ptr,
                                            dns2: dns2Ptr
                                        )

                                        let code = openppp2_ios_tap_start(
                                            tap,
                                            configPtr,
                                            &nativeOptions
                                        )
                                        return code == 0
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func startStage() -> String {
        guard let tap else {
            return "tap not created"
        }

        var buffer = [CChar](repeating: 0, count: 256)
        let count = openppp2_ios_tap_get_start_stage(tap, &buffer, Int32(buffer.count))
        guard count > 0 else {
            return "stage unavailable"
        }
        return String(cString: buffer)
    }

    private func dataplaneName() -> String {
        dataplane
    }

    private func readNativeRuntimeSnapshot() -> String? {
        guard let tap else {
            return nil
        }

        // The bridge truncates silently but returns the full length, so grow
        // and retry rather than decoding a cut-off payload.
        var capacity = 4_096
        for _ in 0..<2 {
            var buffer = [CChar](repeating: 0, count: capacity)
            let count = openppp2_ios_tap_get_runtime_snapshot(tap, &buffer, Int32(buffer.count))
            guard count > 0 else {
                return nil
            }
            if count < buffer.count {
                return String(cString: buffer)
            }
            capacity = Int(count) + 1
        }
        return nil
    }

    private func readPackets() {
        guard isRunning else {
            return
        }

        if outputQueue.shouldPauseReads() {
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + Self.readBackpressureDelay) { [weak self] in
                self?.readPackets()
            }
            return
        }

        flow.readPackets { [weak self] packets, protocols in
            guard let self else {
                return
            }

            if self.isRunning, let tap = self.tap {
                for (index, packet) in packets.enumerated() {
                    let protocolNumber = protocols.indices.contains(index) ? protocols[index] : nil
                    if self.packetFlowDiagnostics.noteInputPacket(packet, protocolNumber: protocolNumber) {
                        self.persistDiagnosticsSnapshot()
                    }
                    packet.withUnsafeBytes { buffer in
                        guard let baseAddress = buffer.baseAddress, !buffer.isEmpty else {
                            return
                        }

                        _ = openppp2_ios_tap_input(tap, baseAddress, Int32(buffer.count))
                    }
                }
            }

            self.readPackets()
        }
    }

    private func persistDiagnosticsSnapshot() {
        statsQueue.async { [weak self] in
            self?.writeDiagnosticsSnapshotLocked()
        }
    }

    private func writeDiagnosticsSnapshotLocked() {
        if let snapshot = readNativeRuntimeSnapshot() {
            latestRuntimeSnapshotJson = snapshot
        }
        packetFlowDiagnostics.persistSnapshot(
            linkState: Int(linkState()),
            startStage: startStage(),
            lastError: openPPP2LastErrorText(),
            outputDroppedCount: outputQueue.droppedCountSnapshot(),
            pendingOutputDepth: outputQueue.pendingDepthSnapshot(),
            runtimeSnapshotJson: latestRuntimeSnapshotJson
        )
    }

    private func startHeartbeat() {
        stopHeartbeat()
        let timer = DispatchSource.makeTimerSource(queue: statsQueue)
        timer.schedule(deadline: .now(), repeating: 1.0)
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            if let snapshot = self.readNativeRuntimeSnapshot() {
                self.latestRuntimeSnapshotJson = snapshot
                TunnelSharedState.writeRuntimeSnapshotJson(snapshot)
            }
            self.packetFlowDiagnostics.heartbeatTick(
                linkState: Int(self.linkState()),
                startStage: self.startStage(),
                lastError: openPPP2LastErrorText(),
                outputDroppedCount: self.outputQueue.droppedCountSnapshot(),
                pendingOutputDepth: self.outputQueue.pendingDepthSnapshot(),
                runtimeSnapshotJson: self.latestRuntimeSnapshotJson
            )
        }
        timer.resume()
        heartbeatTimer = timer
    }

    private func stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
    }
}
