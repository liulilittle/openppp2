import Darwin
import Foundation
import OpenPPP2

final class PacketFlowDiagnostics {
    private static let packetSampleLimit = 16
    private static let packetTelemetryInitialLimit = 4
    private static let packetTelemetryInterval = 200
    private static let packetTelemetrySnapshotInterval: TimeInterval = 30
    private static let diagnosticsWriteInterval = 500

    private let diagnosticsEnabled: Bool
    private let consoleLoggingEnabled: Bool
    private let packetFlowExporter: OTLPHTTPLogExporter?
    private let diagnosticsFileURL: URL
    private let lock = NSLock()
    private var inputPacketCount = 0
    private var lastInputPacketSummary = ""
    private var inputPacketSamples: [String] = []
    private var outputPacketCount = 0
    private var lastOutputPacketSummary = ""
    private var lastOutputPacketOK = false
    private var outputPacketSamples: [String] = []
    private var lastTelemetrySnapshotAt: Date?
    private var lastTelemetrySnapshotLinkState: Int?
    private var dataplane = "ctcp"

    init(telemetry: TelemetrySettings, debug: DebugSettings) {
        diagnosticsEnabled = debug.packetFlowDiagnosticsEnabled
        consoleLoggingEnabled = debug.packetFlowConsoleLoggingEnabled
        packetFlowExporter = debug.packetFlowTelemetryEnabled && telemetry.canUpload
            ? OTLPHTTPLogExporter(settings: telemetry, scopeName: "openppp2.ios.packet_flow")
            : nil
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        diagnosticsFileURL = (documents ?? URL(fileURLWithPath: NSTemporaryDirectory()))
            .appendingPathComponent("openppp2-diagnostics.json")
    }

    func setDataplane(_ value: String) {
        dataplane = value
    }

    @discardableResult
    func noteInputPacket(_ packet: Data, protocolNumber: NSNumber?) -> Bool {
        lock.lock()
        inputPacketCount += 1
        let packetNumber = inputPacketCount
        let shouldSample = diagnosticsEnabled
            && (packetNumber <= Self.packetSampleLimit || packetNumber % Self.diagnosticsWriteInterval == 0)
        let shouldLog = consoleLoggingEnabled
            && (packetNumber <= 8 || packetNumber % Self.diagnosticsWriteInterval == 0)
        let shouldExport = shouldExportPacketTelemetry(packetNumber: packetNumber, ok: true)
        let shouldWrite = diagnosticsEnabled
            && (packetNumber <= 20 || packetNumber % Self.diagnosticsWriteInterval == 0)
        lock.unlock()

        guard shouldSample || shouldLog || shouldExport || shouldWrite else {
            return false
        }

        let needsSummary = shouldSample || shouldLog || shouldExport
        let summary = needsSummary ? Self.packetSummary(packet, protocolNumber: protocolNumber) : ""
        if shouldLog {
            NSLog("OpenPPP2 PacketTunnel input #%d %@", packetNumber, summary)
        }

        lock.lock()
        if needsSummary {
            lastInputPacketSummary = summary
            if shouldSample {
                inputPacketSamples.append("#\(packetNumber) \(summary)")
                if inputPacketSamples.count > Self.packetSampleLimit {
                    inputPacketSamples.removeFirst(inputPacketSamples.count - Self.packetSampleLimit)
                }
            }
        }
        lock.unlock()

        if shouldExport {
            exportPacketTelemetry(
                direction: "input",
                packetNumber: packetNumber,
                packet: packet,
                protocolNumber: protocolNumber,
                summary: summary,
                ok: true
            )
        }
        return shouldWrite
    }

    func noteOutputBatch(_ batch: [(Data, NSNumber)], ok: Bool) -> Bool {
        var shouldWrite = false
        for (data, protocolNumber) in batch {
            if noteOutputPacket(data, protocolNumber: protocolNumber, ok: ok) {
                shouldWrite = true
            }
        }
        return shouldWrite
    }

    @discardableResult
    private func noteOutputPacket(_ packet: Data, protocolNumber: NSNumber, ok: Bool) -> Bool {
        lock.lock()
        outputPacketCount += 1
        lastOutputPacketOK = ok
        let packetNumber = outputPacketCount
        let shouldSample = diagnosticsEnabled
            && (!ok || packetNumber <= Self.packetSampleLimit || packetNumber % Self.diagnosticsWriteInterval == 0)
        let shouldLog = consoleLoggingEnabled
            && (!ok || packetNumber <= 8 || packetNumber % Self.diagnosticsWriteInterval == 0)
        let shouldExport = shouldExportPacketTelemetry(packetNumber: packetNumber, ok: ok)
        let shouldWrite = diagnosticsEnabled
            && (!ok || packetNumber <= 20 || packetNumber % Self.diagnosticsWriteInterval == 0)
        lock.unlock()

        guard shouldSample || shouldLog || shouldExport || shouldWrite else {
            return false
        }

        let needsSummary = shouldSample || shouldLog || shouldExport
        let summary = needsSummary ? Self.packetSummary(packet, protocolNumber: protocolNumber) : ""
        if shouldLog {
            NSLog("OpenPPP2 PacketTunnel output #%d ok=%d %@", packetNumber, ok ? 1 : 0, summary)
        }

        lock.lock()
        if needsSummary {
            lastOutputPacketSummary = summary
            if shouldSample {
                let okText = ok ? "ok" : "failed"
                outputPacketSamples.append("#\(packetNumber) \(okText) \(summary)")
                if outputPacketSamples.count > Self.packetSampleLimit {
                    outputPacketSamples.removeFirst(outputPacketSamples.count - Self.packetSampleLimit)
                }
            }
        }
        lock.unlock()

        if shouldExport {
            exportPacketTelemetry(
                direction: "output",
                packetNumber: packetNumber,
                packet: packet,
                protocolNumber: protocolNumber,
                summary: summary,
                ok: ok
            )
        }
        return shouldWrite
    }

    func inputPacketCountSnapshot() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return inputPacketCount
    }

    func outputPacketCountSnapshot() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return outputPacketCount
    }

    func diagnosticsPayload(
        linkState: Int,
        startStage: String,
        lastError: String,
        outputDroppedCount: Int,
        pendingOutputDepth: Int,
        runtimeSnapshotJson: String
    ) -> [String: Any] {
        lock.lock()
        let inputCount = inputPacketCount
        let inputSummary = lastInputPacketSummary
        let inputSamples = inputPacketSamples
        let outputCount = outputPacketCount
        let outputSummary = lastOutputPacketSummary
        let outputOK = lastOutputPacketOK
        let outputSamples = outputPacketSamples
        lock.unlock()

        var payload: [String: Any] = [
            "linkState": linkState,
            "startStage": startStage,
            "lastError": lastError,
            "lastErrorCode": openPPP2LastErrorCode(),
            "inputPacketCount": inputCount,
            "lastInputPacket": inputSummary,
            "inputPackets": inputSamples,
            "outputPacketCount": outputCount,
            "outputDroppedCount": outputDroppedCount,
            "pendingOutputDepth": pendingOutputDepth,
            "lastOutputPacket": outputSummary,
            "lastOutputPacketOK": outputOK,
            "outputPackets": outputSamples,
            "dataplane": dataplane,
            "runtimeSnapshot": runtimeSnapshotJson
        ]
        if let networkPath = TunnelSharedState.readNetworkPathSnapshot() {
            payload["networkPath"] = networkPath.dictionary
        }
        return payload
    }

    func diagnosticsJson(
        linkState: Int,
        startStage: String,
        lastError: String,
        outputDroppedCount: Int,
        pendingOutputDepth: Int,
        runtimeSnapshotJson: String
    ) -> String {
        let payload = diagnosticsPayload(
            linkState: linkState,
            startStage: startStage,
            lastError: lastError,
            outputDroppedCount: outputDroppedCount,
            pendingOutputDepth: pendingOutputDepth,
            runtimeSnapshotJson: runtimeSnapshotJson
        )

        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8)
        else {
            return "{\"linkState\":\(linkState)}"
        }
        return text
    }

    func persistSnapshot(
        linkState: Int,
        startStage: String,
        lastError: String,
        outputDroppedCount: Int,
        pendingOutputDepth: Int,
        runtimeSnapshotJson: String
    ) {
        var payload = diagnosticsPayload(
            linkState: linkState,
            startStage: startStage,
            lastError: lastError,
            outputDroppedCount: outputDroppedCount,
            pendingOutputDepth: pendingOutputDepth,
            runtimeSnapshotJson: runtimeSnapshotJson
        )
        payload["updatedAt"] = ISO8601DateFormatter().string(from: Date())

        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        else {
            return
        }

        try? data.write(to: diagnosticsFileURL, options: [.atomic])

        if let text = String(data: data, encoding: .utf8) {
            TunnelSharedState.writeLinkStateHeartbeat(linkState)
            TunnelSharedState.writeDiagnosticsJson(text)
        }
    }

    func heartbeatTick(
        linkState: Int,
        startStage: String,
        lastError: String,
        outputDroppedCount: Int,
        pendingOutputDepth: Int,
        runtimeSnapshotJson: String
    ) {
        TunnelSharedState.writeLinkStateHeartbeat(linkState)
        if diagnosticsEnabled {
            persistSnapshot(
                linkState: linkState,
                startStage: startStage,
                lastError: lastError,
                outputDroppedCount: outputDroppedCount,
                pendingOutputDepth: pendingOutputDepth,
                runtimeSnapshotJson: runtimeSnapshotJson
            )
        }
        if shouldExportSnapshotTelemetry(linkState: linkState) {
            exportSnapshotTelemetry(
                reason: "heartbeat",
                linkState: linkState,
                startStage: startStage,
                lastError: lastError,
                outputDroppedCount: outputDroppedCount,
                pendingOutputDepth: pendingOutputDepth,
                runtimeSnapshotJson: runtimeSnapshotJson
            )
        }
    }

    private func shouldExportPacketTelemetry(packetNumber: Int, ok: Bool) -> Bool {
        guard packetFlowExporter != nil else { return false }
        return !ok
            || packetNumber <= Self.packetTelemetryInitialLimit
            || packetNumber % Self.packetTelemetryInterval == 0
    }

    private func shouldExportSnapshotTelemetry(linkState: Int) -> Bool {
        guard packetFlowExporter != nil else { return false }
        let now = Date()
        lock.lock()
        defer { lock.unlock() }
        if lastTelemetrySnapshotLinkState != linkState {
            lastTelemetrySnapshotAt = now
            lastTelemetrySnapshotLinkState = linkState
            return true
        }
        if let lastTelemetrySnapshotAt,
           now.timeIntervalSince(lastTelemetrySnapshotAt) < Self.packetTelemetrySnapshotInterval {
            return false
        }
        lastTelemetrySnapshotAt = now
        lastTelemetrySnapshotLinkState = linkState
        return true
    }

    private func exportPacketTelemetry(
        direction: String,
        packetNumber: Int,
        packet: Data,
        protocolNumber: NSNumber?,
        summary: String,
        ok: Bool
    ) {
        guard let packetFlowExporter else { return }

        lock.lock()
        let inputCount = inputPacketCount
        let outputCount = outputPacketCount
        lock.unlock()

        var attributes: [String: OTLPAttributeValue] = [
            "event.name": .string("openppp2.packet_flow.packet"),
            "openppp2.packet.direction": .string(direction),
            "openppp2.packet.number": .int(Int64(packetNumber)),
            "openppp2.packet.bytes": .int(Int64(packet.count)),
            "openppp2.packet.ok": .bool(ok),
            "openppp2.packet.summary": .string(summary),
            "openppp2.dataplane": .string(dataplane),
            "openppp2.packet.input_count": .int(Int64(inputCount)),
            "openppp2.packet.output_count": .int(Int64(outputCount))
        ]
        attributes["openppp2.packet.af"] = .int(Int64(protocolNumber?.intValue ?? -1))
        if let version = packet.first.map({ Int($0 >> 4) }) {
            attributes["openppp2.packet.ip_version"] = .int(Int64(version))
        }
        if let transportProtocol = Self.transportProtocol(packet) {
            attributes["openppp2.packet.transport_protocol"] = .int(Int64(transportProtocol))
            attributes["openppp2.packet.transport_name"] = .string(Self.transportName(transportProtocol))
        }

        let record = OTLPLogRecord(
            timeUnixNano: Self.unixNanoNow(),
            severityText: ok ? "INFO" : "ERROR",
            body: "packet_flow direction=\(direction) number=\(packetNumber) ok=\(ok ? 1 : 0) \(summary)",
            attributes: attributes
        )
        packetFlowExporter.export(records: [record]) { result in
            if case let .failure(error) = result {
                NSLog("OpenPPP2 packetFlow telemetry upload failed: %@", error.localizedDescription)
            }
        }
    }

    private func exportSnapshotTelemetry(
        reason: String,
        linkState: Int,
        startStage: String,
        lastError: String,
        outputDroppedCount: Int,
        pendingOutputDepth: Int,
        runtimeSnapshotJson: String
    ) {
        guard let packetFlowExporter else { return }

        lock.lock()
        let inputCount = inputPacketCount
        let outputCount = outputPacketCount
        let outputOK = lastOutputPacketOK
        lock.unlock()
        let trimmedError = lastError.trimmingCharacters(in: .whitespacesAndNewlines)
        let meaningfulError = trimmedError.lowercased() == "success" ? "" : trimmedError
        let lastErrorCode = openPPP2LastErrorCode()
        let sharedContainerAvailable = TunnelSharedState.isSharedContainerAvailable

        let record = OTLPLogRecord(
            timeUnixNano: Self.unixNanoNow(),
            severityText: "INFO",
            body: "packet_flow snapshot reason=\(reason) linkState=\(linkState) stage=\(startStage) error=\(meaningfulError.isEmpty ? "none" : meaningfulError) input=\(inputCount) output=\(outputCount) lastOutputOK=\(outputOK ? 1 : 0)",
            attributes: [
                "event.name": .string("openppp2.packet_flow.snapshot"),
                "openppp2.packet_flow.reason": .string(reason),
                "openppp2.dataplane": .string(dataplane),
                "openppp2.link_state": .int(Int64(linkState)),
                "openppp2.start_stage": .string(startStage),
                "openppp2.last_error": .string(meaningfulError),
                "openppp2.last_error_code": .int(Int64(lastErrorCode)),
                "openppp2.packet.input_count": .int(Int64(inputCount)),
                "openppp2.packet.output_count": .int(Int64(outputCount)),
                "openppp2.packet.last_output_ok": .bool(outputOK),
                "openppp2.output_dropped_count": .int(Int64(outputDroppedCount)),
                "openppp2.pending_output_depth": .int(Int64(pendingOutputDepth)),
                "openppp2.app_group.identifier": .string(TunnelSharedState.appGroupIdentifier),
                "openppp2.app_group.available": .bool(sharedContainerAvailable),
                "openppp2.runtime.snapshot": .string(runtimeSnapshotJson)
            ]
        )
        packetFlowExporter.export(records: [record]) { result in
            if case let .failure(error) = result {
                NSLog("OpenPPP2 packetFlow snapshot upload failed: %@", error.localizedDescription)
            }
        }
    }

    private static func packetSummary(_ packet: Data, protocolNumber: NSNumber?) -> String {
        guard let first = packet.first else {
            return "empty packet"
        }

        let family = protocolNumber.map { "af=\($0.intValue)" } ?? "af=?"
        switch first >> 4 {
        case 4:
            return "\(family) \(ipv4Summary(packet))"
        case 6:
            return "\(family) \(ipv6Summary(packet))"
        default:
            return "\(family) unknown-version=\(first >> 4) len=\(packet.count)"
        }
    }

    private static func ipv4Summary(_ packet: Data) -> String {
        guard packet.count >= 20 else {
            return "ipv4 truncated len=\(packet.count)"
        }

        let headerLength = Int(packet[0] & 0x0f) * 4
        guard headerLength >= 20, packet.count >= headerLength else {
            return "ipv4 bad-header len=\(packet.count)"
        }

        let proto = Int(packet[9])
        let src = ipv4Address(packet, 12)
        let dst = ipv4Address(packet, 16)
        let ports = transportPorts(packet, offset: headerLength, proto: proto)
        let detail = transportDetail(packet, offset: headerLength, proto: proto)
        let checksum = ipv4ChecksumDetail(packet, headerLength: headerLength, proto: proto)
        return "ipv4 \(transportName(proto)) \(src)\(ports.src) -> \(dst)\(ports.dst) len=\(packet.count)\(detail)\(checksum)"
    }

    private static func ipv6Summary(_ packet: Data) -> String {
        guard packet.count >= 40 else {
            return "ipv6 truncated len=\(packet.count)"
        }

        let nextHeader = Int(packet[6])
        let src = ipv6Address(packet, 8)
        let dst = ipv6Address(packet, 24)
        let ports = transportPorts(packet, offset: 40, proto: nextHeader)
        let detail = transportDetail(packet, offset: 40, proto: nextHeader)
        return "ipv6 \(transportName(nextHeader)) \(src)\(ports.src) -> \(dst)\(ports.dst) len=\(packet.count)\(detail)"
    }

    private static func transportPorts(_ packet: Data, offset: Int, proto: Int) -> (src: String, dst: String) {
        guard (proto == 6 || proto == 17), packet.count >= offset + 4 else {
            return ("", "")
        }

        let src = (UInt16(packet[offset]) << 8) | UInt16(packet[offset + 1])
        let dst = (UInt16(packet[offset + 2]) << 8) | UInt16(packet[offset + 3])
        return (":\(src)", ":\(dst)")
    }

    private static func transportDetail(_ packet: Data, offset: Int, proto: Int) -> String {
        switch proto {
        case 6:
            guard packet.count >= offset + 20 else {
                return " tcp=truncated"
            }
            let dataOffset = Int(packet[offset + 12] >> 4) * 4
            guard dataOffset >= 20, packet.count >= offset + dataOffset else {
                return " tcp=bad-header"
            }
            let flags = Int(packet[offset + 13])
            let tcpPayloadLength = packet.count - offset - dataOffset
            let seq = uint32(packet, offset + 4)
            let ack = uint32(packet, offset + 8)
            let wnd = uint16(packet, offset + 14)
            return " flags=\(tcpFlags(flags)) seq=\(seq) ack=\(ack) wnd=\(wnd) tcpPayload=\(tcpPayloadLength)"
        case 17:
            guard packet.count >= offset + 8 else {
                return " udp=truncated"
            }
            let udpLength = Int(uint16(packet, offset + 4))
            let udpPayloadLength = max(0, udpLength - 8)
            return " udpPayload=\(udpPayloadLength)"
        default:
            return ""
        }
    }

    private static func tcpFlags(_ value: Int) -> String {
        var names: [String] = []
        if value & 0x01 != 0 { names.append("FIN") }
        if value & 0x02 != 0 { names.append("SYN") }
        if value & 0x04 != 0 { names.append("RST") }
        if value & 0x08 != 0 { names.append("PSH") }
        if value & 0x10 != 0 { names.append("ACK") }
        if value & 0x20 != 0 { names.append("URG") }
        if value & 0x40 != 0 { names.append("ECE") }
        if value & 0x80 != 0 { names.append("CWR") }
        return names.isEmpty ? "NONE" : names.joined(separator: "|")
    }

    private static func uint16(_ packet: Data, _ offset: Int) -> UInt16 {
        guard packet.count >= offset + 2 else { return 0 }
        return (UInt16(packet[offset]) << 8) | UInt16(packet[offset + 1])
    }

    private static func uint32(_ packet: Data, _ offset: Int) -> UInt32 {
        guard packet.count >= offset + 4 else { return 0 }
        return (UInt32(packet[offset]) << 24)
            | (UInt32(packet[offset + 1]) << 16)
            | (UInt32(packet[offset + 2]) << 8)
            | UInt32(packet[offset + 3])
    }

    private static func ipv4ChecksumDetail(_ packet: Data, headerLength: Int, proto: Int) -> String {
        let ipResidual = internetChecksum(packet, offset: 0, length: headerLength, seed: 0)
        var parts = [" ipCk=\(checksumText(ipResidual))"]

        if proto == 6, packet.count >= headerLength + 20 {
            let tcpLength = packet.count - headerLength
            var seed: UInt32 = 0
            seed += UInt32(uint16(packet, 12))
            seed += UInt32(uint16(packet, 14))
            seed += UInt32(uint16(packet, 16))
            seed += UInt32(uint16(packet, 18))
            seed += UInt32(proto)
            seed += UInt32(tcpLength)
            let tcpResidual = internetChecksum(packet, offset: headerLength, length: tcpLength, seed: seed)
            parts.append("tcpCk=\(checksumText(tcpResidual))")
        }

        return parts.joined(separator: " ")
    }

    private static func internetChecksum(_ packet: Data, offset: Int, length: Int, seed: UInt32) -> UInt16 {
        guard offset >= 0, length >= 0, packet.count >= offset + length else { return 0xffff }

        var sum = seed
        var index = offset
        let end = offset + length
        while index + 1 < end {
            sum += UInt32(UInt16(packet[index]) << 8 | UInt16(packet[index + 1]))
            index += 2
        }
        if index < end {
            sum += UInt32(UInt16(packet[index]) << 8)
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return UInt16(~sum & 0xffff)
    }

    private static func checksumText(_ value: UInt16) -> String {
        value == 0 ? "ok" : String(format: "bad:%04x", value)
    }

    private static func transportProtocol(_ packet: Data) -> Int? {
        guard let first = packet.first else { return nil }
        switch first >> 4 {
        case 4:
            guard packet.count >= 20 else { return nil }
            return Int(packet[9])
        case 6:
            guard packet.count >= 40 else { return nil }
            return Int(packet[6])
        default:
            return nil
        }
    }

    private static func unixNanoNow() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
    }

    private static func transportName(_ proto: Int) -> String {
        switch proto {
        case 1: return "ICMP"
        case 6: return "TCP"
        case 17: return "UDP"
        case 58: return "ICMPv6"
        default: return "proto\(proto)"
        }
    }

    private static func ipv4Address(_ packet: Data, _ offset: Int) -> String {
        guard packet.count >= offset + 4 else { return "?.?.?.?" }
        return "\(packet[offset]).\(packet[offset + 1]).\(packet[offset + 2]).\(packet[offset + 3])"
    }

    private static func ipv6Address(_ packet: Data, _ offset: Int) -> String {
        guard packet.count >= offset + 16 else { return "::" }
        var groups: [String] = []
        for index in stride(from: offset, to: offset + 16, by: 2) {
            let value = (UInt16(packet[index]) << 8) | UInt16(packet[index + 1])
            groups.append(String(value, radix: 16))
        }
        return groups.joined(separator: ":")
    }
}
