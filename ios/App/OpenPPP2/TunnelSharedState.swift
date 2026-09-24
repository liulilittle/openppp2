import Foundation
import Network

/// Cross-process tunnel liveness and diagnostics via App Group (mirrors Android
/// `openppp2-linkstate.txt` + `PppStateStore`).
enum TunnelSharedState {
    struct LastTunnelConfiguration: Codable {
        var profileId: String
        var profileName: String
        var serverAddress: String
        var configJson: String
        var optionsJson: String
        var telemetryJson: String
        var debugJson: String?
        var updatedAtMs: Int64
    }

    struct LastTunnelStopReason: Codable, Equatable {
        var code: Int
        var name: String
        var updatedAtMs: Int64
    }

    struct NetworkPathSnapshot: Codable, Equatable {
        var status: String
        var interfaces: [String]
        var isExpensive: Bool
        var isConstrained: Bool
        var supportsIPv4: Bool
        var supportsIPv6: Bool
        var supportsDNS: Bool
        var updatedAtMs: Int64

        init(
            status: String,
            interfaces: [String],
            isExpensive: Bool,
            isConstrained: Bool,
            supportsIPv4: Bool,
            supportsIPv6: Bool,
            supportsDNS: Bool,
            updatedAtMs: Int64
        ) {
            self.status = status
            self.interfaces = interfaces
            self.isExpensive = isExpensive
            self.isConstrained = isConstrained
            self.supportsIPv4 = supportsIPv4
            self.supportsIPv6 = supportsIPv6
            self.supportsDNS = supportsDNS
            self.updatedAtMs = updatedAtMs
        }

        init(path: NWPath, now: Date = Date()) {
            status = Self.statusText(path.status)
            interfaces = Self.interfaceNames(path)
            isExpensive = path.isExpensive
            isConstrained = path.isConstrained
            supportsIPv4 = path.supportsIPv4
            supportsIPv6 = path.supportsIPv6
            supportsDNS = path.supportsDNS
            updatedAtMs = Int64(now.timeIntervalSince1970 * 1000)
        }

        init?(dictionary: [String: Any]) {
            guard let status = dictionary["status"] as? String else {
                return nil
            }
            self.status = status
            interfaces = dictionary["interfaces"] as? [String] ?? []
            isExpensive = Self.boolValue(dictionary["isExpensive"])
            isConstrained = Self.boolValue(dictionary["isConstrained"])
            supportsIPv4 = Self.boolValue(dictionary["supportsIPv4"])
            supportsIPv6 = Self.boolValue(dictionary["supportsIPv6"])
            supportsDNS = Self.boolValue(dictionary["supportsDNS"])
            if let number = dictionary["updatedAtMs"] as? NSNumber {
                updatedAtMs = number.int64Value
            } else if let text = dictionary["updatedAtMs"] as? String, let value = Int64(text) {
                updatedAtMs = value
            } else {
                updatedAtMs = 0
            }
        }

        var dictionary: [String: Any] {
            [
                "status": status,
                "interfaces": interfaces,
                "isExpensive": isExpensive,
                "isConstrained": isConstrained,
                "supportsIPv4": supportsIPv4,
                "supportsIPv6": supportsIPv6,
                "supportsDNS": supportsDNS,
                "updatedAtMs": updatedAtMs
            ]
        }

        var summaryText: String {
            let interfaceText = interfaces.isEmpty ? "none" : interfaces.joined(separator: ",")
            return "\(status) \(interfaceText) expensive=\(isExpensive ? 1 : 0) constrained=\(isConstrained ? 1 : 0) dns=\(supportsDNS ? 1 : 0) ipv4=\(supportsIPv4 ? 1 : 0) ipv6=\(supportsIPv6 ? 1 : 0)"
        }

        var isSatisfied: Bool {
            status == "satisfied"
        }

        var isUnavailable: Bool {
            status == "unsatisfied" || status == "requiresConnection"
        }

        private static func statusText(_ status: NWPath.Status) -> String {
            switch status {
            case .satisfied:
                return "satisfied"
            case .unsatisfied:
                return "unsatisfied"
            case .requiresConnection:
                return "requiresConnection"
            @unknown default:
                return "unknown"
            }
        }

        private static func interfaceNames(_ path: NWPath) -> [String] {
            var names: [String] = []
            if path.usesInterfaceType(.wifi) { names.append("wifi") }
            if path.usesInterfaceType(.cellular) { names.append("cellular") }
            if path.usesInterfaceType(.wiredEthernet) { names.append("wiredEthernet") }
            if path.usesInterfaceType(.loopback) { names.append("loopback") }
            if path.usesInterfaceType(.other) { names.append("other") }
            return names
        }

        private static func boolValue(_ value: Any?) -> Bool {
            if let bool = value as? Bool {
                return bool
            }
            if let number = value as? NSNumber {
                return number.boolValue
            }
            if let text = value as? String {
                return (text as NSString).boolValue
            }
            return false
        }
    }

    static var appGroupIdentifier: String {
        AppGroupResolver.resolve(
            configured: Bundle.main.object(forInfoDictionaryKey: "OpenPPP2AppGroupIdentifier") as? String,
            bundleIdentifier: Bundle.main.bundleIdentifier
        )
    }
    static let heartbeatStaleMilliseconds: Int64 = 30_000
    static let connectWatchdogMaxSeconds = 180

    private static let linkStateFileName = "openppp2-linkstate.txt"
    private static let runtimeSnapshotFileName = "openppp2-runtime-snapshot.json"
    private static let diagnosticsFileName = "openppp2-shared-diagnostics.json"
    private static let lastTunnelConfigurationKey = "openppp2_last_tunnel_configuration_v1"
    private static let lastTunnelStopReasonKey = "openppp2_last_tunnel_stop_reason_v1"
    private static let networkPathSnapshotKey = "openppp2_network_path_snapshot_v1"
    private static let queue = DispatchQueue(label: "openppp2.tunnel-shared-state")

    static var isSharedContainerAvailable: Bool {
        containerURL() != nil
    }

    static var shouldUseSharedHeartbeat: Bool {
        isSharedContainerAvailable
    }

    static func beginSession() {
        writeLinkStateHeartbeat(6)
    }

    static func writeLinkStateHeartbeat(_ linkState: Int) {
        queue.async {
            guard let url = linkStateURL() else { return }
            try? "\(linkState)\n".write(to: url, atomically: true, encoding: .utf8)
        }
    }

    static func writeRuntimeSnapshotJson(_ json: String) {
        queue.async {
            guard let url = runtimeSnapshotURL(),
                  let data = json.data(using: .utf8)
            else { return }
            try? data.write(to: url, options: .atomic)
        }
    }

    static func readRuntimeSnapshotJsonIfAlive() -> String? {
        guard shouldUseSharedHeartbeat,
              isExtensionAlive(),
              let url = runtimeSnapshotURL(),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return nil }
        return text
    }

    static func heartbeatAgeMs() -> Int64 {
        guard shouldUseSharedHeartbeat,
              let url = linkStateURL(),
              let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let modified = attributes[.modificationDate] as? Date
        else {
            return -1
        }
        return Int64(Date().timeIntervalSince(modified) * 1000)
    }

    static func isExtensionAlive() -> Bool {
        guard shouldUseSharedHeartbeat else { return true }
        let age = heartbeatAgeMs()
        return age >= 0 && age <= heartbeatStaleMilliseconds
    }

    static func readLinkStateIfAlive() -> Int? {
        guard shouldUseSharedHeartbeat,
              isExtensionAlive(),
              let url = linkStateURL(),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else {
            return nil
        }

        let line = text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: .newlines)
            .first ?? ""
        return Int(line)
    }

    static func writeDiagnosticsJson(_ json: String) {
        queue.async {
            guard shouldUseSharedHeartbeat,
                  let url = diagnosticsURL(),
                  let data = json.data(using: .utf8)
            else {
                return
            }
            try? data.write(to: url, options: .atomic)
        }
    }

    static func readDiagnosticsJson() -> String? {
        guard shouldUseSharedHeartbeat,
              let url = diagnosticsURL(),
              let text = try? String(contentsOf: url, encoding: .utf8),
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return nil
        }
        return text
    }

    static func writeNetworkPathSnapshot(_ snapshot: NetworkPathSnapshot) {
        queue.async {
            guard let defaults = sharedDefaults(),
                  let data = try? JSONEncoder().encode(snapshot)
            else {
                return
            }
            defaults.set(data, forKey: networkPathSnapshotKey)
        }
    }

    static func readNetworkPathSnapshot() -> NetworkPathSnapshot? {
        guard let defaults = sharedDefaults(),
              let data = defaults.data(forKey: networkPathSnapshotKey),
              let snapshot = try? JSONDecoder().decode(NetworkPathSnapshot.self, from: data)
        else {
            return nil
        }
        return snapshot
    }

    static func writeLastTunnelStopReason(code: Int, name: String) {
        let reason = LastTunnelStopReason(
            code: code,
            name: name,
            updatedAtMs: Int64(Date().timeIntervalSince1970 * 1000)
        )
        queue.sync {
            guard let defaults = sharedDefaults(),
                  let data = try? JSONEncoder().encode(reason)
            else {
                return
            }
            defaults.set(data, forKey: lastTunnelStopReasonKey)
            defaults.synchronize()
        }
    }

    static func readLastTunnelStopReason() -> LastTunnelStopReason? {
        guard let defaults = sharedDefaults(),
              let data = defaults.data(forKey: lastTunnelStopReasonKey),
              let reason = try? JSONDecoder().decode(LastTunnelStopReason.self, from: data)
        else {
            return nil
        }
        return reason
    }

    static func clearLastTunnelStopReason() {
        queue.sync {
            guard let defaults = sharedDefaults() else { return }
            defaults.removeObject(forKey: lastTunnelStopReasonKey)
            defaults.synchronize()
        }
    }

    static func clearSession() {
        queue.sync {
            guard let base = containerURL() else { return }
            for name in [linkStateFileName, runtimeSnapshotFileName, diagnosticsFileName] {
                let url = base.appendingPathComponent(name)
                if FileManager.default.fileExists(atPath: url.path) {
                    try? FileManager.default.removeItem(at: url)
                }
            }
        }
    }

    static func writeLastTunnelConfiguration(_ configuration: LastTunnelConfiguration) {
        queue.sync {
            guard let defaults = sharedDefaults(),
                  let data = try? JSONEncoder().encode(configuration)
            else {
                return
            }
            defaults.set(data, forKey: lastTunnelConfigurationKey)
        }
    }

    static func readLastTunnelConfiguration() -> LastTunnelConfiguration? {
        guard let defaults = sharedDefaults(),
              let data = defaults.data(forKey: lastTunnelConfigurationKey),
              let configuration = try? JSONDecoder().decode(LastTunnelConfiguration.self, from: data)
        else {
            return nil
        }
        return configuration
    }

    private static func containerURL() -> URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier)
    }

    private static func sharedDefaults() -> UserDefaults? {
        UserDefaults(suiteName: appGroupIdentifier)
    }

    private static func linkStateURL() -> URL? {
        containerURL()?.appendingPathComponent(linkStateFileName)
    }

    private static func runtimeSnapshotURL() -> URL? {
        containerURL()?.appendingPathComponent(runtimeSnapshotFileName)
    }

    private static func diagnosticsURL() -> URL? {
        containerURL()?.appendingPathComponent(diagnosticsFileName)
    }
}
