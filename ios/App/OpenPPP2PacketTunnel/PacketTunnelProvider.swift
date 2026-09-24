import Foundation
import Darwin
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var adapter: OpenPPP2PacketTunnelAdapter?
    private var lastOptions = PacketTunnelOptions()
    private var telemetrySettings = TelemetrySettings.disabled
    private var debugSettings = DebugSettings()
    private var lastDiagnosticsJson = "{}"
    private var networkPathMonitor: NWPathMonitor?
    private let networkPathQueue = DispatchQueue(label: "openppp2.packet-tunnel.network-path")

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        TelemetryIdentity.installIfNeeded()
        CrashReporter.install(process: .packetTunnel)
        NativeTelemetryTransport.install()

        TunnelSharedState.beginSession()

        let providerConfiguration = Self.effectiveProviderConfiguration(
            from: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        )
        let launchOptions = Self.readOptions(from: providerConfiguration)
        let telemetry = Self.readTelemetry(from: providerConfiguration)
        let debug = Self.readDebug(from: providerConfiguration)
        let configJson = providerConfiguration?["configJson"] as? String ?? "{}"
        lastOptions = launchOptions
        telemetrySettings = telemetry
        debugSettings = debug
        startNetworkPathMonitor(settings: telemetry)
        let preparedConfigJson = Self.preparedConfigJson(configJson)
        let serverHost = Self.serverHost(from: preparedConfigJson)
        let telemetryHost = Self.telemetryEndpointHost(from: preparedConfigJson)
        lastDiagnosticsJson = Self.diagnosticsJson(
            linkState: 6,
            startStage: "startTunnel received",
            lastError: "success",
            serverHost: serverHost,
            options: launchOptions
        )
        TunnelSharedState.writeDiagnosticsJson(lastDiagnosticsJson)
        guard serverHost != nil else {
            let error = Self.configurationError("client.server is empty or invalid")
            lastDiagnosticsJson = Self.diagnosticsJson(
                linkState: 6,
                startStage: "invalid configuration",
                lastError: error.localizedDescription,
                serverHost: nil,
                options: launchOptions
            )
            TunnelSharedState.writeDiagnosticsJson(lastDiagnosticsJson)
            stopNetworkPathMonitor()
            completionHandler(error)
            return
        }

        if debug.packetFlowConsoleLoggingEnabled {
            NSLog(
                "OpenPPP2 PacketTunnel start profile=%@ source=%@ server=%@ tunnel=%@/%@ route=%@/%d dataplane=%@",
                providerConfiguration?["profileName"] as? String ?? "(unknown)",
                providerConfiguration?["configurationSource"] as? String ?? "provider",
                serverHost ?? "(unknown)",
                launchOptions.tunIp,
                launchOptions.tunMask,
                launchOptions.route,
                launchOptions.routePrefix,
                launchOptions.lwip ? "lwip" : "ctcp"
            )
        }

        let proxyOnly: Bool = {
            guard let data = preparedConfigJson.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data),
                  let root = object as? [String: Any],
                  let client = root["client"] as? [String: Any]
            else {
                return false
            }

            return client["proxy-only"] as? Bool ?? false
        }()

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverHost ?? launchOptions.gateway)

        let ipv4 = NEIPv4Settings(
            addresses: [launchOptions.tunIp],
            subnetMasks: [launchOptions.tunMask]
        )
        let includedRoute = proxyOnly
            ? NEIPv4Route(destinationAddress: launchOptions.tunIp, subnetMask: launchOptions.tunMask)
            : NEIPv4Route(destinationAddress: launchOptions.route, subnetMask: Self.mask(prefix: launchOptions.routePrefix))
        ipv4.includedRoutes = [includedRoute]
        let serverIPv4Addresses = Self.resolveIPv4Addresses(for: serverHost)
        let telemetryIPv4Addresses = Self.resolveIPv4Addresses(for: telemetryHost)
        ipv4.excludedRoutes = Self.excludedRoutes(
            from: proxyOnly ? "" : launchOptions.effectiveBypassIpList,
            serverHost: serverHost,
            resolvedServerIPv4Addresses: serverIPv4Addresses,
            extraHosts: [telemetryHost].compactMap { $0 },
            extraResolvedIPv4Addresses: telemetryIPv4Addresses
        )
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: launchOptions.mtu)

        if !proxyOnly {
            let dnsServers: [String] = [launchOptions.dns1, launchOptions.dns2]
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if !dnsServers.isEmpty {
                let dnsSettings = NEDNSSettings(servers: dnsServers)
                // Match all domains so DNS for full-tunnel traffic also uses tunnel DNS.
                dnsSettings.matchDomains = [""]
                settings.dnsSettings = dnsSettings
            }
        }
        settings.proxySettings = Self.disabledProxySettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                NSLog("OpenPPP2 PacketTunnel setTunnelNetworkSettings failed: %@", error.localizedDescription)
                self?.stopNetworkPathMonitor()
                completionHandler(error)
                return
            }

            guard let self else {
                completionHandler(nil)
                return
            }

            let adapter = OpenPPP2PacketTunnelAdapter(provider: self, flow: self.packetFlow, telemetry: telemetry, debug: debug)
            guard adapter.start(configJson: preparedConfigJson, options: launchOptions) else {
                let lastError = openPPP2LastErrorText()
                self.stopNetworkPathMonitor()
                self.lastDiagnosticsJson = Self.diagnosticsJson(
                    linkState: 6,
                    startStage: "engine start failed",
                    lastError: lastError,
                    serverHost: serverHost,
                    options: launchOptions
                )
                NSLog("OpenPPP2 PacketTunnel engine start failed: %@", lastError)
                completionHandler(NSError(
                    domain: "OpenPPP2PacketTunnel",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Unable to start OpenPPP2 tunnel engine: \(lastError)"]
                ))
                return
            }

            if debug.packetFlowConsoleLoggingEnabled {
                NSLog("OpenPPP2 PacketTunnel engine started")
            }
            self.adapter = adapter
            self.lastDiagnosticsJson = adapter.diagnosticsJson()
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        if debugSettings.packetFlowConsoleLoggingEnabled {
            NSLog("OpenPPP2 PacketTunnel stop reason=%d (%@)", reason.rawValue, reason.telemetryLabel)
        }
        TunnelSharedState.writeLastTunnelStopReason(code: reason.rawValue, name: reason.telemetryLabel)

        let stopAttributes = adapter?.telemetryStopAttributes() ?? [:]
        adapter?.stop(stopReason: Int32(reason.rawValue))
        adapter = nil
        stopNetworkPathMonitor()

        NativeTelemetryTransport.exportStopEvent(
            settings: telemetrySettings,
            reason: reason,
            extraAttributes: stopAttributes
        )
        NativeTelemetryTransport.flushPendingUploads(timeout: 0.5)
        TunnelSharedState.clearSession()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let command = try? JSONDecoder().decode(ProviderCommand.self, from: messageData) {
            handle(command: command, completionHandler: completionHandler)
            return
        }

        guard let command = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        switch command {
        case "linkState":
            let state = adapter?.linkState() ?? 2
            completionHandler?("\(state)".data(using: .utf8))
        case "lastError":
            completionHandler?(openPPP2LastErrorText().data(using: .utf8))
        case "diagnostics":
            if let diagnostics = adapter?.diagnosticsJson() {
                lastDiagnosticsJson = diagnostics
                completionHandler?(diagnostics.data(using: .utf8))
            } else {
                completionHandler?(lastDiagnosticsJson.data(using: .utf8))
            }
        case "crashReports":
            completionHandler?(CrashReporter.encodedStoreSnapshot(for: .packetTunnel))
        case "deleteCrashReports":
            CrashReporter.deleteReports(for: .packetTunnel)
            completionHandler?(CrashReporter.encodedStoreSnapshot(for: .packetTunnel))
        default:
            completionHandler?(nil)
        }
    }

    private func handle(command: ProviderCommand, completionHandler: ((Data?) -> Void)?) {
        switch command.command {
        case "uploadCrashReports":
            let settings = command.telemetry ?? telemetrySettings
            CrashReporter.uploadReports(for: .packetTunnel, settings: settings) { summary in
                completionHandler?(CrashReporter.encodedUploadSummary(summary))
            }
        default:
            completionHandler?(nil)
        }
    }

    private func startNetworkPathMonitor(settings: TelemetrySettings) {
        stopNetworkPathMonitor()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            let snapshot = TunnelSharedState.NetworkPathSnapshot(path: path)
            TunnelSharedState.writeNetworkPathSnapshot(snapshot)
            Self.exportNetworkPathChanged(snapshot, settings: settings)
        }
        monitor.start(queue: networkPathQueue)
        networkPathMonitor = monitor
    }

    private func stopNetworkPathMonitor() {
        networkPathMonitor?.cancel()
        networkPathMonitor = nil
    }

    private static func exportNetworkPathChanged(
        _ snapshot: TunnelSharedState.NetworkPathSnapshot,
        settings: TelemetrySettings
    ) {
        guard settings.canUpload, settings.includeNativeTelemetry else {
            return
        }

        let interfaceText = snapshot.interfaces.joined(separator: ",")
        let record = OTLPLogRecord(
            timeUnixNano: UInt64(Date().timeIntervalSince1970 * 1_000_000_000),
            severityText: "INFO",
            body: "network_path changed status=\(snapshot.status) interfaces=\(interfaceText)",
            attributes: [
                "event.name": .string("openppp2.network_path.changed"),
                "openppp2.component": .string("packet_tunnel"),
                "openppp2.network_path.status": .string(snapshot.status),
                "openppp2.network_path.interfaces": .string(interfaceText),
                "openppp2.network_path.expensive": .bool(snapshot.isExpensive),
                "openppp2.network_path.constrained": .bool(snapshot.isConstrained),
                "openppp2.network_path.supports_ipv4": .bool(snapshot.supportsIPv4),
                "openppp2.network_path.supports_ipv6": .bool(snapshot.supportsIPv6),
                "openppp2.network_path.supports_dns": .bool(snapshot.supportsDNS)
            ]
        )
        OTLPHTTPLogExporter(settings: settings, scopeName: "openppp2.ios.network_path")
            .export(records: [record]) { result in
                if case let .failure(error) = result {
                    NSLog("OpenPPP2 network path telemetry failed: %@", error.localizedDescription)
                }
            }
    }

    private static func configurationError(_ message: String) -> NSError {
        NSError(
            domain: "OpenPPP2PacketTunnel",
            code: 1001,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    private static func readOptions(from providerConfiguration: [String: Any]?) -> PacketTunnelOptions {
        guard let raw = providerConfiguration?["optionsJson"] as? String,
              let data = raw.data(using: .utf8),
              let options = try? JSONDecoder().decode(PacketTunnelOptions.self, from: data)
        else {
            return PacketTunnelOptions()
        }
        return options
    }

    private static func readTelemetry(from providerConfiguration: [String: Any]?) -> TelemetrySettings {
        guard let raw = providerConfiguration?["telemetryJson"] as? String,
              let data = raw.data(using: .utf8),
              let settings = try? JSONDecoder().decode(TelemetrySettings.self, from: data)
        else {
            return .disabled
        }
        return settings
    }

    private static func readDebug(from providerConfiguration: [String: Any]?) -> DebugSettings {
        guard let raw = providerConfiguration?["debugJson"] as? String,
              let data = raw.data(using: .utf8),
              let settings = try? JSONDecoder().decode(DebugSettings.self, from: data)
        else {
            return DebugSettings()
        }
        return settings
    }

    private static func effectiveProviderConfiguration(from providerConfiguration: [String: Any]?) -> [String: Any]? {
        if let providerConfiguration,
           let configJson = providerConfiguration["configJson"] as? String,
           !configJson.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           configJson != "{}" {
            var configuration = providerConfiguration
            configuration["configurationSource"] = "provider"
            return configuration
        }

        guard let shared = TunnelSharedState.readLastTunnelConfiguration() else {
            return providerConfiguration
        }

        NSLog("OpenPPP2 PacketTunnel using shared last tunnel configuration profile=%@", shared.profileName)
        return [
            "profileId": shared.profileId,
            "profileName": shared.profileName,
            "configJson": shared.configJson,
            "optionsJson": shared.optionsJson,
            "telemetryJson": shared.telemetryJson,
            "debugJson": shared.debugJson ?? "{}",
            "configurationSource": "app-group"
        ]
    }

    private static func preparedConfigJson(_ rawJson: String) -> String {
        let rootDirectory = prepareRuntimeRoot()
        guard let data = rawJson.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              var root = object as? [String: Any]
        else {
            return rawJson
        }

        var geo = root["geo-rules"] as? [String: Any] ?? [:]
        if let rulesDirectory = rootDirectory?.appendingPathComponent("rules", isDirectory: true) {
            geo["geoip-dat"] = rulesDirectory.appendingPathComponent("GeoIP.dat").path
            geo["geosite-dat"] = rulesDirectory.appendingPathComponent("GeoSite.dat").path
        }
        root["geo-rules"] = geo

        guard JSONSerialization.isValidJSONObject(root),
              let output = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]),
              let text = String(data: output, encoding: .utf8)
        else {
            return rawJson
        }
        return text
    }

    @discardableResult
    private static func prepareRuntimeRoot() -> URL? {
        let fileManager = FileManager.default
        guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return nil
        }

        let rulesDirectory = documents.appendingPathComponent("rules", isDirectory: true)
        do {
            try fileManager.createDirectory(at: rulesDirectory, withIntermediateDirectories: true)
            for strayName in ["GeoIP.dat", "GeoSite.dat"] {
                let stray = documents.appendingPathComponent(strayName)
                var isDirectory: ObjCBool = false
                if fileManager.fileExists(atPath: stray.path, isDirectory: &isDirectory), isDirectory.boolValue {
                    try fileManager.removeItem(at: stray)
                }
            }
            try copyBundledRule(named: "geoip", outputName: "GeoIP.dat", to: rulesDirectory)
            try copyBundledRule(named: "geosite", outputName: "GeoSite.dat", to: rulesDirectory)
        } catch {
            NSLog("OpenPPP2 prepareRuntimeRoot failed: %@", error.localizedDescription)
        }
        return documents
    }

    private static func copyBundledRule(named resourceName: String, outputName: String, to directory: URL) throws {
        guard let source = Bundle.main.url(forResource: resourceName, withExtension: "dat", subdirectory: "rules") else {
            return
        }

        let destination = directory.appendingPathComponent(outputName)
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: destination.path, isDirectory: &isDirectory) {
            if isDirectory.boolValue {
                try FileManager.default.removeItem(at: destination)
            } else {
                let attributes = try? FileManager.default.attributesOfItem(atPath: destination.path)
                if let size = attributes?[.size] as? NSNumber, size.int64Value > 0 {
                    return
                }
                try FileManager.default.removeItem(at: destination)
            }
        }

        try FileManager.default.copyItem(at: source, to: destination)
    }

    private static func serverHost(from json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              let client = root["client"] as? [String: Any],
              let server = client["server"] as? String,
              let url = URL(string: server),
              let host = url.host,
              !host.isEmpty
        else {
            return nil
        }

        return host
    }

    private static func telemetryEndpointHost(from json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              let telemetry = root["telemetry"] as? [String: Any],
              let endpoint = telemetry["endpoint"] as? String,
              !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let components = URLComponents(string: endpoint),
              let host = components.host,
              !host.isEmpty
        else {
            return nil
        }
        return host
    }

    private static func excludedRoutes(
        from text: String,
        serverHost: String?,
        resolvedServerIPv4Addresses: [String],
        extraHosts: [String] = [],
        extraResolvedIPv4Addresses: [String] = []
    ) -> [NEIPv4Route] {
        var routes = text
            .components(separatedBy: .newlines)
            .compactMap { line -> NEIPv4Route? in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else { return nil }
                let parts = trimmed.split(separator: "/", maxSplits: 1).map(String.init)
                let address = parts[0]
                let prefix = parts.count == 2 ? (Int(parts[1]) ?? 32) : 32
                return NEIPv4Route(destinationAddress: address, subnetMask: mask(prefix: prefix))
            }

        var excludedHostIps = Set(resolvedServerIPv4Addresses.filter { isIPv4Address($0) })
        excludedHostIps.formUnion(extraResolvedIPv4Addresses.filter { isIPv4Address($0) })
        if let serverHost, isIPv4Address(serverHost) {
            excludedHostIps.insert(serverHost)
        }
        for host in extraHosts where isIPv4Address(host) {
            excludedHostIps.insert(host)
        }
        for ip in excludedHostIps {
            routes.append(NEIPv4Route(destinationAddress: ip, subnetMask: mask(prefix: 32)))
        }
        return routes
    }

    private static func resolveIPv4Addresses(for host: String?) -> [String] {
        guard let host, !host.isEmpty, !isIPv4Address(host) else {
            return []
        }

        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var info: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &info)
        guard status == 0, let firstInfo = info else {
            return []
        }
        defer { freeaddrinfo(firstInfo) }

        var addresses = Set<String>()
        var cursor: UnsafeMutablePointer<addrinfo>? = firstInfo
        while let current = cursor {
            if current.pointee.ai_family == AF_INET,
               let rawAddress = current.pointee.ai_addr {
                let sin = rawAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var addr = sin.sin_addr
                var hostBuffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr, &hostBuffer, socklen_t(hostBuffer.count)) != nil {
                    addresses.insert(String(cString: hostBuffer))
                }
            }
            cursor = current.pointee.ai_next
        }
        return Array(addresses)
    }

    private static func isIPv4Address(_ text: String) -> Bool {
        var address = in_addr()
        return text.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func disabledProxySettings() -> NEProxySettings {
        let settings = NEProxySettings()
        settings.httpEnabled = false
        settings.httpsEnabled = false
        settings.autoProxyConfigurationEnabled = false
        return settings
    }

    private static func diagnosticsJson(
        linkState: Int,
        startStage: String,
        lastError: String,
        serverHost: String?,
        options: PacketTunnelOptions
    ) -> String {
        var payload: [String: Any] = [
            "linkState": linkState,
            "startStage": startStage,
            "lastError": lastError,
            "serverHost": serverHost ?? "",
            "tunIp": options.tunIp,
            "route": "\(options.route)/\(options.routePrefix)",
            "routeMode": options.routeMode,
            "dataplane": options.lwip ? "lwip" : "ctcp"
        ]
        if let networkPath = TunnelSharedState.readNetworkPathSnapshot() {
            payload["networkPath"] = networkPath.dictionary
        }

        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8)
        else {
            return "{}"
        }
        return text
    }

    private static func mask(prefix: Int) -> String {
        let clamped = max(0, min(prefix, 32))
        let value = clamped == 0 ? UInt32(0) : UInt32.max << UInt32(32 - clamped)
        return [24, 16, 8, 0]
            .map { String((value >> UInt32($0)) & 0xff) }
            .joined(separator: ".")
    }
}
