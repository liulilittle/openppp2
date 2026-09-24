import Foundation
import Network
import NetworkExtension

// MARK: - VPN Controller

enum VPNReconnectError: LocalizedError {
    case teardownTimeout

    var errorDescription: String? {
        L10n.tr("vpn.error.teardownTimeout")
    }
}

final class VPNController {
    static let shared = VPNController()
    static let didChangeNotification = Notification.Name("OpenPPP2VPNControllerDidChange")
    private static let pathReconnectDebounce: TimeInterval = 10
    private static let pathRecoveryUnexpectedDisconnectWindow: TimeInterval = 120

    private var manager: NETunnelProviderManager?
    private(set) var status: NEVPNStatus = .invalid
    private(set) var lastError: String?
    private(set) var diagnostics = VpnDiagnostics.empty
    private(set) var networkPath: TunnelSharedState.NetworkPathSnapshot?
    private var lastStatusBeforeChange: NEVPNStatus = .invalid
    private let networkPathMonitor = NWPathMonitor()
    private let networkPathQueue = DispatchQueue(label: "openppp2.network-path")
    private var lastNetworkPathStatus: String?
    private var reconnectWhenPathRecovers = false
    private var pathReconnectInFlight = false
    private var lastPathReconnectAt: Date?
    private var lastUnexpectedDisconnectAt: Date?
    private var userRequestedDisconnect = false
#if targetEnvironment(simulator)
    private var simulatorPreviewConnected = false
#endif

    private init() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(statusDidChange),
            name: .NEVPNStatusDidChange,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(savedConfigurationDidChange),
            name: ProfileStore.didChangeNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(savedConfigurationDidChange),
            name: TelemetrySettingsStore.didChangeNotification,
            object: nil
        )
        startNetworkPathMonitor()
    }

    var isActive: Bool {
        status == .connected
    }

    var requiresRestartToApplyConfiguration: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    func recoverStaleTunnelState() {
#if targetEnvironment(simulator)
        return
#else
        refresh { [weak self] in
            guard let self else { return }
            let active = self.status == .connecting || self.status == .connected || self.status == .reasserting
            if active, !TunnelSharedState.isExtensionAlive() {
                NSLog("OpenPPP2 recovering stale VPN state (NE status=%d)", self.status.rawValue)
                self.manager?.connection.stopVPNTunnel()
                TunnelSharedState.clearSession()
                self.lastError = L10n.tr("vpn.error.staleSessionRecovered")
                self.status = .disconnected
                self.diagnostics = .empty
                self.emitChange()
            } else if !active {
                TunnelSharedState.clearSession()
            }
        }
#endif
    }

    func refresh(completion: (() -> Void)? = nil) {
#if targetEnvironment(simulator)
        status = simulatorPreviewConnected ? .connected : .disconnected
        emitChange()
        completion?()
#else
        loadManager { [weak self] manager, _ in
            self?.manager = manager
            self?.lastStatusBeforeChange = self?.status ?? .invalid
            self?.status = manager?.connection.status ?? .disconnected
            if self?.status == .disconnected || self?.status == .invalid {
                self?.diagnostics = .empty
            }
            self?.emitChange()
            completion?()
        }
#endif
    }

    func connect(profile: ConfigProfile, completion: @escaping (Result<Void, Error>) -> Void) {
#if targetEnvironment(simulator)
        simulatorPreviewConnected = true
        lastError = nil
        lastStatusBeforeChange = status
        status = .connected
        emitChange()
        completion(.success(()))
#else
        if let error = Self.configurationError(for: profile) {
            record(error)
            completion(.failure(error))
            return
        }

        let telemetry = TelemetrySettingsStore.shared.settings()
        let providerConfiguration = Self.providerConfiguration(for: profile, telemetry: telemetry)
        let serverAddress = Self.systemServerAddress(for: profile)
        userRequestedDisconnect = false
        reconnectWhenPathRecovers = false
        lastUnexpectedDisconnectAt = nil
        TunnelSharedState.clearLastTunnelStopReason()
        Self.persistLastTunnelConfiguration(for: profile, telemetry: telemetry)
        loadManager { [weak self] manager, error in
            if let error {
                self?.record(error)
                completion(.failure(error))
                return
            }

            let manager = manager ?? NETunnelProviderManager()
            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleIdentifier
            proto.serverAddress = serverAddress
            proto.providerConfiguration = providerConfiguration
            manager.localizedDescription = "OpenPPP2"
            manager.protocolConfiguration = proto
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if let saveError {
                    self?.record(saveError, context: L10n.tr("vpn.error.saveConfig"))
                    completion(.failure(saveError))
                    return
                }

                manager.loadFromPreferences { loadError in
                    if let loadError {
                        self?.record(loadError, context: L10n.tr("vpn.error.reloadConfig"))
                        completion(.failure(loadError))
                        return
                    }

                    do {
                        try manager.connection.startVPNTunnel()
                        self?.manager = manager
                        self?.lastError = nil
                        self?.diagnostics = .empty
                        self?.lastStatusBeforeChange = self?.status ?? .invalid
                        self?.status = manager.connection.status
                        self?.emitChange()
                        completion(.success(()))
                    } catch {
                        self?.record(error, context: L10n.tr("vpn.error.startTunnel"))
                        completion(.failure(error))
                    }
                }
            }
        }
#endif
    }

    func syncActiveProfileToSystemPreferences(completion: ((Result<Void, Error>) -> Void)? = nil) {
#if targetEnvironment(simulator)
        completion?(.success(()))
#else
        guard let profile = ProfileStore.shared.activeProfile() else {
            completion?(.success(()))
            return
        }
        if let error = Self.configurationError(for: profile) {
            record(error)
            completion?(.failure(error))
            return
        }

        let telemetry = TelemetrySettingsStore.shared.settings()
        let providerConfiguration = Self.providerConfiguration(for: profile, telemetry: telemetry)
        let serverAddress = Self.systemServerAddress(for: profile)
        Self.persistLastTunnelConfiguration(for: profile, telemetry: telemetry)

        loadManager { [weak self] manager, error in
            if let error {
                NSLog("OpenPPP2 failed to load VPN preferences for sync: %@", error.localizedDescription)
                completion?(.failure(error))
                return
            }

            guard let manager else {
                NSLog("OpenPPP2 skipped VPN preferences sync because no manager exists yet")
                completion?(.success(()))
                return
            }

            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleIdentifier
            proto.serverAddress = serverAddress
            proto.providerConfiguration = providerConfiguration
            manager.localizedDescription = "OpenPPP2"
            manager.protocolConfiguration = proto
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if let saveError {
                    self?.logConfigurationError(saveError, context: L10n.tr("vpn.error.syncConfig"))
                    DispatchQueue.main.async {
                        completion?(.failure(saveError))
                    }
                    return
                }

                manager.loadFromPreferences { loadError in
                    DispatchQueue.main.async {
                        if let loadError {
                            self?.logConfigurationError(loadError, context: L10n.tr("vpn.error.reloadSyncedConfig"))
                            completion?(.failure(loadError))
                            return
                        }

                        self?.manager = manager
                        NSLog("OpenPPP2 synced VPN preferences for Control Center profile=%@", profile.name)
                        completion?(.success(()))
                    }
                }
            }
        }
#endif
    }

    func reconnect(profile: ConfigProfile, completion: @escaping (Result<Void, Error>) -> Void) {
#if targetEnvironment(simulator)
        connect(profile: profile, completion: completion)
#else
        guard requiresRestartToApplyConfiguration || status == .disconnecting else {
            connect(profile: profile, completion: completion)
            return
        }
        if let error = Self.configurationError(for: profile) {
            record(error)
            completion(.failure(error))
            return
        }

        disconnect()
        waitForDisconnectThenConnect(profile: profile, attemptsRemaining: 40, completion: completion)
#endif
    }

    func disconnect() {
#if targetEnvironment(simulator)
        simulatorPreviewConnected = false
        userRequestedDisconnect = true
        lastStatusBeforeChange = status
        status = .disconnected
        reconnectWhenPathRecovers = false
        pathReconnectInFlight = false
        emitChange()
#else
        userRequestedDisconnect = true
        manager?.connection.stopVPNTunnel()
        lastStatusBeforeChange = status
        status = manager?.connection.status ?? .disconnected
        diagnostics = .empty
        reconnectWhenPathRecovers = false
        pathReconnectInFlight = false
        lastUnexpectedDisconnectAt = nil
        emitChange()
#endif
    }

    func fetchLinkState(completion: @escaping (Int) -> Void) {
#if targetEnvironment(simulator)
        completion(simulatorPreviewConnected ? 0 : 6)
#else
        if let shared = TunnelSharedState.readLinkStateIfAlive() {
            noteObservedLinkState(shared)
            completion(shared)
            return
        }

        sendProviderMessage("linkState") { [weak self] data in
            guard let data,
                  let raw = String(data: data, encoding: .utf8),
                  let state = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines))
            else {
                completion(6)
                return
            }
            self?.noteObservedLinkState(state)
            completion(state)
        }
#endif
    }

    func fetchDiagnostics(completion: @escaping (VpnDiagnostics) -> Void) {
#if targetEnvironment(simulator)
        completion(.empty)
#else
        if let json = TunnelSharedState.readDiagnosticsJson() {
            let diagnostics = VpnDiagnostics(jsonText: json)
            self.diagnostics = diagnostics
            if !diagnostics.meaningfulLastError.isEmpty {
                lastError = diagnostics.meaningfulLastError
            }
            emitChange()
            completion(diagnostics)
            return
        }

        sendProviderMessage("diagnostics") { [weak self] data in
            guard let data,
                  let raw = String(data: data, encoding: .utf8),
                  !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            else {
                completion(self?.diagnostics ?? .empty)
                return
            }

            let diagnostics = VpnDiagnostics(jsonText: raw)
            self?.diagnostics = diagnostics
            if !diagnostics.meaningfulLastError.isEmpty {
                self?.lastError = diagnostics.meaningfulLastError
            }
            self?.emitChange()
            completion(diagnostics)
        }
#endif
    }

    func fetchPacketTunnelCrashReports(completion: @escaping (CrashReporter.StoreSnapshot?) -> Void) {
#if targetEnvironment(simulator)
        completion(CrashReporter.StoreSnapshot(process: .packetTunnel, reportIDs: []))
#else
        sendProviderMessage("crashReports") { data in
            completion(CrashReporter.decodedStoreSnapshot(from: data))
        }
#endif
    }

    func deletePacketTunnelCrashReports(completion: (() -> Void)? = nil) {
#if targetEnvironment(simulator)
        completion?()
#else
        sendProviderMessage("deleteCrashReports") { _ in
            completion?()
        }
#endif
    }

    func uploadPacketTunnelCrashReports(
        settings: TelemetrySettings,
        completion: @escaping (TelemetryUploadSummary?) -> Void
    ) {
#if targetEnvironment(simulator)
        completion(TelemetryUploadSummary())
#else
        let command = ProviderCommand(command: "uploadCrashReports", telemetry: settings)
        sendProviderCommand(command) { data in
            completion(CrashReporter.decodedUploadSummary(from: data))
        }
#endif
    }

    private func loadManager(completion: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                DispatchQueue.main.async { completion(nil, error) }
                return
            }

            let manager = managers?.first { existing in
                guard let proto = existing.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return proto.providerBundleIdentifier == Self.providerBundleIdentifier
            }
            DispatchQueue.main.async { completion(manager, nil) }
        }
    }

    private func sendProviderMessage(_ command: String, completion: @escaping (Data?) -> Void) {
        sendProviderData(command.data(using: .utf8), completion: completion)
    }

    private func sendProviderCommand(_ command: ProviderCommand, completion: @escaping (Data?) -> Void) {
        sendProviderData(try? JSONEncoder().encode(command), completion: completion)
    }

    private func sendProviderData(_ data: Data?, completion: @escaping (Data?) -> Void) {
        let send: (NETunnelProviderManager?) -> Void = { manager in
            guard let session = manager?.connection as? NETunnelProviderSession,
                  manager?.connection.status == .connected,
                  let data
            else {
                completion(nil)
                return
            }

            do {
                try session.sendProviderMessage(data) { response in
                    DispatchQueue.main.async {
                        completion(response)
                    }
                }
            } catch {
                self.record(error)
                completion(nil)
            }
        }

        if let manager {
            send(manager)
        } else {
            loadManager { [weak self] manager, _ in
                self?.manager = manager
                send(manager)
            }
        }
    }

    private func waitForDisconnectThenConnect(
        profile: ConfigProfile,
        attemptsRemaining: Int,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            self.refresh {
                let extensionDead = !TunnelSharedState.isExtensionAlive()
                let neReady = self.status == .disconnected || self.status == .invalid
                if neReady && extensionDead {
                    self.connect(profile: profile, completion: completion)
                } else if attemptsRemaining <= 0 {
                    self.record(VPNReconnectError.teardownTimeout)
                    completion(.failure(VPNReconnectError.teardownTimeout))
                } else {
                    self.waitForDisconnectThenConnect(
                        profile: profile,
                        attemptsRemaining: attemptsRemaining - 1,
                        completion: completion
                    )
                }
            }
        }
    }

    @objc private func statusDidChange(_ notification: Notification) {
        guard let connection = notification.object as? NEVPNConnection else { return }
        lastStatusBeforeChange = status
        status = connection.status
        if status == .disconnected,
           (lastStatusBeforeChange == .connecting || lastStatusBeforeChange == .reasserting),
           lastError == nil {
            lastError = L10n.tr("vpn.error.packetTunnelStartFailed")
        }
        if status == .disconnected || status == .invalid {
            if userRequestedDisconnect || Self.lastStopWasUserInitiated() {
                reconnectWhenPathRecovers = false
                lastUnexpectedDisconnectAt = nil
            } else if Self.isActiveStatus(lastStatusBeforeChange), networkPath?.isUnavailable == true {
                lastUnexpectedDisconnectAt = Date()
                reconnectWhenPathRecovers = true
            } else if Self.isActiveStatus(lastStatusBeforeChange) {
                lastUnexpectedDisconnectAt = Date()
                reconnectWhenPathRecovers = true
            } else {
                reconnectWhenPathRecovers = false
            }
            diagnostics = .empty
        } else if Self.isActiveStatus(status) {
            userRequestedDisconnect = false
            lastUnexpectedDisconnectAt = nil
            TunnelSharedState.clearLastTunnelStopReason()
            if networkPath?.isUnavailable == true {
                reconnectWhenPathRecovers = true
            }
        }
        emitChange()
    }

    @objc private func savedConfigurationDidChange(_ notification: Notification) {
        if let reason = notification.userInfo?[ProfileStore.changeReasonUserInfoKey] as? String,
           reason == ProfileStore.ChangeReason.debugPanel.rawValue {
            return
        }
        syncActiveProfileToSystemPreferences()
    }

    private func record(_ error: Error, context: String? = nil) {
        logConfigurationError(error, context: context)
        if let context {
            lastError = "\(context): \(error.localizedDescription)"
        } else {
            lastError = error.localizedDescription
        }
        emitChange()
    }

    private func noteObservedLinkState(_ state: Int) {
        guard state == 0, lastError != nil else {
            return
        }
        lastError = nil
        emitChange()
    }

    private func logConfigurationError(_ error: Error, context: String? = nil) {
        let nsError = error as NSError
        let contextText = context ?? L10n.tr("vpn.error.operationFailed")
        NSLog(
            "OpenPPP2 %@ domain=%@ code=%ld description=%@",
            contextText,
            nsError.domain,
            nsError.code,
            nsError.localizedDescription
        )
    }

    private func emitChange() {
        NotificationCenter.default.post(name: Self.didChangeNotification, object: self)
    }

    private func startNetworkPathMonitor() {
        networkPathMonitor.pathUpdateHandler = { [weak self] path in
            let snapshot = TunnelSharedState.NetworkPathSnapshot(path: path)
            DispatchQueue.main.async {
                self?.handleNetworkPath(snapshot)
            }
        }
        networkPathMonitor.start(queue: networkPathQueue)
    }

    private func handleNetworkPath(_ snapshot: TunnelSharedState.NetworkPathSnapshot) {
        let previousStatus = lastNetworkPathStatus
        lastNetworkPathStatus = snapshot.status
        networkPath = snapshot
        TunnelSharedState.writeNetworkPathSnapshot(snapshot)

        if snapshot.isUnavailable, (Self.isActiveStatus(status) || hasRecentUnexpectedDisconnect) {
            reconnectWhenPathRecovers = true
        }

        if let previousStatus,
           previousStatus != snapshot.status,
           Self.isUnavailablePathStatus(previousStatus),
           snapshot.isSatisfied {
            reconnectAfterPathRecoveryIfNeeded(snapshot)
        }
        emitChange()
    }

    private func reconnectAfterPathRecoveryIfNeeded(_ snapshot: TunnelSharedState.NetworkPathSnapshot) {
        guard let profile = ProfileStore.shared.activeProfile(),
              ProfileStore.shared.launchOptions().autoReconnectOnPathRecovery
        else {
            reconnectWhenPathRecovers = false
            return
        }
        guard reconnectWhenPathRecovers || Self.isActiveStatus(status) || hasRecentUnexpectedDisconnect else {
            return
        }
        guard !userRequestedDisconnect, !Self.lastStopWasUserInitiated() else {
            reconnectWhenPathRecovers = false
            return
        }
        guard !pathReconnectInFlight else {
            return
        }

        let now = Date()
        if let lastPathReconnectAt,
           now.timeIntervalSince(lastPathReconnectAt) < Self.pathReconnectDebounce {
            return
        }

        reconnectWhenPathRecovers = false
        pathReconnectInFlight = true
        lastPathReconnectAt = now
        lastUnexpectedDisconnectAt = nil
        exportNetworkPathReconnectRequested(snapshot: snapshot, profile: profile)
        reconnect(profile: profile) { [weak self] result in
            DispatchQueue.main.async {
                self?.pathReconnectInFlight = false
                if case let .failure(error) = result {
                    self?.record(error)
                }
            }
        }
    }

    private func exportNetworkPathReconnectRequested(
        snapshot: TunnelSharedState.NetworkPathSnapshot,
        profile: ConfigProfile
    ) {
        let settings = TelemetrySettingsStore.shared.settings()
        guard settings.canUpload, settings.includeNativeTelemetry else {
            return
        }

        let interfaceText = snapshot.interfaces.joined(separator: ",")
        let record = OTLPLogRecord(
            timeUnixNano: UInt64(Date().timeIntervalSince1970 * 1_000_000_000),
            severityText: "INFO",
            body: "network_path reconnect_requested status=\(snapshot.status) interfaces=\(interfaceText)",
            attributes: [
                "event.name": .string("openppp2.network_path.reconnect_requested"),
                "openppp2.component": .string("app"),
                "openppp2.profile.id": .string(profile.id),
                "openppp2.profile.name": .string(profile.name),
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
                    NSLog("OpenPPP2 network path reconnect telemetry failed: %@", error.localizedDescription)
                }
            }
    }

    private static func isActiveStatus(_ status: NEVPNStatus) -> Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    private static func configurationError(for profile: ConfigProfile) -> Error? {
        guard profile.serverHost?.isEmpty == false else {
            return NSError.openPPP2(L10n.tr("vpn.error.missingServer"))
        }
        return nil
    }

    private static func systemServerAddress(for profile: ConfigProfile) -> String {
        profile.serverHost ?? "OpenPPP2"
    }

    private static func isUnavailablePathStatus(_ status: String) -> Bool {
        status == "unsatisfied" || status == "requiresConnection"
    }

    private var hasRecentUnexpectedDisconnect: Bool {
        guard let lastUnexpectedDisconnectAt else {
            return false
        }
        return Date().timeIntervalSince(lastUnexpectedDisconnectAt) <= Self.pathRecoveryUnexpectedDisconnectWindow
    }

    private static func lastStopWasUserInitiated() -> Bool {
        guard let reason = TunnelSharedState.readLastTunnelStopReason() else {
            return false
        }
        return reason.code == NEProviderStopReason.userInitiated.rawValue
            || reason.name == "user_initiated"
    }

    private static var providerBundleIdentifier: String {
        "\(Bundle.main.bundleIdentifier ?? "com.tunnel.openppp2").PacketTunnel"
    }

    private static func encodeOptions(_ options: LaunchOptions) -> String {
        guard let data = try? JSONEncoder().encode(options),
              let raw = String(data: data, encoding: .utf8)
        else { return "{}" }
        return raw
    }

    private static func encodeTelemetry(_ settings: TelemetrySettings) -> String {
        guard let data = try? JSONEncoder().encode(settings),
              let raw = String(data: data, encoding: .utf8)
        else { return "{}" }
        return raw
    }

    private static func encodeDebug(_ settings: DebugSettings) -> String {
        guard let data = try? JSONEncoder().encode(settings),
              let raw = String(data: data, encoding: .utf8)
        else { return "{}" }
        return raw
    }

    private static func providerConfiguration(for profile: ConfigProfile, telemetry: TelemetrySettings) -> [String: Any] {
        let options = ProfileStore.shared.launchOptions()
        let debug = ProfileStore.shared.debugSettings()
        return [
            "profileId": profile.id,
            "profileName": profile.name,
            "configJson": "{}",
            "optionsJson": encodeOptions(options),
            "telemetryJson": encodeTelemetry(telemetry),
            "debugJson": encodeDebug(debug),
            "configurationSource": "app-group-pointer"
        ]
    }

    private static func persistLastTunnelConfiguration(for profile: ConfigProfile, telemetry: TelemetrySettings) {
        let options = ProfileStore.shared.launchOptions()
        let effectiveJson = ProfileStore.effectiveJson(profile.json, options: options, telemetry: telemetry)
        let debug = ProfileStore.shared.debugSettings()
        TunnelSharedState.writeLastTunnelConfiguration(TunnelSharedState.LastTunnelConfiguration(
            profileId: profile.id,
            profileName: profile.name,
            serverAddress: systemServerAddress(for: profile),
            configJson: effectiveJson,
            optionsJson: encodeOptions(options),
            telemetryJson: encodeTelemetry(telemetry),
            debugJson: encodeDebug(debug),
            updatedAtMs: Int64(Date().timeIntervalSince1970 * 1000)
        ))
    }
}
