import Foundation

// MARK: - Store

final class ProfileStore {
    static let shared = ProfileStore()
    static let didChangeNotification = Notification.Name("OpenPPP2ProfileStoreDidChange")
    static let changeReasonUserInfoKey = "reason"

    enum ChangeReason: String {
        case profiles
        case launchOptions
        case debugPanel
        case packetTunnelDebug
    }

    private let defaults = UserDefaults.standard
    private let profilesKey = "openppp2_profiles_v2"
    private let launchOptionsKey = "openppp2_launch_options_v1"
    private let activeIdKey = "openppp2_active_profile_id"
    private let debugPanelKey = "openppp2_debug_panel_enabled"
    private let packetFlowDiagnosticsKey = "openppp2_packet_flow_diagnostics_enabled"
    private let packetFlowConsoleLoggingKey = "openppp2_packet_flow_console_logging_enabled"
    private let packetFlowTelemetryKey = "openppp2_packet_flow_telemetry_enabled"
    private let defaultServerPresetKey = "openppp2_default_server_preset_v5"
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    private init() {}

    func profiles() -> [ConfigProfile] {
        ensureSeeded()
        guard let data = defaults.data(forKey: profilesKey),
              let list = try? decoder.decode([ConfigProfile].self, from: data)
        else {
            return []
        }
        return list
    }

    func activeProfile() -> ConfigProfile? {
        let list = profiles()
        guard !list.isEmpty else { return nil }
        let id = defaults.string(forKey: activeIdKey)
        return list.first(where: { $0.id == id }) ?? list.first
    }

    func setActive(_ id: String) {
        defaults.set(id, forKey: activeIdKey)
        emitChange()
    }

    func add(_ profile: ConfigProfile) {
        var list = profiles()
        list.append(profile)
        defaults.set(profile.id, forKey: activeIdKey)
        save(list)
    }

    @discardableResult
    func upsertSubscription(url: String, subscription: RemoteSubscriptionResult) -> Int {
        var list = profiles()
        let now = Int(Date().timeIntervalSince1970 * 1000)
        var changed = 0

        for node in subscription.nodes {
            if let index = list.firstIndex(where: { $0.subscriptionUrl == url && $0.subscriptionNodeId == node.id }) {
                var updated = list[index]
                if updated.json != node.json {
                    updated.history.insert(ConfigSnapshot(timestampMs: now, json: updated.json), at: 0)
                    if updated.history.count > ConfigProfile.historyLimit {
                        updated.history = Array(updated.history.prefix(ConfigProfile.historyLimit))
                    }
                }
                updated.name = node.name
                updated.subtitle = node.subtitle.isEmpty ? (Self.hostFromJson(node.json) ?? "") : node.subtitle
                updated.flag = node.flag
                updated.json = node.json
                updated.subscriptionUrl = url
                updated.subscriptionNodeId = node.id
                updated.subscriptionUpdatedAtMs = now
                if let options = node.options {
                    updated.options = options
                }
                list[index] = updated
            } else {
                list.append(ConfigProfile(
                    id: UUID().uuidString,
                    name: node.name,
                    subtitle: node.subtitle.isEmpty ? (Self.hostFromJson(node.json) ?? "") : node.subtitle,
                    flag: node.flag,
                    json: node.json,
                    favorite: false,
                    subscriptionUrl: url,
                    subscriptionNodeId: node.id,
                    subscriptionUpdatedAtMs: now,
                    options: node.options ?? LaunchOptions(),
                    history: []
                ))
            }
            changed += 1
        }

        if changed > 0 {
            save(list)
        }
        return changed
    }

    func update(_ profile: ConfigProfile, snapshot: Bool = true) {
        var list = profiles()
        guard let index = list.firstIndex(where: { $0.id == profile.id }) else {
            add(profile)
            return
        }

        var updated = profile
        let previous = list[index]
        if snapshot, previous.json != profile.json {
            updated.history.insert(
                ConfigSnapshot(timestampMs: Int(Date().timeIntervalSince1970 * 1000), json: previous.json),
                at: 0
            )
            if updated.history.count > ConfigProfile.historyLimit {
                updated.history = Array(updated.history.prefix(ConfigProfile.historyLimit))
            }
        }

        list[index] = updated
        save(list)
    }

    func remove(_ id: String) {
        var list = profiles()
        list.removeAll { $0.id == id }
        if list.isEmpty {
            list = [Self.defaultProfile()]
        }
        if defaults.string(forKey: activeIdKey) == id {
            defaults.set(list[0].id, forKey: activeIdKey)
        }
        save(list)
    }

    func debugPanelEnabled() -> Bool {
        defaults.bool(forKey: debugPanelKey)
    }

    func setDebugPanelEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: debugPanelKey)
        emitChange(reason: .debugPanel)
    }

    func debugSettings() -> DebugSettings {
        DebugSettings(
            packetFlowDiagnosticsEnabled: defaults.bool(forKey: packetFlowDiagnosticsKey),
            packetFlowConsoleLoggingEnabled: defaults.bool(forKey: packetFlowConsoleLoggingKey),
            packetFlowTelemetryEnabled: defaults.bool(forKey: packetFlowTelemetryKey)
        )
    }

    func setPacketFlowDiagnosticsEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: packetFlowDiagnosticsKey)
        emitChange(reason: .packetTunnelDebug)
    }

    func setPacketFlowConsoleLoggingEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: packetFlowConsoleLoggingKey)
        emitChange(reason: .packetTunnelDebug)
    }

    func setPacketFlowTelemetryEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: packetFlowTelemetryKey)
        emitChange(reason: .packetTunnelDebug)
    }

    func resetAll() {
        defaults.removeObject(forKey: profilesKey)
        defaults.removeObject(forKey: launchOptionsKey)
        defaults.removeObject(forKey: activeIdKey)
        ensureSeeded()
        emitChange()
    }

    func launchOptions() -> LaunchOptions {
        ensureSeeded()
        if let data = defaults.data(forKey: launchOptionsKey),
           let options = try? decoder.decode(LaunchOptions.self, from: data) {
            return options
        }

        let options = Self.migratedLaunchOptions(from: activeProfile())
        setLaunchOptions(options, notify: false)
        return options
    }

    func setLaunchOptions(_ options: LaunchOptions, notify: Bool = true) {
        if let data = try? encoder.encode(options) {
            defaults.set(data, forKey: launchOptionsKey)
        }
        if notify { emitChange(reason: .launchOptions) }
    }

    func exportBundle(includeActiveId: Bool = true) -> ProfileExportBundle {
        ProfileExportBundle(
            activeProfileId: includeActiveId ? activeProfile()?.id : nil,
            profiles: Self.profileOnlyCopies(profiles())
        )
    }

    func exportProfile(id: String) throws -> ProfileExportBundle {
        guard let profile = profiles().first(where: { $0.id == id }) else {
            throw ProfileImportExportError.profileNotFound
        }
        return ProfileExportBundle(profiles: [Self.profileOnlyCopy(profile)])
    }

    @discardableResult
    func importBundle(_ bundle: ProfileExportBundle, mode: ProfileImportMode) throws -> ProfileImportResult {
        try ProfileImportExportCodec.validate(bundle)

        var list = bundle.profiles
        var nextActiveId = defaults.string(forKey: activeIdKey)

        if mode == .replace && list.isEmpty {
            let fallback = Self.defaultProfile()
            list = [fallback]
            nextActiveId = fallback.id
            save(list)
            defaults.set(fallback.id, forKey: activeIdKey)
            return ProfileImportResult(importedCount: 0, updatedCount: 0, addedCount: 0)
        }

        let profileOnlyBundle = ProfileExportBundle(
            exportedAtMs: bundle.exportedAtMs,
            activeProfileId: bundle.activeProfileId,
            profiles: Self.profileOnlyCopies(bundle.profiles)
        )
        let applied = ProfileImportExportLogic.applyImport(
            bundle: profileOnlyBundle,
            mode: mode,
            existingProfiles: profiles(),
            activeProfileId: nextActiveId
        )
        save(applied.profiles)
        if mode == .replace, let activeId = applied.activeProfileId {
            defaults.set(activeId, forKey: activeIdKey)
        }
        return applied.result
    }

    static func defaultProfile() -> ConfigProfile {
        ConfigProfile(
            id: UUID().uuidString,
            name: defaultProfileName,
            subtitle: defaultServerSubtitle,
            flag: "",
            json: defaultJson,
            favorite: false,
            options: LaunchOptions(),
            history: []
        )
    }

    static func effectiveJson(_ profileJson: String, options: LaunchOptions) -> String {
        effectiveJson(profileJson, options: options, telemetry: .disabled)
    }

    static func effectiveJson(_ profileJson: String, options: LaunchOptions, telemetry: TelemetrySettings) -> String {
        let source = profileJson.data(using: .utf8) ?? Data()
        let defaultData = defaultJson.data(using: .utf8) ?? Data()
        let object = (try? JSONSerialization.jsonObject(with: source))
            ?? (try? JSONSerialization.jsonObject(with: defaultData))
            ?? [:]
        var root = object as? [String: Any] ?? [:]

        var dns = root["dns"] as? [String: Any] ?? [:]
        var servers = dns["servers"] as? [String: Any] ?? [:]
        if !options.dnsDomestic.isEmpty { servers["domestic"] = options.dnsDomestic }
        if !options.dnsForeign.isEmpty { servers["foreign"] = options.dnsForeign }
        dns["servers"] = servers
        dns["intercept-unmatched"] = options.dnsInterceptUnmatched
        dns["fake-ip"] = [
            "enabled": options.dnsFakeIpEnabled,
            "range": options.dnsFakeIpRange
        ]
        dns["ecs"] = [
            "enabled": options.dnsEcsEnabled,
            "override-ip": options.dnsEcsOverrideIp
        ]
        dns["tls"] = ["verify-peer": options.dnsTlsVerifyPeer]
        dns["stun"] = ["candidates": splitLines(options.dnsStunCandidates)]
        root["dns"] = dns

        var geo = root["geo-rules"] as? [String: Any] ?? [:]
        geo["enabled"] = options.effectiveGeoEnabled
        geo["country"] = options.geoCountry
        geo["geoip-dat"] = options.geoIpDat
        geo["geosite-dat"] = options.geoSiteDat
        root["geo-rules"] = geo

        var mux = root["mux"] as? [String: Any] ?? [:]
        mux["mode"] = options.muxMode
        root["mux"] = mux

        var client = root["client"] as? [String: Any] ?? [:]
        let bind = options.allowLan ? "0.0.0.0" : "127.0.0.1"
        var http = client["http-proxy"] as? [String: Any] ?? ["port": 8080]
        var socks = client["socks-proxy"] as? [String: Any] ?? ["port": 1080]
        http["bind"] = bind
        http["port"] = options.httpProxyPort
        socks["bind"] = bind
        socks["port"] = options.socksProxyPort
        client["http-proxy"] = http
        client["socks-proxy"] = socks

        var routing = client["routing"] as? [String: Any] ?? [:]
        // Remove the deprecated routing.mode field.  Runtime mode is
        // controlled exclusively by client.proxy-only and the --mode CLI
        // flag; an old nested mode value must never re-enter as a runtime
        // decision source.
        routing.removeValue(forKey: "mode")
        let profileProxyOnly = client["proxy-only"] as? Bool ?? false
        // UI options are the user's active override and take precedence over the
        // profile canonical value when non-empty.  An empty UI value means "not
        // set by user"; keep the profile's existing canonical value in that case.
        // routeMode==.global always forces an empty bypass regardless of UI or
        // profile content.
        let uiBypass = splitLines(options.bypassIpList)
        let uiDnsRules = splitLines(options.dnsRulesList)

        var ipRouting = routing["ip"] as? [String: Any] ?? [:]
        if ipRouting["routes"] == nil, routing["routes"] == nil, let legacyRoutes = client["routes"] {
            ipRouting["routes"] = legacyRoutes
        }
        if ipRouting["peer-routes"] == nil, routing["peer-routes"] == nil, let legacyPeerRoutes = client["peer-routes"] {
            ipRouting["peer-routes"] = legacyPeerRoutes
        }
        // Canonical nested values are authoritative and remain mirrored for
        // legacy native consumers that still read client.routes fields.
        if let canonicalRoutes = ipRouting["routes"] {
            client["routes"] = canonicalRoutes
        }
        if let canonicalPeerRoutes = ipRouting["peer-routes"] {
            client["peer-routes"] = canonicalPeerRoutes
        }
        if options.routeMode == .global {
            ipRouting["bypass"] = [String]()
        } else if !uiBypass.isEmpty {
            ipRouting["bypass"] = uiBypass
        }
        // ipRouting["bypass"] left unchanged when uiBypass is empty and routeMode != .global.
        routing["ip"] = ipRouting

        var dnsRouting = routing["dns"] as? [String: Any] ?? [:]
        if !uiDnsRules.isEmpty {
            dnsRouting["rules"] = uiDnsRules
        }
        // dnsRouting["rules"] left unchanged when uiDnsRules is empty.
        routing["dns"] = dnsRouting
        client["routing"] = routing
        client["proxy-only"] = profileProxyOnly
        root["client"] = client

        var telemetryMap = root["telemetry"] as? [String: Any] ?? [:]
        telemetryMap["enabled"] = telemetry.uploadEnabled && telemetry.includeNativeTelemetry
        telemetryMap["level"] = telemetry.nativeLogLevel
        telemetryMap["count"] = telemetry.nativeMetricsEnabled
        telemetryMap["span"] = telemetry.nativeSpansEnabled
        telemetryMap["console-log"] = true
        telemetryMap["console-metric"] = telemetry.nativeMetricsEnabled
        telemetryMap["console-span"] = telemetry.nativeSpansEnabled
        if let endpoint = nativeTelemetryEndpoint(from: telemetry) {
            telemetryMap["endpoint"] = endpoint
        } else {
            telemetryMap["endpoint"] = ""
        }
        root["telemetry"] = telemetryMap

        guard JSONSerialization.isValidJSONObject(root),
              let data = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
              let json = String(data: data, encoding: .utf8)
        else {
            return profileJson
        }

        return json
    }

    private static func nativeTelemetryEndpoint(from settings: TelemetrySettings) -> String? {
        guard settings.uploadEnabled, settings.includeNativeTelemetry else { return nil }
        let endpoint = settings.effectiveEndpoint
        guard let components = URLComponents(string: endpoint),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              components.host?.isEmpty == false
        else {
            return nil
        }
        return endpoint
    }

    private static func splitLines(_ value: String) -> [String] {
        value
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private static func profileOnlyCopies(_ profiles: [ConfigProfile]) -> [ConfigProfile] {
        profiles.map(profileOnlyCopy)
    }

    private static func profileOnlyCopy(_ profile: ConfigProfile) -> ConfigProfile {
        var copy = profile
        copy.options = LaunchOptions()
        return copy
    }

    private static func migratedLaunchOptions(from profile: ConfigProfile?) -> LaunchOptions {
        var options = profile?.options ?? LaunchOptions()
        if let profile {
            let ports = proxyPorts(in: profile.json)
            options.httpProxyPort = ports.http ?? options.httpProxyPort
            options.socksProxyPort = ports.socks ?? options.socksProxyPort
        }
        return options
    }

    private static func proxyPorts(in json: String) -> (http: Int?, socks: Int?) {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              let client = root["client"] as? [String: Any]
        else {
            return (nil, nil)
        }

        let http = client["http-proxy"] as? [String: Any]
        let socks = client["socks-proxy"] as? [String: Any]
        return (portValue(http?["port"]), portValue(socks?["port"]))
    }

    private static func portValue(_ value: Any?) -> Int? {
        if let int = value as? Int, (1...65535).contains(int) {
            return int
        }
        if let number = value as? NSNumber {
            let int = number.intValue
            return (1...65535).contains(int) ? int : nil
        }
        if let text = value as? String, let int = Int(text), (1...65535).contains(int) {
            return int
        }
        return nil
    }

    private func ensureSeeded() {
        guard let data = defaults.data(forKey: profilesKey) else {
            let seed = Self.defaultProfile()
            save([seed], notify: false)
            defaults.set(seed.id, forKey: activeIdKey)
            defaults.set(Self.defaultServerPresetMarker, forKey: defaultServerPresetKey)
            return
        }

        guard defaults.string(forKey: defaultServerPresetKey) != Self.defaultServerPresetMarker else {
            return
        }

        guard var list = try? decoder.decode([ConfigProfile].self, from: data) else {
            let seed = Self.defaultProfile()
            save([seed], notify: false)
            defaults.set(seed.id, forKey: activeIdKey)
            defaults.set(Self.defaultServerPresetMarker, forKey: defaultServerPresetKey)
            return
        }

        var changed = false
        var activeIdChanged = false
        let previousActiveId = defaults.string(forKey: activeIdKey)
        var migratedDefaultProfileId: String?
        list = list.map { profile in
            guard Self.canClearLegacyDefaultServer(to: profile) else { return profile }
            var updated = profile
            updated.name = Self.defaultProfileName
            updated.subtitle = Self.defaultServerSubtitle
            updated.json = Self.jsonByReplacingClientServer(in: updated.json, server: Self.defaultServerURI)
            updated.options = LaunchOptions()
            migratedDefaultProfileId = updated.id
            changed = true
            return updated
        }

        if list.isEmpty {
            let seed = Self.defaultProfile()
            list = [seed]
            defaults.set(seed.id, forKey: activeIdKey)
            changed = true
            activeIdChanged = true
        } else if let previousActiveId,
                  list.contains(where: { $0.id == previousActiveId }) {
            // Preserve the user's selected profile. Older builds had a bundled
            // default server; clearing that default must not steal active state.
        } else if let migratedDefaultProfileId {
            defaults.set(migratedDefaultProfileId, forKey: activeIdKey)
            activeIdChanged = true
        } else if previousActiveId == nil || !list.contains(where: { $0.id == previousActiveId }) {
            defaults.set(list[0].id, forKey: activeIdKey)
            activeIdChanged = true
        }

        if changed {
            save(list, notify: false)
        }
        if activeIdChanged {
            defaults.synchronize()
        }
        defaults.set(Self.defaultServerPresetMarker, forKey: defaultServerPresetKey)
    }

    private static func canClearLegacyDefaultServer(to profile: ConfigProfile) -> Bool {
        if profile.favorite || !profile.history.isEmpty {
            return false
        }

        let knownNames = [defaultProfileName, "Default", "JP Test", "未配置"]
        let knownSubtitles = ["", "192.168.0.24:20000", "127.0.0.1:20000"]
        let legacyServer = clientServer(in: profile.json) ?? ""
        return knownNames.contains(profile.name)
            && (profile.subtitle.isEmpty || knownSubtitles.contains(profile.subtitle))
            && legacyDefaultServerURIs.contains(legacyServer)
    }

    private static func clientServer(in json: String) -> String? {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let root = object as? [String: Any],
              let client = root["client"] as? [String: Any]
        else {
            return nil
        }

        return client["server"] as? String
    }

    private static func hostFromJson(_ json: String) -> String? {
        guard let server = clientServer(in: json),
              let endpoint = PppServerEndpoint.parse(server)
        else {
            return nil
        }
        if let port = endpoint.port {
            return "\(endpoint.host):\(port)"
        }
        return endpoint.host
    }

    private static func jsonByReplacingClientServer(in json: String, server: String) -> String {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              var root = object as? [String: Any]
        else {
            return defaultJson
        }

        var client = root["client"] as? [String: Any] ?? [:]
        client["server"] = server
        root["client"] = client

        guard JSONSerialization.isValidJSONObject(root),
              let updated = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: updated, encoding: .utf8)
        else {
            return defaultJson
        }

        return text
    }

    private static let defaultProfileName = "未配置"
    private static let defaultServerSubtitle = ""
    private static let defaultServerURI = ""
    private static let defaultServerPresetMarker = "default-empty-profile-v1"
    private static let legacyDefaultServerURIs: Set<String> = [
        "",
        "ppp://192.168.0.24:20000/",
        "ppp://127.0.0.1:20000/"
    ]

    private func save(_ profiles: [ConfigProfile], notify: Bool = true) {
        if let data = try? encoder.encode(profiles) {
            defaults.set(data, forKey: profilesKey)
        }
        if notify { emitChange() }
    }

    private func emitChange(reason: ChangeReason = .profiles) {
        NotificationCenter.default.post(
            name: Self.didChangeNotification,
            object: self,
            userInfo: [Self.changeReasonUserInfoKey: reason.rawValue]
        )
    }

    static let defaultJson = OpenPPP2DefaultConfig.templateJson
}
