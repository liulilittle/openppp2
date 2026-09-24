import Darwin
import Foundation

// MARK: - Models

struct ConfigSnapshot: Codable, Equatable {
    var timestampMs: Int
    var json: String
}

enum LaunchRouteMode: String, Codable, CaseIterable {
    case geo
    case global
    case basic
}

struct LaunchOptions: Codable, Equatable {
    var tunIp: String = "10.8.0.2"
    var tunMask: String = "255.255.255.0"
    var tunPrefix: Int = 24
    var gateway: String = "10.8.0.1"
    var route: String = "0.0.0.0"
    var routePrefix: Int = 0
    var dns1: String = "8.8.8.8"
    var dns2: String = "1.1.1.1"
    var mtu: Int = 1400
    var mux: Int = 0
    var muxMode: String = "compat"
    var vnet: Bool = false
    var lwip: Bool = false
    var blockQuic: Bool = true
    var staticMode: Bool = true
    var bypassIpList: String = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n169.254.0.0/16\n100.64.0.0/10"
    var dnsRulesList: String = ""
    var allowLan: Bool = false
    var httpProxyPort: Int = 8080
    var socksProxyPort: Int = 1080
    var dnsDomestic: String = "doh.pub"
    var dnsForeign: String = "cloudflare"
    var dnsInterceptUnmatched: Bool = true
    var dnsFakeIpEnabled: Bool = false
    var dnsFakeIpRange: String = "198.18.0.1/16"
    var dnsEcsEnabled: Bool = true
    var dnsEcsOverrideIp: String = ""
    var dnsTlsVerifyPeer: Bool = true
    var dnsStunCandidates: String = "39.107.142.158:3478\n74.125.250.129:19302"
    var geoEnabled: Bool = true
    var routeMode: LaunchRouteMode = .geo
    var geoCountry: String = "cn"
    var geoIpDat: String = "./rules/GeoIP.dat"
    var geoSiteDat: String = "./rules/GeoSite.dat"
    var autoReconnectOnPathRecovery: Bool = false

    init() {}

    enum CodingKeys: String, CodingKey {
        case tunIp
        case tunMask
        case tunPrefix
        case gateway
        case route
        case routePrefix
        case dns1
        case dns2
        case mtu
        case mux
        case muxMode
        case vnet
        case lwip
        case blockQuic
        case staticMode
        case bypassIpList
        case dnsRulesList
        case allowLan
        case httpProxyPort
        case socksProxyPort
        case dnsDomestic
        case dnsForeign
        case dnsInterceptUnmatched
        case dnsFakeIpEnabled
        case dnsFakeIpRange
        case dnsEcsEnabled
        case dnsEcsOverrideIp
        case dnsTlsVerifyPeer
        case dnsStunCandidates
        case geoEnabled
        case routeMode
        case geoCountry
        case geoIpDat
        case geoSiteDat
        case autoReconnectOnPathRecovery
    }

    init(from decoder: Decoder) throws {
        let defaults = LaunchOptions()
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tunIp = try container.decodeIfPresent(String.self, forKey: .tunIp) ?? defaults.tunIp
        tunMask = try container.decodeIfPresent(String.self, forKey: .tunMask) ?? defaults.tunMask
        tunPrefix = try container.decodeIfPresent(Int.self, forKey: .tunPrefix) ?? defaults.tunPrefix
        gateway = try container.decodeIfPresent(String.self, forKey: .gateway) ?? defaults.gateway
        route = try container.decodeIfPresent(String.self, forKey: .route) ?? defaults.route
        routePrefix = try container.decodeIfPresent(Int.self, forKey: .routePrefix) ?? defaults.routePrefix
        dns1 = try container.decodeIfPresent(String.self, forKey: .dns1) ?? defaults.dns1
        dns2 = try container.decodeIfPresent(String.self, forKey: .dns2) ?? defaults.dns2
        mtu = try container.decodeIfPresent(Int.self, forKey: .mtu) ?? defaults.mtu
        mux = try container.decodeIfPresent(Int.self, forKey: .mux) ?? defaults.mux
        muxMode = try container.decodeIfPresent(String.self, forKey: .muxMode) ?? defaults.muxMode
        vnet = try container.decodeIfPresent(Bool.self, forKey: .vnet) ?? defaults.vnet
        lwip = try container.decodeIfPresent(Bool.self, forKey: .lwip) ?? defaults.lwip
        blockQuic = try container.decodeIfPresent(Bool.self, forKey: .blockQuic) ?? defaults.blockQuic
        staticMode = try container.decodeIfPresent(Bool.self, forKey: .staticMode) ?? defaults.staticMode
        bypassIpList = try container.decodeIfPresent(String.self, forKey: .bypassIpList) ?? defaults.bypassIpList
        dnsRulesList = try container.decodeIfPresent(String.self, forKey: .dnsRulesList) ?? defaults.dnsRulesList
        allowLan = try container.decodeIfPresent(Bool.self, forKey: .allowLan) ?? defaults.allowLan
        httpProxyPort = try container.decodeIfPresent(Int.self, forKey: .httpProxyPort) ?? defaults.httpProxyPort
        socksProxyPort = try container.decodeIfPresent(Int.self, forKey: .socksProxyPort) ?? defaults.socksProxyPort
        dnsDomestic = try container.decodeIfPresent(String.self, forKey: .dnsDomestic) ?? defaults.dnsDomestic
        dnsForeign = try container.decodeIfPresent(String.self, forKey: .dnsForeign) ?? defaults.dnsForeign
        dnsInterceptUnmatched = try container.decodeIfPresent(Bool.self, forKey: .dnsInterceptUnmatched) ?? defaults.dnsInterceptUnmatched
        dnsFakeIpEnabled = try container.decodeIfPresent(Bool.self, forKey: .dnsFakeIpEnabled) ?? defaults.dnsFakeIpEnabled
        dnsFakeIpRange = try container.decodeIfPresent(String.self, forKey: .dnsFakeIpRange) ?? defaults.dnsFakeIpRange
        dnsEcsEnabled = try container.decodeIfPresent(Bool.self, forKey: .dnsEcsEnabled) ?? defaults.dnsEcsEnabled
        dnsEcsOverrideIp = try container.decodeIfPresent(String.self, forKey: .dnsEcsOverrideIp) ?? defaults.dnsEcsOverrideIp
        dnsTlsVerifyPeer = try container.decodeIfPresent(Bool.self, forKey: .dnsTlsVerifyPeer) ?? defaults.dnsTlsVerifyPeer
        dnsStunCandidates = try container.decodeIfPresent(String.self, forKey: .dnsStunCandidates) ?? defaults.dnsStunCandidates
        geoEnabled = try container.decodeIfPresent(Bool.self, forKey: .geoEnabled) ?? defaults.geoEnabled
        routeMode = try container.decodeIfPresent(LaunchRouteMode.self, forKey: .routeMode) ?? (geoEnabled ? .geo : .basic)
        geoCountry = try container.decodeIfPresent(String.self, forKey: .geoCountry) ?? defaults.geoCountry
        geoIpDat = try container.decodeIfPresent(String.self, forKey: .geoIpDat) ?? defaults.geoIpDat
        geoSiteDat = try container.decodeIfPresent(String.self, forKey: .geoSiteDat) ?? defaults.geoSiteDat
        autoReconnectOnPathRecovery = try container.decodeIfPresent(Bool.self, forKey: .autoReconnectOnPathRecovery) ?? defaults.autoReconnectOnPathRecovery
    }

    var effectiveGeoEnabled: Bool {
        routeMode == .geo
    }

    var effectiveBypassIpList: String {
        routeMode == .global ? "" : bypassIpList
    }

    mutating func setRouteMode(_ mode: LaunchRouteMode) {
        routeMode = mode
        geoEnabled = mode == .geo
    }
}

struct ConfigProfile: Codable, Equatable {
    var id: String
    var name: String
    var subtitle: String
    var flag: String
    var json: String
    var favorite: Bool
    var subscriptionUrl: String?
    var subscriptionNodeId: String?
    var subscriptionUpdatedAtMs: Int?
    var options: LaunchOptions
    var history: [ConfigSnapshot]

    static let historyLimit = 8

    var serverHost: String? {
        parsedServerEndpoint?.host
    }

    var serverEndpoint: String? {
        guard let endpoint = parsedServerEndpoint else {
            return nil
        }

        if let port = endpoint.port {
            return "\(endpoint.host):\(port)"
        }
        return endpoint.host
    }

    private var parsedServerEndpoint: PppServerEndpoint? {
        guard
            let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data),
            let root = object as? [String: Any],
            let client = root["client"] as? [String: Any],
            let server = client["server"] as? String,
            let endpoint = PppServerEndpoint.parse(server)
        else {
            return nil
        }
        return endpoint
    }

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case subtitle
        case flag
        case json
        case favorite
        case subscriptionUrl
        case subscriptionNodeId
        case subscriptionUpdatedAtMs
        case options
        case history
    }

    init(
        id: String,
        name: String,
        subtitle: String,
        flag: String,
        json: String,
        favorite: Bool,
        subscriptionUrl: String? = nil,
        subscriptionNodeId: String? = nil,
        subscriptionUpdatedAtMs: Int? = nil,
        options: LaunchOptions,
        history: [ConfigSnapshot]
    ) {
        self.id = id
        self.name = name
        self.subtitle = subtitle
        self.flag = flag
        self.json = json
        self.favorite = favorite
        self.subscriptionUrl = subscriptionUrl
        self.subscriptionNodeId = subscriptionNodeId
        self.subscriptionUpdatedAtMs = subscriptionUpdatedAtMs
        self.options = options
        self.history = history
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        subtitle = try container.decodeIfPresent(String.self, forKey: .subtitle) ?? ""
        flag = try container.decodeIfPresent(String.self, forKey: .flag) ?? ""
        json = try container.decode(String.self, forKey: .json)
        favorite = try container.decodeIfPresent(Bool.self, forKey: .favorite) ?? false
        subscriptionUrl = try container.decodeIfPresent(String.self, forKey: .subscriptionUrl)
        subscriptionNodeId = try container.decodeIfPresent(String.self, forKey: .subscriptionNodeId)
        subscriptionUpdatedAtMs = try container.decodeIfPresent(Int.self, forKey: .subscriptionUpdatedAtMs)
        options = try container.decodeIfPresent(LaunchOptions.self, forKey: .options) ?? LaunchOptions()
        history = try container.decodeIfPresent([ConfigSnapshot].self, forKey: .history) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(subtitle, forKey: .subtitle)
        try container.encode(flag, forKey: .flag)
        try container.encode(json, forKey: .json)
        try container.encode(favorite, forKey: .favorite)
        try container.encodeIfPresent(subscriptionUrl, forKey: .subscriptionUrl)
        try container.encodeIfPresent(subscriptionNodeId, forKey: .subscriptionNodeId)
        try container.encodeIfPresent(subscriptionUpdatedAtMs, forKey: .subscriptionUpdatedAtMs)
        try container.encode(options, forKey: .options)
        try container.encode(history, forKey: .history)
    }
}

struct PppServerEndpoint {
    var host: String
    var port: Int?

    static func parse(_ value: String) -> PppServerEndpoint? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        let prefix = "ppp://"
        if trimmed.hasPrefix(prefix) {
            let rest = String(trimmed.dropFirst(prefix.count))
            let parts = rest.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            let authority: String
            if let first = parts.first?.lowercased(), (first == "ws" || first == "wss"), parts.count > 1 {
                authority = parts[1]
            } else {
                authority = parts.first ?? ""
            }
            return parseAuthority(authority)
        }

        if let components = URLComponents(string: trimmed), let host = components.host, !host.isEmpty {
            return PppServerEndpoint(host: host, port: components.port)
        }
        return parseAuthority(trimmed)
    }

    private static func parseAuthority(_ raw: String) -> PppServerEndpoint? {
        let authority = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !authority.isEmpty else { return nil }

        if authority.hasPrefix("[") {
            guard let end = authority.firstIndex(of: "]") else { return nil }
            let host = String(authority[authority.index(after: authority.startIndex)..<end])
            let rest = String(authority[authority.index(after: end)...])
            let port = rest.hasPrefix(":") ? Int(rest.dropFirst()) : nil
            return PppServerEndpoint(host: host, port: port)
        }

        if authority.filter({ $0 == ":" }).count > 1 {
            if let colon = authority.lastIndex(of: ":") {
                let hostCandidate = String(authority[..<colon])
                let tail = String(authority[authority.index(after: colon)...])
                if let port = Int(tail), isValidIPv6Address(hostCandidate) {
                    return PppServerEndpoint(host: hostCandidate, port: port)
                }
            }
            return PppServerEndpoint(host: authority, port: nil)
        }

        if let colon = authority.lastIndex(of: ":") {
            let host = String(authority[..<colon])
            let tail = String(authority[authority.index(after: colon)...])
            if let port = Int(tail), !host.isEmpty {
                return PppServerEndpoint(host: host, port: port)
            }
        }
        return PppServerEndpoint(host: authority, port: nil)
    }

    private static func isValidIPv6Address(_ value: String) -> Bool {
        var addr = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }
}

struct RemoteSubscriptionNode {
    var id: String
    var name: String
    var subtitle: String
    var flag: String
    var json: String
    var options: LaunchOptions?
}

struct RemoteSubscriptionResult {
    var name: String
    var profilePrefix: String?
    var nodes: [RemoteSubscriptionNode]
}

enum RemoteSubscriptionParser {
    static func parse(_ text: String) throws -> RemoteSubscriptionResult {
        guard let data = text.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw NSError.openPPP2("订阅根节点必须是 JSON object")
        }

        guard object["type"] as? String == "openppp2-subscription" else {
            throw NSError.openPPP2("订阅 type 必须是 openppp2-subscription")
        }
        guard let version = object["version"] as? NSNumber, version.intValue == 1 else {
            throw NSError.openPPP2("仅支持订阅 version=1")
        }
        guard let rawNodes = object["nodes"] as? [[String: Any]] else {
            throw NSError.openPPP2("订阅 nodes 必须是数组")
        }

        let prefix = (object["profilePrefix"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        var nodes: [RemoteSubscriptionNode] = []
        for rawNode in rawNodes where (rawNode["enabled"] as? Bool) != false {
            let id = "\(rawNode["id"] ?? "")".trimmingCharacters(in: .whitespacesAndNewlines)
            guard !id.isEmpty else {
                throw NSError.openPPP2("节点 id 不能为空")
            }

            let rawName = "\(rawNode["name"] ?? id)".trimmingCharacters(in: .whitespacesAndNewlines)
            let name: String
            if let prefix, !prefix.isEmpty, !rawName.hasPrefix(prefix) {
                name = "\(prefix) \(rawName)"
            } else {
                name = rawName.isEmpty ? id : rawName
            }

            let config = try buildConfig(from: rawNode)
            guard JSONSerialization.isValidJSONObject(config),
                  let jsonData = try? JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys]),
                  let json = String(data: jsonData, encoding: .utf8)
            else {
                throw NSError.openPPP2("节点 \(id) 配置无法序列化")
            }

            nodes.append(RemoteSubscriptionNode(
                id: id,
                name: name,
                subtitle: rawNode["subtitle"] as? String ?? "",
                flag: rawNode["flag"] as? String ?? "",
                json: json,
                options: decodeOptions(rawNode["options"])
            ))
        }

        guard !nodes.isEmpty else {
            throw NSError.openPPP2("订阅中没有可导入节点")
        }

        return RemoteSubscriptionResult(
            name: object["name"] as? String ?? "OPENPPP2 Subscription",
            profilePrefix: prefix?.isEmpty == false ? prefix : nil,
            nodes: nodes
        )
    }

    private static func buildConfig(from node: [String: Any]) throws -> [String: Any] {
        if let config = node["config"] as? [String: Any] {
            return config
        }
        if let configText = node["config"] as? String, !configText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard let data = configText.data(using: .utf8),
                  let config = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                throw NSError.openPPP2("节点 config 字符串必须是 JSON object")
            }
            return config
        }

        guard let defaultData = OpenPPP2DefaultConfig.templateJson.data(using: .utf8),
              var root = try JSONSerialization.jsonObject(with: defaultData) as? [String: Any]
        else {
            throw NSError.openPPP2("默认配置无法解析")
        }

        let server = "\(node["server"] ?? "")".trimmingCharacters(in: .whitespacesAndNewlines)
        guard server.hasPrefix("ppp://") else {
            throw NSError.openPPP2("精简节点必须包含 ppp:// server")
        }
        guard let key = node["key"] as? [String: Any], !key.isEmpty else {
            throw NSError.openPPP2("精简节点必须包含 key")
        }

        var keyRoot = root["key"] as? [String: Any] ?? [:]
        key.forEach { keyRoot[$0.key] = $0.value }
        root["key"] = keyRoot

        var client = root["client"] as? [String: Any] ?? [:]
        if let clientOverride = node["client"] as? [String: Any] {
            clientOverride.forEach { client[$0.key] = $0.value }
        }
        client["server"] = server
        if let bandwidth = node["bandwidth"] as? NSNumber {
            client["bandwidth"] = bandwidth.intValue
        }
        client["mappings"] = []
        root["client"] = client

        if let websocket = node["websocket"] as? [String: Any] {
            var ws = root["websocket"] as? [String: Any] ?? [:]
            websocket.forEach { ws[$0.key] = $0.value }
            root["websocket"] = ws
        }

        return root
    }

    private static func decodeOptions(_ value: Any?) -> LaunchOptions? {
        guard let map = value as? [String: Any],
              JSONSerialization.isValidJSONObject(map),
              let data = try? JSONSerialization.data(withJSONObject: map),
              let options = try? JSONDecoder().decode(LaunchOptions.self, from: data)
        else {
            return nil
        }
        return options
    }
}

extension NSError {
    static func openPPP2(_ message: String) -> NSError {
        NSError(domain: "OpenPPP2", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

struct VpnDiagnostics: Equatable {
    var linkState: Int?
    var startStage: String = ""
    var lastError: String = ""
    var serverHost: String = ""
    var tunIp: String = ""
    var route: String = ""
    var dataplane: String = ""
    var inputPacketCount: Int = 0
    var lastInputPacket: String = ""
    var outputPacketCount: Int = 0
    var lastOutputPacket: String = ""
    var lastOutputPacketOK: Bool?
    var networkPath: TunnelSharedState.NetworkPathSnapshot?

    static let empty = VpnDiagnostics()

    init() {}

    init(jsonText: String) {
        guard let data = jsonText.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let map = object as? [String: Any]
        else {
            self = .empty
            return
        }

        if let number = map["linkState"] as? NSNumber {
            linkState = number.intValue
        } else if let text = map["linkState"] as? String {
            linkState = Int(text)
        }
        startStage = map["startStage"] as? String ?? ""
        lastError = map["lastError"] as? String ?? ""
        serverHost = map["serverHost"] as? String ?? ""
        tunIp = map["tunIp"] as? String ?? ""
        route = map["route"] as? String ?? ""
        dataplane = map["dataplane"] as? String ?? ""
        if let number = map["inputPacketCount"] as? NSNumber {
            inputPacketCount = number.intValue
        } else if let text = map["inputPacketCount"] as? String {
            inputPacketCount = Int(text) ?? 0
        }
        lastInputPacket = map["lastInputPacket"] as? String ?? ""
        if let number = map["outputPacketCount"] as? NSNumber {
            outputPacketCount = number.intValue
        } else if let text = map["outputPacketCount"] as? String {
            outputPacketCount = Int(text) ?? 0
        }
        lastOutputPacket = map["lastOutputPacket"] as? String ?? ""
        if let number = map["lastOutputPacketOK"] as? NSNumber {
            lastOutputPacketOK = number.boolValue
        } else if let value = map["lastOutputPacketOK"] as? Bool {
            lastOutputPacketOK = value
        } else if let text = map["lastOutputPacketOK"] as? String {
            lastOutputPacketOK = (text as NSString).boolValue
        }
        if let networkPathMap = map["networkPath"] as? [String: Any] {
            networkPath = TunnelSharedState.NetworkPathSnapshot(dictionary: networkPathMap)
        } else {
            networkPath = TunnelSharedState.readNetworkPathSnapshot()
        }
    }

    var hasContent: Bool {
        linkState != nil || !startStage.isEmpty || !meaningfulLastError.isEmpty || networkPath != nil
    }

    var meaningfulLastError: String {
        let trimmed = lastError.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased() == "success" ? "" : trimmed
    }

    func summaryText(
        fallbackLinkState: Int,
        fallbackNetworkPath: TunnelSharedState.NetworkPathSnapshot? = nil
    ) -> String? {
        let effectiveNetworkPath = networkPath ?? fallbackNetworkPath
        guard hasContent || effectiveNetworkPath != nil else { return nil }
        let state = fallbackLinkState
        var parts = ["linkState \(state)"]
        if !startStage.isEmpty {
            parts.append("stage \(startStage)")
        }
        if !serverHost.isEmpty {
            parts.append("server \(serverHost)")
        }
        if !tunIp.isEmpty || !route.isEmpty {
            parts.append("tunnel \(tunIp) route \(route)")
        }
        if !dataplane.isEmpty {
            parts.append("dataplane \(dataplane)")
        }
        if inputPacketCount > 0 || !lastInputPacket.isEmpty {
            parts.append("input #\(inputPacketCount) \(lastInputPacket)")
        }
        if outputPacketCount > 0 || !lastOutputPacket.isEmpty {
            let okText = lastOutputPacketOK.map { $0 ? "ok" : "failed" } ?? "unknown"
            parts.append("output #\(outputPacketCount) \(okText) \(lastOutputPacket)")
        }
        if let effectiveNetworkPath {
            parts.append("path \(effectiveNetworkPath.summaryText)")
        }
        if !meaningfulLastError.isEmpty {
            parts.append("error \(meaningfulLastError)")
        }
        return parts.joined(separator: "\n")
    }
}

enum OpenPPP2DefaultConfig {
    static let templateJson = """
    {
      "concurrent" : 1,
      "cdn" : [80, 443],
      "key" : {
        "kf" : 154543927,
        "kx" : 128,
        "kl" : 10,
        "kh" : 12,
        "protocol" : "aes-128-cfb",
        "protocol-key" : "N6HMzdUs7IUnYHwq",
        "transport" : "aes-256-cfb",
        "transport-key" : "HWFweXu2g5RVMEpy",
        "masked" : false,
        "plaintext" : false,
        "delta-encode" : false,
        "shuffle-data" : false
      },
      "ip" : { "public" : "0.0.0.0", "interface" : "0.0.0.0" },
      "server" : {
        "node" : 1,
        "log" : "./ppp.log",
        "subnet" : true,
        "mapping" : false,
        "backend" : "",
        "backend-key" : ""
      },
      "tcp" : {
        "inactive" : { "timeout" : 300 },
        "connect" : { "timeout" : 5 },
        "listen" : { "port" : 20000 },
        "turbo" : true,
        "backlog" : 511,
        "fast-open" : true
      },
      "udp" : {
        "inactive" : { "timeout" : 72 },
        "dns" : { "timeout" : 4, "redirect" : "8.8.8.8:53" },
        "listen" : { "port" : 20000 },
        "static" : {
          "keep-alived" : [1, 5],
          "dns" : true,
          "quic" : false,
          "icmp" : true,
          "server" : "127.0.0.1:20000"
        }
      },
      "websocket" : {
        "host" : "",
        "path" : "/",
        "listen" : { "ws" : 0, "wss" : 0 },
        "verify-peer" : true
      },
      "client" : {
        "guid" : "{F4569420-4E49-4CBA-9C36-94E722C8E363}",
        "server" : "",
        "bandwidth" : 0,
        "reconnections" : { "timeout" : 5 },
        "paper-airplane" : { "tcp" : true },
        "http-proxy" : { "bind" : "127.0.0.1", "port" : 8080 },
        "socks-proxy" : { "bind" : "127.0.0.1", "port" : 1080 },
        "mappings" : []
      }
    }
    """
}
