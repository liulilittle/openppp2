import Foundation

public enum RuntimePhase: String, Codable, Sendable {
    case idle
    case starting
    case preparingHost = "preparing_host"
    case connecting
    case handshaking
    case applyingPolicy = "applying_policy"
    case connected
    case reconnecting
    case stopping
    case failed
    case unknown
}

public enum P2PState: String, CaseIterable, Sendable {
    case disabled
    case unavailable
    case relay
    case eligible
    case probing
    case direct
    case suspect
    case fallingBack = "falling_back"
    case failed

    public static func parse(_ value: String) -> P2PState {
        P2PState(rawValue: value) ?? .unavailable
    }

    public var displayName: String {
        switch self {
        case .disabled: return "Disabled"
        case .unavailable: return "Unavailable"
        case .relay: return "Relay"
        case .eligible: return "Eligible"
        case .probing: return "Probing"
        case .direct: return "Direct"
        case .suspect: return "Suspect"
        case .fallingBack: return "Falling back"
        case .failed: return "Failed"
        }
    }
}

public struct RuntimeErrorSnapshot: Codable, Equatable, Sendable {
    public var code: UInt32
    public var severity: String
    public var retryable: Bool
    public var userMessageKey: String
    public var diagnosticDetail: String

    public init(
        code: UInt32 = 0,
        severity: String = "",
        retryable: Bool = false,
        userMessageKey: String = "",
        diagnosticDetail: String = ""
    ) {
        self.code = code
        self.severity = severity
        self.retryable = retryable
        self.userMessageKey = userMessageKey
        self.diagnosticDetail = diagnosticDetail
    }

    enum CodingKeys: String, CodingKey {
        case code
        case severity
        case retryable
        case userMessageKey = "user_message_key"
        case diagnosticDetail = "diagnostic_detail"
    }
}

public struct RuntimeTrafficSnapshot: Codable, Equatable, Sendable {
    public var rxBytes: UInt64
    public var txBytes: UInt64

    public init(rxBytes: UInt64 = 0, txBytes: UInt64 = 0) {
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }

    enum CodingKeys: String, CodingKey {
        case rxBytes = "rx_bytes"
        case txBytes = "tx_bytes"
    }
}

public struct RuntimeSnapshot: Codable, Equatable, Sendable {
    public static let schemaVersion: UInt32 = 1
    public static let bundledCapabilities = [
        "mux.compat", "mux.flow", "mux.balance", "mux.stripe"
    ]

    public var generation: UInt64
    public var monotonicMs: UInt64
    public var phase: RuntimePhase
    public var role: String
    public var server: String
    public var transport: String
    public var capabilities: [String]
    public var requestedMuxMode: String
    public var effectiveMuxMode: String
    public var muxReceiverOrdering: String
    public var muxActiveLinks: UInt16
    public var muxFallbackReason: String
    public var p2pState: P2PState
    public var effectivePath: String { p2pState == .direct ? "direct" : "relay" }
    public var traffic: RuntimeTrafficSnapshot

    /// `monotonicMs` at which the session entered `connected`, or 0 when it is
    /// not connected. Elapsed time is `monotonicMs - connectedMonotonicMs`, so
    /// it stays correct across an app process restart.
    public var connectedMonotonicMs: UInt64
    public var lastError: RuntimeErrorSnapshot

    public init(
        generation: UInt64,
        monotonicMs: UInt64,
        phase: RuntimePhase,
        role: String = "",
        server: String = "",
        transport: String = "",
        capabilities: [String] = [],
        requestedMuxMode: String = "",
        effectiveMuxMode: String = "",
        muxReceiverOrdering: String = "",
        muxActiveLinks: UInt16 = 0,
        muxFallbackReason: String = "",
        p2pState: P2PState = .disabled,
        traffic: RuntimeTrafficSnapshot = RuntimeTrafficSnapshot(),
        connectedMonotonicMs: UInt64 = 0,
        lastError: RuntimeErrorSnapshot = RuntimeErrorSnapshot()
    ) {
        self.generation = generation
        self.monotonicMs = monotonicMs
        self.phase = phase
        self.role = role
        self.server = server
        self.transport = transport
        self.capabilities = capabilities
        self.requestedMuxMode = requestedMuxMode
        self.effectiveMuxMode = effectiveMuxMode
        self.muxReceiverOrdering = muxReceiverOrdering
        self.muxActiveLinks = muxActiveLinks
        self.muxFallbackReason = muxFallbackReason
        self.p2pState = p2pState
        self.traffic = traffic
        self.connectedMonotonicMs = connectedMonotonicMs
        self.lastError = lastError
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case generation
        case monotonicMs = "monotonic_ms"
        case phase
        case role
        case server
        case transport
        case capabilities
        case requestedMuxMode = "requested_mux_mode"
        case effectiveMuxMode = "effective_mux_mode"
        case muxReceiverOrdering = "mux_receiver_ordering"
        case muxActiveLinks = "mux_active_links"
        case muxFallbackReason = "mux_fallback_reason"
        case p2pState = "p2p_state"
        case effectivePath = "effective_path"
        case traffic
        case connectedMonotonicMs = "connected_monotonic_ms"
        case lastError = "last_error"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decode(UInt32.self, forKey: .schemaVersion)
        guard version == Self.schemaVersion else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported runtime schema version: \(version)"
            )
        }

        generation = try container.decode(UInt64.self, forKey: .generation)
        monotonicMs = try container.decode(UInt64.self, forKey: .monotonicMs)
        phase = try container.decode(RuntimePhase.self, forKey: .phase)
        role = try container.decodeIfPresent(String.self, forKey: .role) ?? ""
        server = try container.decodeIfPresent(String.self, forKey: .server) ?? ""
        transport = try container.decodeIfPresent(String.self, forKey: .transport) ?? ""
        if container.contains(.capabilities) {
            capabilities = try container.decodeIfPresent([String].self, forKey: .capabilities) ?? []
        } else {
            capabilities = Self.bundledCapabilities
        }
        requestedMuxMode = try container.decodeIfPresent(String.self, forKey: .requestedMuxMode) ?? ""
        effectiveMuxMode = try container.decodeIfPresent(String.self, forKey: .effectiveMuxMode) ?? ""
        muxReceiverOrdering = try container.decodeIfPresent(String.self, forKey: .muxReceiverOrdering) ?? ""
        muxActiveLinks = try container.decodeIfPresent(UInt16.self, forKey: .muxActiveLinks) ?? 0
        muxFallbackReason = try container.decodeIfPresent(String.self, forKey: .muxFallbackReason) ?? ""
        p2pState = P2PState.parse(
            try container.decodeIfPresent(String.self, forKey: .p2pState) ?? "disabled"
        )
        traffic = try container.decodeIfPresent(RuntimeTrafficSnapshot.self, forKey: .traffic) ?? RuntimeTrafficSnapshot()
        connectedMonotonicMs = try container.decodeIfPresent(UInt64.self, forKey: .connectedMonotonicMs) ?? 0
        lastError = try container.decodeIfPresent(RuntimeErrorSnapshot.self, forKey: .lastError) ?? RuntimeErrorSnapshot()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Self.schemaVersion, forKey: .schemaVersion)
        try container.encode(generation, forKey: .generation)
        try container.encode(monotonicMs, forKey: .monotonicMs)
        try container.encode(phase, forKey: .phase)
        try container.encode(role, forKey: .role)
        try container.encode(server, forKey: .server)
        try container.encode(transport, forKey: .transport)
        try container.encode(capabilities, forKey: .capabilities)
        try container.encode(requestedMuxMode, forKey: .requestedMuxMode)
        try container.encode(effectiveMuxMode, forKey: .effectiveMuxMode)
        try container.encode(muxReceiverOrdering, forKey: .muxReceiverOrdering)
        try container.encode(muxActiveLinks, forKey: .muxActiveLinks)
        try container.encode(muxFallbackReason, forKey: .muxFallbackReason)
        try container.encode(p2pState.rawValue, forKey: .p2pState)
        try container.encode(effectivePath, forKey: .effectivePath)
        try container.encode(traffic, forKey: .traffic)
        try container.encode(connectedMonotonicMs, forKey: .connectedMonotonicMs)
        try container.encode(lastError, forKey: .lastError)
    }

    public func availableMuxModes(experimental: Bool = false) -> [String] {
        ["compat", "flow", "balance", "stripe"].filter {
            capabilities.contains("mux.\($0)") && ($0 != "stripe" || experimental)
        }
    }

    public var effectiveMuxDisplayName: String {
        effectiveMuxMode == "compat" ? "Compatibility mode" : effectiveMuxMode
    }

    public var muxDiagnosticLines: [String] {
        var lines: [String] = []
        if !requestedMuxMode.isEmpty { lines.append("Requested VMUX: \(requestedMuxMode)") }
        if !effectiveMuxMode.isEmpty { lines.append("Effective VMUX: \(effectiveMuxDisplayName)") }
        if !muxFallbackReason.isEmpty { lines.append("Fallback reason: \(muxFallbackReason)") }
        return lines
    }

    public var effectivePathDisplayName: String {
        effectivePath == "direct" ? "Direct" : "Relay"
    }

    public var p2pDiagnosticLines: [String] {
        ["P2P: \(p2pState.displayName)", "Effective path: \(effectivePathDisplayName)"]
    }
}
