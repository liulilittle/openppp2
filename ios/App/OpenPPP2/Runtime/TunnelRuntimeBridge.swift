import Foundation

public struct RuntimeOrdering: Codable, Equatable, Sendable {
    public var generation: UInt64
    public var monotonicMs: UInt64

    enum CodingKeys: String, CodingKey {
        case generation
        case monotonicMs = "monotonic_ms"
    }
}

public enum TunnelRuntimeBridge {
    public static func decodeSnapshot(_ data: Data) throws -> RuntimeSnapshot {
        try JSONDecoder().decode(RuntimeSnapshot.self, from: data)
    }

    public static func decodeSnapshot(_ text: String) throws -> RuntimeSnapshot {
        guard let data = text.data(using: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return try decodeSnapshot(data)
    }

    public static func decodeOrdering(_ data: Data) throws -> RuntimeOrdering {
        try JSONDecoder().decode(RuntimeOrdering.self, from: data)
    }

    public static func decodeOrdering(_ text: String) throws -> RuntimeOrdering {
        guard let data = text.data(using: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        return try decodeOrdering(data)
    }
}
