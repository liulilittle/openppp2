import Combine
import Foundation

@MainActor
public final class RuntimeStore: ObservableObject {
    @Published public private(set) var state: RuntimeSnapshot

    public init(
        initial: RuntimeSnapshot = RuntimeSnapshot(
            generation: 0,
            monotonicMs: 0,
            phase: .idle,
            capabilities: RuntimeSnapshot.bundledCapabilities
        )
    ) {
        state = initial
    }

    @discardableResult
    public func apply(_ incoming: RuntimeSnapshot) -> Bool {
        if incoming.generation < state.generation {
            return false
        }
        if incoming.generation == state.generation,
           incoming.monotonicMs <= state.monotonicMs {
            return false
        }
        state = incoming
        return true
    }

    public func markUnknown() {
        guard state.phase != .unknown else { return }
        state.phase = .unknown
        state.p2pState = .unavailable
    }

    @discardableResult
    public func applyUnknown(generation: UInt64, monotonicMs: UInt64) -> Bool {
        if generation < state.generation ||
            (generation == state.generation && monotonicMs <= state.monotonicMs) {
            return false
        }
        state = RuntimeSnapshot(
            generation: generation,
            monotonicMs: monotonicMs,
            phase: .unknown,
            p2pState: .unavailable
        )
        return true
    }
}
