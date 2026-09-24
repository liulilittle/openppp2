import Foundation

/// Byte totals plus a rate derived from two consecutive snapshots.
///
/// The rate uses the snapshot's own monotonic clock rather than how often the
/// UI samples, so it stays correct when a poll is late or dropped.
public struct RuntimeTrafficRate: Equatable, Sendable {
    public var rxBytes: UInt64
    public var txBytes: UInt64
    public var rxBytesPerSecond: UInt64
    public var txBytesPerSecond: UInt64

    public init(
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0,
        rxBytesPerSecond: UInt64 = 0,
        txBytesPerSecond: UInt64 = 0
    ) {
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.rxBytesPerSecond = rxBytesPerSecond
        self.txBytesPerSecond = txBytesPerSecond
    }

    public static let empty = RuntimeTrafficRate()

    /// Derives the next rate from `previous` and `current`. A new generation, a
    /// clock that did not advance, or counters that moved backwards report the
    /// totals with no rate instead of a spike.
    public static func between(
        _ previous: RuntimeSnapshot?,
        _ current: RuntimeSnapshot
    ) -> RuntimeTrafficRate {
        let totals = RuntimeTrafficRate(
            rxBytes: current.traffic.rxBytes,
            txBytes: current.traffic.txBytes
        )
        guard let previous, previous.generation == current.generation else {
            return totals
        }
        guard current.monotonicMs > previous.monotonicMs else {
            return totals
        }
        guard current.traffic.rxBytes >= previous.traffic.rxBytes,
              current.traffic.txBytes >= previous.traffic.txBytes
        else {
            return totals
        }

        let elapsedMs = current.monotonicMs - previous.monotonicMs
        return RuntimeTrafficRate(
            rxBytes: current.traffic.rxBytes,
            txBytes: current.traffic.txBytes,
            rxBytesPerSecond: (current.traffic.rxBytes - previous.traffic.rxBytes) * 1000 / elapsedMs,
            txBytesPerSecond: (current.traffic.txBytes - previous.traffic.txBytes) * 1000 / elapsedMs
        )
    }

    /// Whether `current` should replace the traffic rate baseline.
    ///
    /// Phase/readiness snapshots advance `monotonicMs` without changing byte
    /// counters. Using those as the next baseline shrinks the elapsed window
    /// for the following traffic sample and spikes the rate.
    public static func advancesTrafficBaseline(
        _ previous: RuntimeSnapshot?,
        _ current: RuntimeSnapshot
    ) -> Bool {
        guard let previous else { return true }
        if previous.generation != current.generation { return true }
        return previous.traffic.rxBytes != current.traffic.rxBytes ||
            previous.traffic.txBytes != current.traffic.txBytes
    }
}

/// Milliseconds the session has been connected, or 0 when it is not.
public func connectedElapsedMs(_ snapshot: RuntimeSnapshot) -> UInt64 {
    guard snapshot.connectedMonotonicMs != 0,
          snapshot.monotonicMs >= snapshot.connectedMonotonicMs
    else {
        return 0
    }
    return snapshot.monotonicMs - snapshot.connectedMonotonicMs
}
