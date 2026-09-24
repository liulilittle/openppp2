import 'runtime_snapshot.dart';

/// Byte totals plus a rate derived from two consecutive snapshots.
///
/// The rate uses the snapshot's own monotonic clock rather than how often the
/// UI samples, so it stays correct when a poll is late or dropped.
class RuntimeTrafficRate {
  const RuntimeTrafficRate({
    this.rxBytes = 0,
    this.txBytes = 0,
    this.rxBytesPerSecond = 0,
    this.txBytesPerSecond = 0,
  });

  final int rxBytes;
  final int txBytes;
  final int rxBytesPerSecond;
  final int txBytesPerSecond;

  /// Derives the next rate from [previous] and [current]. A new generation, a
  /// clock that did not advance, or counters that moved backwards report the
  /// totals with no rate instead of a spike.
  static RuntimeTrafficRate between(
    RuntimeSnapshot? previous,
    RuntimeSnapshot current,
  ) {
    final totals = RuntimeTrafficRate(
      rxBytes: current.traffic.rxBytes,
      txBytes: current.traffic.txBytes,
    );
    if (previous == null || previous.generation != current.generation) {
      return totals;
    }
    final elapsedMs = current.monotonicMs - previous.monotonicMs;
    if (elapsedMs <= 0) {
      return totals;
    }
    final rx = current.traffic.rxBytes - previous.traffic.rxBytes;
    final tx = current.traffic.txBytes - previous.traffic.txBytes;
    if (rx < 0 || tx < 0) {
      return totals;
    }
    return RuntimeTrafficRate(
      rxBytes: current.traffic.rxBytes,
      txBytes: current.traffic.txBytes,
      rxBytesPerSecond: (rx * 1000) ~/ elapsedMs,
      txBytesPerSecond: (tx * 1000) ~/ elapsedMs,
    );
  }

  /// Whether [current] should replace the traffic rate baseline.
  ///
  /// Phase/readiness snapshots advance [RuntimeSnapshot.monotonicMs] without
  /// touching byte counters. Using those as the next baseline shrinks the
  /// elapsed window for the following traffic sample and spikes the rate.
  /// Keep the last counters sample until generation or rx/tx changes.
  static bool advancesTrafficBaseline(
    RuntimeSnapshot? previous,
    RuntimeSnapshot current,
  ) {
    if (previous == null) return true;
    if (previous.generation != current.generation) return true;
    return previous.traffic.rxBytes != current.traffic.rxBytes ||
        previous.traffic.txBytes != current.traffic.txBytes;
  }
}

/// Milliseconds the session has been connected, or 0 when it is not.
int connectedElapsedMs(RuntimeSnapshot snapshot) {
  if (snapshot.connectedMonotonicMs == 0 ||
      snapshot.monotonicMs < snapshot.connectedMonotonicMs) {
    return 0;
  }
  return snapshot.monotonicMs - snapshot.connectedMonotonicMs;
}
