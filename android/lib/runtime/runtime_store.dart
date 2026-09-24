import 'package:flutter/foundation.dart';

import 'runtime_snapshot.dart';

class RuntimeStore extends ChangeNotifier {
  RuntimeStore({RuntimeSnapshot? initial})
      : _state = initial ??
            const RuntimeSnapshot(
              generation: 0,
              monotonicMs: 0,
              phase: RuntimePhase.idle,
              capabilities: RuntimeSnapshot.bundledCapabilities,
            );

  RuntimeSnapshot _state;
  RuntimeSnapshot get state => _state;
  bool _sessionActive = false;

  /// Drops the ordering baseline. A restarted `:vpn` service counts
  /// generations from zero again, so the previous watermark would otherwise
  /// reject every snapshot the new session publishes.
  bool resetForNewSession() {
    if (_state.generation == 0 && _state.phase == RuntimePhase.idle) {
      return false;
    }
    _state = const RuntimeSnapshot(
      generation: 0,
      monotonicMs: 0,
      phase: RuntimePhase.idle,
      capabilities: RuntimeSnapshot.bundledCapabilities,
    );
    notifyListeners();
    return true;
  }

  /// Clears the baseline once, on the first payload seen after a gap.
  bool beginSession() {
    if (_sessionActive) return false;
    _sessionActive = true;
    return resetForNewSession();
  }

  /// Records that the mirrored session is gone, so the next payload starts a
  /// new generation sequence.
  void endSession() {
    _sessionActive = false;
  }

  bool apply(RuntimeSnapshot incoming) {
    if (incoming.generation < _state.generation) {
      return false;
    }
    if (incoming.generation == _state.generation &&
        incoming.monotonicMs <= _state.monotonicMs) {
      return false;
    }
    _state = incoming;
    notifyListeners();
    return true;
  }

  bool markUnknown() {
    if (_state.phase == RuntimePhase.unknown) return false;
    _state = RuntimeSnapshot(
      generation: _state.generation,
      monotonicMs: _state.monotonicMs,
      phase: RuntimePhase.unknown,
      role: _state.role,
      server: _state.server,
      transport: _state.transport,
      capabilities: _state.capabilities,
      requestedMuxMode: _state.requestedMuxMode,
      effectiveMuxMode: _state.effectiveMuxMode,
      muxReceiverOrdering: _state.muxReceiverOrdering,
      muxActiveLinks: _state.muxActiveLinks,
      muxFallbackReason: _state.muxFallbackReason,
      p2pState: P2PState.unavailable,
      lastError: _state.lastError,
    );
    notifyListeners();
    return true;
  }

  bool applyUnknown({required int generation, required int monotonicMs}) {
    if (generation < _state.generation ||
        (generation == _state.generation && monotonicMs <= _state.monotonicMs)) {
      return false;
    }
    _state = RuntimeSnapshot(
      generation: generation,
      monotonicMs: monotonicMs,
      phase: RuntimePhase.unknown,
      p2pState: P2PState.unavailable,
    );
    notifyListeners();
    return true;
  }
}
