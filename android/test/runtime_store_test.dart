import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';
import 'package:openppp2_mobile/runtime/runtime_store.dart';

RuntimeSnapshot snapshot(int generation, int monotonicMs, RuntimePhase phase) {
  return RuntimeSnapshot(
    generation: generation,
    monotonicMs: monotonicMs,
    phase: phase,
  );
}

void main() {
  test('initial store exposes bundled VMUX capabilities', () {
    expect(RuntimeStore().state.capabilities, RuntimeSnapshot.bundledCapabilities);
  });

  test('older generation cannot overwrite current state', () {
    final store =
        RuntimeStore(initial: snapshot(8, 100, RuntimePhase.connected));
    expect(store.apply(snapshot(7, 200, RuntimePhase.idle)), isFalse);
    expect(store.state.generation, 8);
    expect(store.state.phase, RuntimePhase.connected);
  });

  test('older event within the same generation is ignored', () {
    final store =
        RuntimeStore(initial: snapshot(8, 200, RuntimePhase.stopping));
    expect(store.apply(snapshot(8, 150, RuntimePhase.connected)), isFalse);
    expect(store.state.phase, RuntimePhase.stopping);
  });

  test('duplicate timestamp within the same generation is ignored', () {
    final store =
        RuntimeStore(initial: snapshot(8, 200, RuntimePhase.stopping));
    expect(store.apply(snapshot(8, 200, RuntimePhase.connected)), isFalse);
    expect(store.state.phase, RuntimePhase.stopping);
  });

  test('new generation replaces prior state', () {
    final store = RuntimeStore(initial: snapshot(8, 200, RuntimePhase.failed));
    expect(store.apply(snapshot(9, 1, RuntimePhase.starting)), isTrue);
    expect(store.state.generation, 9);
    expect(store.state.phase, RuntimePhase.starting);
  });

  test('invalid or unavailable snapshot is presented as unknown', () {
    final store = RuntimeStore(
      initial: RuntimeSnapshot(
        generation: 8,
        monotonicMs: 200,
        phase: RuntimePhase.connected,
        p2pState: P2PState.direct,
      ),
    );
    store.markUnknown();
    expect(store.state.generation, 8);
    expect(store.state.monotonicMs, 200);
    expect(store.state.phase, RuntimePhase.unknown);
    expect(store.state.p2pState, P2PState.unavailable);
    expect(store.state.effectivePath, 'relay');
    expect(store.apply(snapshot(8, 201, RuntimePhase.reconnecting)), isTrue);
    expect(store.state.phase, RuntimePhase.reconnecting);
  });

  test('ordered unknown rejects stale payload and advances generation watermark', () {
    final store = RuntimeStore(initial: snapshot(8, 200, RuntimePhase.connected));
    expect(store.applyUnknown(generation: 7, monotonicMs: 300), isFalse);
    expect(store.state.phase, RuntimePhase.connected);

    expect(store.applyUnknown(generation: 9, monotonicMs: 1), isTrue);
    expect(store.state.generation, 9);
    expect(store.state.phase, RuntimePhase.unknown);
    expect(store.state.p2pState, P2PState.unavailable);
    expect(store.state.effectivePath, 'relay');
    expect(store.apply(snapshot(8, 400, RuntimePhase.connected)), isFalse);
  });

  test('restarted session with a lower generation is accepted after reset', () {
    final store = RuntimeStore(initial: snapshot(9, 400, RuntimePhase.connected));
    expect(store.apply(snapshot(1, 10, RuntimePhase.starting)), isFalse);

    expect(store.resetForNewSession(), isTrue);
    expect(store.state.generation, 0);
    expect(store.state.phase, RuntimePhase.idle);

    expect(store.apply(snapshot(1, 10, RuntimePhase.starting)), isTrue);
    expect(store.state.generation, 1);
    expect(store.state.phase, RuntimePhase.starting);
  });

  test('reset on an already idle baseline reports no change', () {
    final store = RuntimeStore();
    expect(store.resetForNewSession(), isFalse);
  });

  test('session restart clears the baseline exactly once', () {
    final store = RuntimeStore();
    expect(store.beginSession(), isFalse);
    expect(store.apply(snapshot(9, 400, RuntimePhase.connected)), isTrue);

    // Still the same session: the baseline must hold and reject stale events.
    expect(store.beginSession(), isFalse);
    expect(store.apply(snapshot(1, 10, RuntimePhase.starting)), isFalse);
    expect(store.state.generation, 9);

    // `:vpn` died and came back with a fresh generation counter.
    store.endSession();
    expect(store.beginSession(), isTrue);
    expect(store.apply(snapshot(1, 10, RuntimePhase.starting)), isTrue);
    expect(store.state.generation, 1);
    expect(store.state.phase, RuntimePhase.starting);
  });

  test('reset restores bundled capabilities', () {
    final store = RuntimeStore(
      initial: RuntimeSnapshot(
        generation: 4,
        monotonicMs: 10,
        phase: RuntimePhase.connected,
        capabilities: const <String>['mux.compat'],
      ),
    );
    store.resetForNewSession();
    expect(store.state.capabilities, RuntimeSnapshot.bundledCapabilities);
  });
}
