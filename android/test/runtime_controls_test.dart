import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_controls.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';

void main() {
  test('phase mapping is authoritative for connection actions', () {
    expect(
        controlsFor(RuntimePhase.idle).action, RuntimeConnectionAction.start);
    expect(controlsFor(RuntimePhase.connected).action,
        RuntimeConnectionAction.stop);
    expect(controlsFor(RuntimePhase.reconnecting).action,
        RuntimeConnectionAction.stop);
    expect(controlsFor(RuntimePhase.stopping).action,
        RuntimeConnectionAction.none);
    expect(
        controlsFor(RuntimePhase.failed).action, RuntimeConnectionAction.retry);
    expect(controlsFor(RuntimePhase.unknown).action,
        RuntimeConnectionAction.forceStop);
  });

  test('configuration is editable only when idle or failed', () {
    for (final phase in RuntimePhase.values) {
      expect(
        controlsFor(phase).configEditable,
        phase == RuntimePhase.idle || phase == RuntimePhase.failed,
        reason: phase.name,
      );
    }
  });

  test('stop timeout changes presentation without enabling an action', () {
    final controls = controlsFor(
      RuntimePhase.stopping,
      stopTakingTooLong: true,
    );
    expect(controls.action, RuntimeConnectionAction.none);
    expect(controls.buttonEnabled, isFalse);
    expect(controls.detailLabel, '停止耗时过长');
  });
}
