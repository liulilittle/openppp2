import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';
import 'package:openppp2_mobile/vpn_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('supersocksr.ppp/vpn');
  final service = VpnService();

  void mock(Future<Object?> Function(MethodCall call) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, handler);
  }

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('runtime snapshot mirror', () {
    test('returns the mirrored payload', () async {
      mock((call) async {
        if (call.method == 'getRuntimeSnapshot') {
          return '{"schema_version":1,"generation":3,"monotonic_ms":10,'
              '"phase":"connected"}';
        }
        return null;
      });

      final raw = await service.getRuntimeSnapshot();
      expect(raw, contains('"phase":"connected"'));
    });

    test('returns null while the vpn process is not alive', () async {
      mock((call) async => null);
      expect(await service.getRuntimeSnapshot(), isNull);
    });

    test('returns null instead of throwing when the channel fails', () async {
      mock((call) async => throw PlatformException(code: 'UNAVAILABLE'));
      expect(await service.getRuntimeSnapshot(), isNull);
    });
  });

  group('last error mirror', () {
    test('returns the mirrored message', () async {
      mock((call) async {
        if (call.method == 'getLastError') {
          return 'Failed to establish VPN interface';
        }
        return null;
      });

      expect(await service.getLastError(), 'Failed to establish VPN interface');
    });

    test('returns empty when there is no error or the channel fails', () async {
      mock((call) async => null);
      expect(await service.getLastError(), '');

      mock((call) async => throw PlatformException(code: 'UNAVAILABLE'));
      expect(await service.getLastError(), '');
    });
  });

  group('poll application', () {
    test('an unavailable mirror ends the session', () {
      final store = service.runtimeStore;
      store.endSession();
      store.resetForNewSession();

      service.applyRuntimeSnapshotPoll(
        '{"schema_version":1,"generation":9,"monotonic_ms":400,'
        '"phase":"connected"}',
      );
      expect(store.state.phase, RuntimePhase.connected);
      expect(store.state.generation, 9);

      service.applyRuntimeSnapshotPoll(null);
      expect(store.state.phase, RuntimePhase.unknown);

      // The restarted session counts generations from zero again.
      service.applyRuntimeSnapshotPoll(
        '{"schema_version":1,"generation":1,"monotonic_ms":5,'
        '"phase":"starting"}',
      );
      expect(store.state.generation, 1);
      expect(store.state.phase, RuntimePhase.starting);
    });

    test('empty polls during connect do not flip to unknown', () {
      final store = service.runtimeStore;
      store.endSession();
      store.resetForNewSession();
      service.connecting = true;

      service.applyRuntimeSnapshotPoll(null, connecting: true);
      expect(store.state.phase, RuntimePhase.idle);

      service.applyRuntimeSnapshotPoll(
        '{"schema_version":1,"generation":1,"monotonic_ms":10,'
        '"phase":"connected"}',
        connecting: true,
      );
      expect(store.state.phase, RuntimePhase.connected);
      service.connecting = false;
    });
  });
}
