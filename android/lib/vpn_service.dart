import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import 'runtime/runtime_bridge.dart';
import 'runtime/runtime_snapshot.dart';
import 'runtime/runtime_store.dart';
import 'runtime/runtime_traffic_rate.dart';

class VpnService with WidgetsBindingObserver {
  static const _channel = MethodChannel('supersocksr.ppp/vpn');

  static final VpnService _instance = VpnService._internal();
  factory VpnService() => _instance;
  VpnService._internal();

  final _errorController = StreamController<String>.broadcast();
  Stream<String> get errorStream => _errorController.stream;

  final RuntimeStore runtimeStore = RuntimeStore();

  RuntimeTrafficRate _traffic = const RuntimeTrafficRate();
  RuntimeTrafficRate get traffic => _traffic;
  RuntimeSnapshot? _previousTrafficSample;

  bool _initialized = false;
  Timer? _runtimePollTimer;
  String? _lastReportedError;

  void init() {
    if (_initialized) return;
    _initialized = true;
    WidgetsBinding.instance.addObserver(this);
    _startRuntimePolling();
  }

  /// Nothing reads the mirror while the app is not visible, and the files it
  /// polls persist, so the timer is stopped in the background and resumed with
  /// an immediate read.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _startRuntimePolling();
      return;
    }
    stopPolling();
  }

  /// Stops reading the mirror. This service is an app-lifetime singleton, so a
  /// widget test that builds the whole app must call this before it ends —
  /// `flutter_test` checks for pending timers before it tears the tree down.
  void stopPolling() {
    _runtimePollTimer?.cancel();
    _runtimePollTimer = null;
  }

  void _applyRuntimeSnapshot(String raw) {
    try {
      final snapshot = decodeRuntimeSnapshot(raw);
      if (runtimeStore.apply(snapshot)) {
        _traffic = RuntimeTrafficRate.between(_previousTrafficSample, snapshot);
        if (RuntimeTrafficRate.advancesTrafficBaseline(
          _previousTrafficSample,
          snapshot,
        )) {
          _previousTrafficSample = snapshot;
        }
      }
    } catch (error) {
      try {
        final ordering = decodeRuntimeOrdering(raw);
        runtimeStore.applyUnknown(
          generation: ordering.generation,
          monotonicMs: ordering.monotonicMs,
        );
      } catch (_) {
        // A payload without ordering metadata cannot mutate current UI state.
      }
      _errorController.add('Invalid runtime snapshot: $error');
    }
  }

  /// The `:vpn` service runs in its own process and cannot reach the UI
  /// process's method channel, so it mirrors every published snapshot to a
  /// file. Polling that mirror is safe because snapshots carry their own
  /// generation and timestamp ordering.
  void _startRuntimePolling() {
    _runtimePollTimer?.cancel();
    _runtimePollTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => unawaited(_pollRuntime()),
    );
    unawaited(_pollRuntime());
  }

  /// True while the UI has started a connect and is waiting for the first
  /// non-idle runtime phase. Empty mirror polls must not mark unknown.
  bool connecting = false;

  Future<void> _pollRuntime() async {
    applyRuntimeSnapshotPoll(
      await getRuntimeSnapshot(),
      connecting: connecting,
    );
    final error = await getLastError();
    if (error.isEmpty) {
      _lastReportedError = null;
      return;
    }
    if (error == _lastReportedError) return;
    _lastReportedError = error;
    _errorController.add(error);
  }

  /// Applies one mirror read. A null payload means the service is not alive,
  /// so the next payload is treated as a new session.
  ///
  /// During an in-flight connect the first polls often race the `:vpn`
  /// heartbeat. Treat those empty reads as "not yet" rather than flipping the
  /// UI to unknown and clearing the session baseline.
  void applyRuntimeSnapshotPoll(
    String? raw, {
    bool connecting = false,
  }) {
    if (raw == null || raw.trim().isEmpty) {
      if (connecting) {
        return;
      }
      runtimeStore.endSession();
      _resetTraffic();
      _markRuntimeUnavailable();
      return;
    }
    runtimeStore.beginSession();
    _applyRuntimeSnapshot(raw);
  }

  void _markRuntimeUnavailable() {
    final phase = runtimeStore.state.phase;
    if (phase == RuntimePhase.idle || phase == RuntimePhase.failed) return;
    runtimeStore.markUnknown();
  }

  void _resetTraffic() {
    _traffic = const RuntimeTrafficRate();
    _previousTrafficSample = null;
  }

  Future<bool> connect(
    String jsonConfig, {
    Map<String, dynamic>? vpnOptions,
  }) async {
    try {
      _resetTraffic();
      final result = await _channel.invokeMethod<bool>('connect', {
        'configJson': jsonConfig,
        'vpnOptions': vpnOptions ?? <String, dynamic>{},
      });
      return result ?? false;
    } on PlatformException catch (e) {
      final details = e.details?.toString();
      throw Exception(
        details == null || details.isEmpty
            ? 'VPN connect failed: ${e.message}'
            : 'VPN connect failed: ${e.message}\n$details',
      );
    }
  }

  Future<bool> disconnect() async {
    try {
      final result = await _channel.invokeMethod<bool>('disconnect');
      return result ?? false;
    } on PlatformException catch (e) {
      throw Exception('VPN disconnect failed: ${e.message}');
    }
  }

  /// Runtime snapshot mirrored by the `:vpn` service, or null while that
  /// process is not alive.
  Future<String?> getRuntimeSnapshot() async {
    try {
      return await _channel.invokeMethod<String>('getRuntimeSnapshot');
    } on PlatformException {
      return null;
    }
  }

  /// Last failure reported by the `:vpn` service. Errors raised around the
  /// native call never reach the runtime snapshot, so they are mirrored
  /// separately.
  Future<String> getLastError() async {
    try {
      return await _channel.invokeMethod<String>('getLastError') ?? '';
    } on PlatformException {
      return '';
    }
  }

  Future<String> readLog() async {
    try {
      return await _channel.invokeMethod<String>('readLog') ?? '';
    } on PlatformException catch (e) {
      return 'readLog failed: ${e.message}';
    }
  }

  Future<String> getLogPath() async {
    try {
      return await _channel.invokeMethod<String>('getLogPath') ?? '';
    } on PlatformException catch (e) {
      return 'getLogPath failed: ${e.message}';
    }
  }

  Future<void> clearLog() async {
    try {
      await _channel.invokeMethod<bool>('clearLog');
    } on PlatformException {
      return;
    }
  }

  /// Milliseconds since the `:vpn` process last wrote its link-state
  /// heartbeat file. Returns -1 if no VPN session has started yet, or
  /// a large value when `:vpn` is dead/crashed. The UI uses this as a
  /// liveness signal during long native operations (e.g. geo-rules
  /// parsing) where the runtime phase does not progress.
  Future<int> getVpnHeartbeatAgeMs() async {
    try {
      final v = await _channel.invokeMethod<int>('getVpnHeartbeatAgeMs');
      return v ?? -1;
    } on PlatformException {
      return -1;
    }
  }

  /// Returns the list of installed user apps with INTERNET permission. Each
  /// entry is `{ 'package': String, 'label': String, 'system': bool }`. Pass
  /// `includeSystem: true` to also include system packages.
  Future<List<Map<String, dynamic>>> getInstalledApps({
    bool includeSystem = false,
  }) async {
    try {
      final raw = await _channel.invokeMethod<List<dynamic>>(
        'getInstalledApps',
        {'includeSystem': includeSystem},
      );
      if (raw == null) return const [];
      return raw
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList(growable: false);
    } on PlatformException {
      return const [];
    }
  }

  /// Returns the base64-encoded PNG icon for `package`, or `null` when the
  /// icon cannot be resolved (e.g. uninstalled app).
  Future<String?> getAppIcon(String package) async {
    try {
      return await _channel.invokeMethod<String>(
        'getAppIcon',
        {'package': package},
      );
    } on PlatformException {
      return null;
    }
  }

  Future<bool> requestVpnPermission() async {
    try {
      final result = await _channel.invokeMethod<bool>('requestPermission');
      return result ?? false;
    } on PlatformException {
      return false;
    }
  }

  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _runtimePollTimer?.cancel();
    _errorController.close();
  }
}
