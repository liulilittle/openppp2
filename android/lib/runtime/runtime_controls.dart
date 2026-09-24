import 'runtime_snapshot.dart';

enum RuntimeConnectionAction { start, cancel, stop, retry, forceStop, none }

class RuntimeControlState {
  const RuntimeControlState({
    required this.action,
    required this.buttonEnabled,
    required this.buttonLabel,
    required this.statusLabel,
    required this.detailLabel,
    required this.configEditable,
    this.isConnected = false,
    this.isBusy = false,
    this.diagnosticsAvailable = false,
  });

  final RuntimeConnectionAction action;
  final bool buttonEnabled;
  final String buttonLabel;
  final String statusLabel;
  final String detailLabel;
  final bool configEditable;
  final bool isConnected;
  final bool isBusy;
  final bool diagnosticsAvailable;
}

RuntimeControlState controlsFor(
  RuntimePhase phase, {
  bool stopTakingTooLong = false,
}) {
  switch (phase) {
    case RuntimePhase.idle:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.start,
        buttonEnabled: true,
        buttonLabel: '连接',
        statusLabel: '未连接',
        detailLabel: '准备连接',
        configEditable: true,
      );
    case RuntimePhase.starting:
    case RuntimePhase.preparingHost:
    case RuntimePhase.connecting:
    case RuntimePhase.handshaking:
    case RuntimePhase.applyingPolicy:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.cancel,
        buttonEnabled: true,
        buttonLabel: '取消',
        statusLabel: '连接中...',
        detailLabel: 'VPN 正在启动',
        configEditable: false,
        isBusy: true,
      );
    case RuntimePhase.connected:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.stop,
        buttonEnabled: true,
        buttonLabel: '停止',
        statusLabel: '已连接',
        detailLabel: '',
        configEditable: false,
        isConnected: true,
      );
    case RuntimePhase.reconnecting:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.stop,
        buttonEnabled: true,
        buttonLabel: '停止',
        statusLabel: '重连中...',
        detailLabel: '网络已变化',
        configEditable: false,
        isBusy: true,
      );
    case RuntimePhase.stopping:
      return RuntimeControlState(
        action: RuntimeConnectionAction.none,
        buttonEnabled: false,
        buttonLabel: '停止',
        statusLabel: '断开中...',
        detailLabel: stopTakingTooLong ? '停止耗时过长' : '正在停止 VPN',
        configEditable: false,
        isBusy: true,
      );
    case RuntimePhase.failed:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.retry,
        buttonEnabled: true,
        buttonLabel: '重试',
        statusLabel: '连接失败',
        detailLabel: '检查配置后重试',
        configEditable: true,
      );
    case RuntimePhase.unknown:
      return const RuntimeControlState(
        action: RuntimeConnectionAction.forceStop,
        buttonEnabled: true,
        buttonLabel: '强制停止',
        statusLabel: '未知状态',
        detailLabel: '请查看诊断信息',
        configEditable: false,
        diagnosticsAvailable: true,
      );
  }
}
