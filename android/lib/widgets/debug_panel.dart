import 'package:flutter/material.dart';
import '../runtime/runtime_snapshot.dart';

/// Operational/error log panel.
///
/// We deliberately do NOT show traffic statistics in this panel: per upstream
/// feedback, traffic numbers are noise during diagnosis. Instead we filter the
/// raw log to only the lines users actually care about (errors, warnings,
/// state transitions, native run/return) and display them most-recent-first.
class DebugPanel extends StatelessWidget {
  final String stateText;
  final String logPath;
  final String logText;
  final VoidCallback onRefresh;
  final VoidCallback onCopy;
  final VoidCallback onClear;
  final VoidCallback onStop;
  final RuntimeSnapshot runtimeSnapshot;

  const DebugPanel({
    super.key,
    required this.stateText,
    required this.logPath,
    required this.logText,
    required this.onRefresh,
    required this.onCopy,
    required this.onClear,
    required this.onStop,
    required this.runtimeSnapshot,
  });

  static final _trafficNoise = RegExp(
    r'(statistics=|onStatistics|setStatistics|in/out=)',
    caseSensitive: false,
  );

  static final _interesting = RegExp(
    r'(error|fail|exception|abort|crash|denied|timeout|refused|reset|'
    r'connect requested|disconnect requested|stopVpn|onStartCommand|'
    r'startForeground|builder\.establish|set_app_configuration|'
    r'set_network_interface|set_bypass_ip_list|set_dns_rules_list|'
    r'libopenppp2\.run|onStarted|VPN started|onRevoke|'
    r'state=|notifyError)',
    caseSensitive: false,
  );

  List<String> _filter(String raw) {
    if (raw.trim().isEmpty) return const [];
    final lines = raw.split('\n');
    final out = <String>[];
    for (final line in lines) {
      if (line.isEmpty) continue;
      if (_trafficNoise.hasMatch(line)) continue;
      if (_interesting.hasMatch(line)) out.add(line);
    }
    // Most-recent-first.
    return out.reversed.toList();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final filtered = _filter(logText);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    '运行日志（仅错误/状态）',
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                IconButton(
                  tooltip: '刷新',
                  onPressed: onRefresh,
                  icon: const Icon(Icons.refresh),
                ),
                IconButton(
                  tooltip: '复制全部原始日志',
                  onPressed: onCopy,
                  icon: const Icon(Icons.copy),
                ),
                IconButton(
                  tooltip: '清空',
                  onPressed: onClear,
                  icon: const Icon(Icons.delete_outline),
                ),
                IconButton(
                  tooltip: '停止 VPN',
                  onPressed: onStop,
                  icon: const Icon(Icons.stop_circle_outlined),
                ),
              ],
            ),
            Text('状态: $stateText'),
            const SizedBox(height: 4),
            for (final line in runtimeSnapshot.muxDiagnosticLines) Text(line),
            for (final line in runtimeSnapshot.p2pDiagnosticLines) Text(line),
            SelectableText(
              '日志文件: ${logPath.isEmpty ? '(未知)' : logPath}',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            Container(
              constraints: const BoxConstraints(minHeight: 160, maxHeight: 320),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: theme.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              child: filtered.isEmpty
                  ? Center(
                      child: Text(
                        '(暂无错误或状态日志)',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    )
                  : ListView.builder(
                      itemCount: filtered.length,
                      itemBuilder: (ctx, i) {
                        final line = filtered[i];
                        final isErr = RegExp(
                          r'(error|fail|exception|abort|crash|denied|timeout|refused|reset)',
                          caseSensitive: false,
                        ).hasMatch(line);
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 4),
                          child: SelectableText(
                            line,
                            style: theme.textTheme.bodySmall?.copyWith(
                              fontFamily: 'monospace',
                              color: isErr
                                  ? theme.colorScheme.error
                                  : theme.colorScheme.onSurface,
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }
}
