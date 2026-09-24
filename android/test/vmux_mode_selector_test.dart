import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/runtime/runtime_snapshot.dart';
import 'package:openppp2_mobile/widgets/vmux_mode_selector.dart';

RuntimeSnapshot snapshot({
  String effective = 'compat',
  List<String> capabilities = const <String>[
    'mux.compat',
    'mux.flow',
    'mux.balance',
    'mux.stripe',
  ],
}) => RuntimeSnapshot(
      generation: 1,
      monotonicMs: 1,
      phase: RuntimePhase.connected,
      capabilities: capabilities,
      effectiveMuxMode: effective,
    );

void main() {
  testWidgets('selector hides stripe and renders compatibility fallback',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: VmuxModeSelector(
          snapshot: snapshot(capabilities: const ['mux.compat', 'mux.flow']),
          selectedMode: 'compat',
          onChanged: (_) {},
        ),
      ),
    ));

    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();

    expect(find.text('Compatibility mode'), findsWidgets);
    expect(find.text('stripe'), findsNothing);
    expect(find.text('balance'), findsNothing);
    expect(find.text('Takes effect on next connection'), findsOneWidget);
  });

  testWidgets('selector reveals stripe only in experimental mode',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(
        body: VmuxModeSelector(
          snapshot: snapshot(effective: 'flow'),
          selectedMode: 'compat',
          experimental: true,
          onChanged: (_) {},
        ),
      ),
    ));
    await tester.tap(find.byType(DropdownButtonFormField<String>));
    await tester.pumpAndSettle();

    expect(find.text('stripe'), findsOneWidget);
  });
}
