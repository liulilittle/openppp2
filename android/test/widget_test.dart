// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:openppp2_mobile/main.dart';
import 'package:openppp2_mobile/vpn_service.dart';

void main() {
  testWidgets('App shell renders home navigation', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const OpenPPP2App());

    // The runtime mirror poll runs on an app-lifetime singleton. flutter_test
    // checks for pending timers right after the body and before it tears the
    // tree down, so a tearDown callback would be too late.
    VpnService().stopPolling();

    // Verify that the home tab renders the current connection state and shell.
    expect(find.text('未连接'), findsOneWidget);
    expect(find.text('主页'), findsOneWidget);
    expect(find.text('启动参数'), findsOneWidget);
    expect(find.text('设置'), findsOneWidget);
    // Bottom nav + home embedded profile section both use this label.
    expect(find.text('配置文件'), findsNWidgets(2));
  });
}
