import 'dart:convert';
import 'dart:io';

import '../models/remote_subscription.dart';
import 'subscription_url_policy.dart';

class SubscriptionService {
  static const int maxBytes = 2 * 1024 * 1024;

  Future<RemoteSubscriptionResult> fetch(String urlText) async {
    var uri = Uri.tryParse(urlText.trim());
    if (!SubscriptionUrlPolicy.isSecure(uri)) {
      throw const FormatException('订阅地址必须是 https URL，本机开发地址除外');
    }

    final client = HttpClient();
    client.connectionTimeout = const Duration(seconds: 12);
    try {
      HttpClientResponse response;
      for (var redirects = 0;; redirects += 1) {
        final request = await client.getUrl(uri!);
        request.followRedirects = false;
        request.headers.set(HttpHeaders.acceptHeader, 'application/json');
        request.headers.set(HttpHeaders.userAgentHeader, 'OpenPPP2/Android');
        response = await request.close();

        if (!SubscriptionUrlPolicy.isRedirectStatus(response.statusCode)) {
          break;
        }
        if (redirects >= SubscriptionUrlPolicy.maxRedirects) {
          throw const HttpException('订阅重定向次数过多');
        }
        final location = response.headers.value(HttpHeaders.locationHeader);
        if (location == null || location.isEmpty) {
          throw const FormatException('订阅重定向缺少 Location');
        }
        final next = uri.resolve(location);
        if (!SubscriptionUrlPolicy.isSecure(next)) {
          throw const FormatException('订阅重定向必须保持 HTTPS，本机开发地址除外');
        }
        await response.drain<void>();
        uri = next;
      }

      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw HttpException('订阅请求失败: HTTP ${response.statusCode}');
      }

      final chunks = <int>[];
      await for (final chunk in response) {
        chunks.addAll(chunk);
        if (chunks.length > maxBytes) {
          throw const FormatException('订阅响应超过 2MB');
        }
      }
      return RemoteSubscriptionParser.parse(utf8.decode(chunks));
    } finally {
      client.close(force: true);
    }
  }
}
