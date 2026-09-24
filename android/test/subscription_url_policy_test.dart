import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/services/subscription_url_policy.dart';

void main() {
  group('SubscriptionUrlPolicy.isSecure', () {
    test('accepts https', () {
      expect(
        SubscriptionUrlPolicy.isSecure(Uri.parse('https://example.com/sub.json')),
        isTrue,
      );
    });

    test('rejects remote http', () {
      expect(
        SubscriptionUrlPolicy.isSecure(Uri.parse('http://example.com/sub.json')),
        isFalse,
      );
    });

    test('accepts loopback http', () {
      expect(
        SubscriptionUrlPolicy.isSecure(Uri.parse('http://localhost:8080/s.json')),
        isTrue,
      );
      expect(
        SubscriptionUrlPolicy.isSecure(Uri.parse('http://127.0.0.1/s.json')),
        isTrue,
      );
      expect(
        SubscriptionUrlPolicy.isSecure(Uri.parse('http://[::1]/s.json')),
        isTrue,
      );
    });

    test('rejects non-http schemes and missing authority', () {
      expect(SubscriptionUrlPolicy.isSecure(Uri.parse('ftp://x')), isFalse);
      expect(SubscriptionUrlPolicy.isSecure(Uri.parse('https:')), isFalse);
      expect(SubscriptionUrlPolicy.isSecure(null), isFalse);
    });
  });

  group('SubscriptionUrlPolicy redirects', () {
    test('recognizes common redirect statuses', () {
      for (final code in [301, 302, 303, 307, 308]) {
        expect(SubscriptionUrlPolicy.isRedirectStatus(code), isTrue);
      }
      expect(SubscriptionUrlPolicy.isRedirectStatus(200), isFalse);
    });

    test('maxRedirects is 5', () {
      expect(SubscriptionUrlPolicy.maxRedirects, 5);
    });
  });
}
