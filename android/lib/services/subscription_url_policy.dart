/// Policy for remote subscription fetch URLs (HTTPS by default).
class SubscriptionUrlPolicy {
  static const int maxRedirects = 5;

  /// Accepts https anywhere, or http only to loopback development hosts.
  static bool isSecure(Uri? uri) {
    if (uri == null || !uri.hasAuthority) return false;
    final scheme = uri.scheme.toLowerCase();
    if (scheme == 'https') return true;
    if (scheme != 'http') return false;
    final host = uri.host.toLowerCase();
    return host == 'localhost' ||
        host == '127.0.0.1' ||
        host == '::1' ||
        host == '[::1]';
  }

  static bool isRedirectStatus(int statusCode) =>
      statusCode == 301 ||
      statusCode == 302 ||
      statusCode == 303 ||
      statusCode == 307 ||
      statusCode == 308;
}
