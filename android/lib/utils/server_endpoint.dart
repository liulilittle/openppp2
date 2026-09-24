import 'dart:io';

class ServerEndpoint {
  /// Dial scheme used by native UriAuxiliary: ppp|tcp|ws|wss.
  final String scheme;
  final String host;
  final int? port;
  /// Request path for ws/wss (e.g. `/tun`). Empty/normalized to `/` for ppp.
  final String path;

  const ServerEndpoint({
    this.scheme = 'ppp',
    required this.host,
    this.port,
    this.path = '/',
  });

  static ServerEndpoint parse(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      return const ServerEndpoint(host: '');
    }

    final lower = trimmed.toLowerCase();
    if (lower.startsWith('ws://') || lower.startsWith('wss://')) {
      final uri = Uri.tryParse(trimmed);
      if (uri != null && uri.host.isNotEmpty) {
        return ServerEndpoint(
          scheme: uri.scheme.toLowerCase(),
          host: uri.host,
          port: uri.hasPort ? uri.port : null,
          path: _normalizePath(uri.path),
        );
      }
    }

    const pppScheme = 'ppp://';
    if (trimmed.startsWith(pppScheme)) {
      final rest = trimmed.substring(pppScheme.length);
      final parts = rest.split('/');
      // Legacy display form: ppp://ws/host:port/ or ppp://wss/host:port/
      if (parts.isNotEmpty &&
          (parts.first.toLowerCase() == 'ws' ||
              parts.first.toLowerCase() == 'wss') &&
          parts.length > 1) {
        final transport = parts.first.toLowerCase();
        final authority = parts[1];
        final endpoint = _parseAuthority(authority);
        final pathParts = parts.skip(2).where((p) => p.isNotEmpty).toList();
        final path =
            pathParts.isEmpty ? '/' : '/${pathParts.join('/')}';
        return ServerEndpoint(
          scheme: transport,
          host: endpoint.host,
          port: endpoint.port,
          path: _normalizePath(path),
        );
      }

      final authority = parts.isNotEmpty ? parts.first : rest;
      final endpoint = _parseAuthority(authority);
      final pathParts = parts.skip(1).where((p) => p.isNotEmpty).toList();
      final path = pathParts.isEmpty ? '/' : '/${pathParts.join('/')}';
      return ServerEndpoint(
        scheme: 'ppp',
        host: endpoint.host,
        port: endpoint.port,
        path: _normalizePath(path),
      );
    }

    final uri = Uri.tryParse(trimmed);
    if (uri != null && uri.host.isNotEmpty) {
      final scheme = uri.scheme.isEmpty ? 'ppp' : uri.scheme.toLowerCase();
      return ServerEndpoint(
        scheme: scheme == 'tcp' ? 'ppp' : scheme,
        host: uri.host,
        port: uri.hasPort ? uri.port : null,
        path: _normalizePath(uri.path),
      );
    }

    final endpoint = _parseAuthority(trimmed);
    return ServerEndpoint(host: endpoint.host, port: endpoint.port);
  }

  static ServerEndpoint _parseAuthority(String authority) {
    final raw = authority.trim();
    if (raw.isEmpty) return const ServerEndpoint(host: '');

    if (raw.startsWith('[')) {
      final end = raw.indexOf(']');
      if (end > 0) {
        final host = raw.substring(1, end);
        final rest = raw.substring(end + 1);
        final port =
            rest.startsWith(':') ? int.tryParse(rest.substring(1)) : null;
        return ServerEndpoint(host: host, port: port);
      }
    }

    final colonCount = ':'.allMatches(raw).length;
    if (colonCount > 1) {
      final lastColon = raw.lastIndexOf(':');
      final hostCandidate = raw.substring(0, lastColon);
      final tail = raw.substring(lastColon + 1);
      final port = int.tryParse(tail);
      if (port != null && _isValidIpv6Address(hostCandidate)) {
        return ServerEndpoint(host: hostCandidate, port: port);
      }
      return ServerEndpoint(host: raw);
    }

    final colon = raw.lastIndexOf(':');
    if (colon > 0) {
      final port = int.tryParse(raw.substring(colon + 1));
      if (port != null) {
        return ServerEndpoint(host: raw.substring(0, colon), port: port);
      }
    }
    return ServerEndpoint(host: raw);
  }

  /// Always emits `ppp://…` — preferred for plain TCP.
  String toPppUrl() => toUrl(forceScheme: 'ppp');

  /// Emits a dial URL for the endpoint's scheme (ppp/ws/wss).
  String toUrl({String? forceScheme}) {
    final effectiveScheme = (forceScheme ?? this.scheme).toLowerCase();
    final normalizedHost = host.trim();
    final urlHost = _needsIpv6Brackets(normalizedHost)
        ? '[$normalizedHost]'
        : normalizedHost;
    final portPart = port != null && port! > 0 ? ':$port' : '';
    if (effectiveScheme == 'ws' || effectiveScheme == 'wss') {
      final pathPart = _normalizePath(path);
      return '$effectiveScheme://$urlHost$portPart$pathPart';
    }
    // Native TCP transport.
    return 'ppp://$urlHost$portPart/';
  }

  static String _normalizePath(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed == '/') return '/';
    return trimmed.startsWith('/') ? trimmed : '/$trimmed';
  }

  static bool _isValidIpv6Address(String value) {
    return InternetAddress.tryParse(value)?.type == InternetAddressType.IPv6;
  }

  static bool _needsIpv6Brackets(String host) =>
      host.contains(':') && !(host.startsWith('[') && host.endsWith(']'));
}
