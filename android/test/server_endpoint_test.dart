import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/utils/server_endpoint.dart';

void main() {
  group('ServerEndpoint', () {
    // Aim: RFC-style bracketed IPv6 authority parses host and port.
    test('parses bracketed IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://[2001:db8::1]:20000/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, 20000);
    });

    // Aim: legacy URLs without brackets still split host/port on last colon.
    test('parses legacy unbracketed IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://2001:db8::1:20000/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, 20000);
    });

    // Aim: unbracketed IPv6 without a trailing port keeps port null.
    test('preserves legacy unbracketed IPv6 server URLs without ports', () {
      final endpoint = ServerEndpoint.parse('ppp://2001:db8::1/');

      expect(endpoint.host, '2001:db8::1');
      expect(endpoint.port, isNull);
    });

    // Aim: IPv4-mapped IPv6 (::ffff:…) uses last-colon port split, not full string as host.
    test('parses legacy unbracketed IPv4-mapped IPv6 server URLs', () {
      final endpoint = ServerEndpoint.parse('ppp://::ffff:192.0.2.128:20000/');

      expect(endpoint.host, '::ffff:192.0.2.128');
      expect(endpoint.port, 20000);
    });

    // Aim: toPppUrl() wraps bare IPv6 hosts in brackets for valid URLs.
    test('formats IPv6 host with brackets for URLs', () {
      final url = ServerEndpoint(host: '2001:db8::1', port: 20000).toPppUrl();

      expect(url, 'ppp://[2001:db8::1]:20000/');
    });

    // Aim: IPv4 and domain hosts are serialized without brackets.
    test('formats IPv4 and domain hosts without brackets', () {
      expect(ServerEndpoint(host: '192.0.2.10', port: 20000).toPppUrl(),
          'ppp://192.0.2.10:20000/');
      expect(ServerEndpoint(host: 'vpn.example.com', port: 20000).toPppUrl(),
          'ppp://vpn.example.com:20000/');
    });

    test('parses websocket transport prefix', () {
      final ws = ServerEndpoint.parse('ppp://ws/vpn.example.com:20000/');
      expect(ws.host, 'vpn.example.com');
      expect(ws.port, 20000);
      expect(ws.scheme, 'ws');

      final wss = ServerEndpoint.parse('ppp://wss/[2001:db8::1]:443/');
      expect(wss.host, '2001:db8::1');
      expect(wss.port, 443);
      expect(wss.scheme, 'wss');
    });

    test('parses native ws URL with path and preserves it on toUrl', () {
      final endpoint = ServerEndpoint.parse('ws://haruka-hk.581006.xyz:20080/tun');
      expect(endpoint.scheme, 'ws');
      expect(endpoint.host, 'haruka-hk.581006.xyz');
      expect(endpoint.port, 20080);
      expect(endpoint.path, '/tun');
      expect(endpoint.toUrl(), 'ws://haruka-hk.581006.xyz:20080/tun');
    });

    test('form-style rebuild no longer forces ppp for ws endpoints', () {
      final original = ServerEndpoint.parse('ws://vpn.example.com:20080/tun');
      final rebuilt = ServerEndpoint(
        scheme: original.scheme,
        host: original.host,
        port: original.port,
        path: original.path,
      );
      expect(rebuilt.toUrl(), 'ws://vpn.example.com:20080/tun');
      expect(rebuilt.toPppUrl(), 'ppp://vpn.example.com:20080/');
    });
  });

  group('ServerEndpoint negative and regression', () {
    // Aim: unclosed bracket does not crash; parser still yields some host text.
    test('rejects_malformed_unclosed_ipv6_bracket', () {
      final endpoint = ServerEndpoint.parse('ppp://[2001:db8::1');
      expect(endpoint.host, isNotEmpty);
    });

    // Aim: regression guard for IPv4-mapped host/port splitting (issue-prone path).
    test('regression_ipv4_mapped_host_port_split', () {
      final endpoint = ServerEndpoint.parse('ppp://::ffff:192.0.2.128:20000/');
      expect(endpoint.host, '::ffff:192.0.2.128');
      expect(endpoint.port, 20000);
    });

    // Aim: empty input yields empty host and no port (boundary).
    test('rejects_empty_input_host', () {
      final endpoint = ServerEndpoint.parse('');
      expect(endpoint.host, '');
      expect(endpoint.port, isNull);
    });

    // Aim: bracketed loopback without port keeps port null.
    test('boundary_ipv6_without_port', () {
      final endpoint = ServerEndpoint.parse('ppp://[::1]/');
      expect(endpoint.host, '::1');
      expect(endpoint.port, isNull);
    });
  });
}
