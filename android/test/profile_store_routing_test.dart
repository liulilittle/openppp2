import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:openppp2_mobile/services/profile_store.dart';

void main() {
  const profileJson = '''
{
  "client": {
    "proxy-only": false,
    "routes": [
      {"path": "./legacy-routes.txt"}
    ],
    "peer-routes": [
      {"network": "10.20.0.0", "prefix": 24, "via": "10.0.0.3"}
    ]
  }
}
''';

  Map<String, dynamic> mergedRoot(Map<String, dynamic> options) {
    return jsonDecode(ProfileStore.effectiveJson(profileJson, options))
        as Map<String, dynamic>;
  }

  Map<String, dynamic> routingOf(Map<String, dynamic> root) {
    return Map<String, dynamic>.from(
      (root['client'] as Map<String, dynamic>)['routing'] as Map,
    );
  }

  test('global mode emits an empty canonical bypass list', () {
    final root = mergedRoot({
      'routeMode': 'global',
      'bypassIpList': '10.0.0.0/8\n192.168.0.0/16',
      'dnsRulesList': '',
    });
    final routing = routingOf(root);
    final ip = routing['ip'] as Map<String, dynamic>;

    expect(routing.containsKey('mode'), isFalse);
    expect(ip['bypass'], isEmpty);
  });

  test('basic mode trims and splits canonical bypass sources', () {
    final root = mergedRoot({
      'routeMode': 'basic',
      'bypassIpList': ' 10.0.0.0/8\n\n 192.168.0.0/16 \n',
      'dnsRulesList': '',
    });
    final routing = routingOf(root);
    final ip = routing['ip'] as Map<String, dynamic>;

    expect(ip['bypass'], ['10.0.0.0/8', '192.168.0.0/16']);
  });

  test('geo mode keeps canonical bypass sources', () {
    final root = mergedRoot({
      'routeMode': 'geo',
      'bypassIpList': ' 10.0.0.0/8\n\n 172.16.0.0/12',
      'dnsRulesList': '',
    });
    final routing = routingOf(root);
    final ip = routing['ip'] as Map<String, dynamic>;

    expect(routing.containsKey('mode'), isFalse);
    expect(ip['bypass'], ['10.0.0.0/8', '172.16.0.0/12']);
  });

  test('proxy-only mode uses the independent top-level flag', () {
    final root = mergedRoot({
      'routeMode': 'basic',
      'proxyOnly': true,
      'bypassIpList': '10.0.0.0/8',
      'dnsRulesList': 'example.com /cloudflare/tun',
    });
    final client = root['client'] as Map<String, dynamic>;
    final routing = client['routing'] as Map<String, dynamic>;
    final ip = routing['ip'] as Map<String, dynamic>;
    final dns = routing['dns'] as Map<String, dynamic>;

    expect(routing.containsKey('mode'), isFalse);
    expect(client['proxy-only'], isTrue);
    expect(ip['bypass'], ['10.0.0.0/8']);
    expect(dns['rules'], ['example.com /cloudflare/tun']);
  });

  // Historical fixture: `routing.mode` was a pre-canonical field that has
  // since been removed from the production schema.  This test verifies that
  // profiles containing the old key are silently upgraded: the key must not
  // appear in the effective JSON, and proxy-only state must come exclusively
  // from the independent top-level `client.proxy-only` flag.
  test('legacy routing mode is ignored and not serialized', () {
    const oldProfileJson = '''
{
  "client": {
    "proxy-only": false,
    "routing": {
      "mode": "proxy-only",
      "ip": {"bypass": ["10.0.0.0/8"]}
    }
  }
}
''';

    Map<String, dynamic> load(bool proxyOnly) {
      return jsonDecode(ProfileStore.effectiveJson(oldProfileJson, {
        'routeMode': 'basic',
        'proxyOnly': proxyOnly,
        'bypassIpList': '',
        'dnsRulesList': '',
      })) as Map<String, dynamic>;
    }

    final client = load(false)['client'] as Map<String, dynamic>;
    final routing = client['routing'] as Map<String, dynamic>;
    expect(routing.containsKey('mode'), isFalse);
    expect(client['proxy-only'], isFalse);

    final proxyClient = load(true)['client'] as Map<String, dynamic>;
    expect(proxyClient['proxy-only'], isTrue);
  });

  test('canonical DNS rules are trimmed, split, and empty lines removed', () {
    final root = mergedRoot({
      'routeMode': 'global',
      'dnsRulesList': '\n example.com /cloudflare/tun\n\n test.com /doh.pub/tun \n',
    });
    final routing = routingOf(root);
    final dns = routing['dns'] as Map<String, dynamic>;

    expect(dns['rules'], [
      'example.com /cloudflare/tun',
      'test.com /doh.pub/tun',
    ]);
  });

  test('legacy routes and proxy-only fields remain available', () {
    final root = mergedRoot({
      'routeMode': 'global',
      'dnsRulesList': '',
    });
    final client = root['client'] as Map<String, dynamic>;
    final routing = client['routing'] as Map<String, dynamic>;
    final ip = routing['ip'] as Map<String, dynamic>;

    expect(client['proxy-only'], isFalse);
    expect(client['routes'], isNotEmpty);
    expect(client['peer-routes'], isNotEmpty);
    expect(ip['routes'], client['routes']);
    expect(ip['peer-routes'], client['peer-routes']);
  });

  // C2 / iOS equivalent: when canonical routing is present, ip.routes and
  // ip.peer-routes are the authoritative source.  effectiveJson keeps those
  // values mirrored to legacy client.routes fields; downstream native code
  // (iOS bridge, Android libopenppp2) must consume canonical routing.routes
  // and not re-process legacy client.routes.
  test('canonical ip.routes matches legacy routes mirror in effective json', () {
    const canonicalProfileJson = '''
{
  "client": {
    "proxy-only": false,
    "routing": {
      "ip": {
        "routes": [{"path": "./canonical-routes.txt"}],
        "peer-routes": [{"network": "10.30.0.0", "prefix": 16, "via": "10.0.0.5"}]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'basic',
      'bypassIpList': '',
      'dnsRulesList': '',
    })) as Map<String, dynamic>;
    final client = root['client'] as Map<String, dynamic>;
    final routing = client['routing'] as Map<String, dynamic>;
    final ip = routing['ip'] as Map<String, dynamic>;

    expect(ip.containsKey('routes'), isTrue);
    expect(ip['routes'], isNotEmpty);
    expect(ip.containsKey('peer-routes'), isTrue);
    expect(ip['peer-routes'], isNotEmpty);
    expect(client['routes'], ip['routes']);
    expect(client['peer-routes'], ip['peer-routes']);
    expect(routing.containsKey('mode'), isFalse);
  });

  // iOS proxy-only toggle: switching proxyOnly from true back to false must
  // restore full canonical routing state and not leave proxy-only artifacts.
  test('proxy-only toggle from true to false restores canonical routing', () {
    Map<String, dynamic> runWith(bool proxyOnly) {
      return jsonDecode(ProfileStore.effectiveJson(profileJson, {
        'routeMode': 'basic',
        'proxyOnly': proxyOnly,
        'bypassIpList': '10.0.0.0/8',
        'dnsRulesList': 'example.com /cloudflare/tun',
      })) as Map<String, dynamic>;
    }

    final withProxy = runWith(true)['client'] as Map<String, dynamic>;
    final withTun = runWith(false)['client'] as Map<String, dynamic>;

    expect(withProxy['proxy-only'], isTrue);
    expect(withTun['proxy-only'], isFalse);

    final proxyRouting = withProxy['routing'] as Map<String, dynamic>;
    final tunRouting = withTun['routing'] as Map<String, dynamic>;

    expect(proxyRouting.containsKey('mode'), isFalse);
    expect(tunRouting.containsKey('mode'), isFalse);

    final tunIp = tunRouting['ip'] as Map<String, dynamic>;
    expect(tunIp['bypass'], isNotEmpty);

    final tunDns = tunRouting['dns'] as Map<String, dynamic>;
    expect(tunDns['rules'], isNotEmpty);
  });

  // L5 regression: when UI options bypass/DNS are empty, effectiveJson must
  // preserve the canonical bypass and DNS values already in the profile JSON.
  test('empty ui bypass preserves canonical profile bypass', () {
    const canonicalProfileJson = '''
{
  "client": {
    "routing": {
      "ip": {
        "bypass": ["10.0.0.0/8", "192.168.0.0/16"]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'basic',
      'bypassIpList': '',
      'dnsRulesList': '',
    })) as Map<String, dynamic>;
    final ip = (((root['client'] as Map)['routing'] as Map)['ip'] as Map);
    expect(ip['bypass'], equals(['10.0.0.0/8', '192.168.0.0/16']));
  });

  test('empty ui dns rules preserves canonical profile dns rules', () {
    const canonicalProfileJson = '''
{
  "client": {
    "routing": {
      "dns": {
        "rules": ["example.com /cloudflare/tun"]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'basic',
      'bypassIpList': '',
      'dnsRulesList': '',
    })) as Map<String, dynamic>;
    final dns = (((root['client'] as Map)['routing'] as Map)['dns'] as Map);
    expect(dns['rules'], equals(['example.com /cloudflare/tun']));
  });

  test('non-empty ui bypass overrides canonical profile bypass', () {
    const canonicalProfileJson = '''
{
  "client": {
    "routing": {
      "ip": {
        "bypass": ["10.0.0.0/8"]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'basic',
      'bypassIpList': '172.16.0.0/12\n192.168.0.0/16',
      'dnsRulesList': '',
    })) as Map<String, dynamic>;
    final ip = (((root['client'] as Map)['routing'] as Map)['ip'] as Map);
    expect(ip['bypass'], equals(['172.16.0.0/12', '192.168.0.0/16']));
  });

  test('global routeMode forces empty bypass regardless of ui or profile', () {
    const canonicalProfileJson = '''
{
  "client": {
    "routing": {
      "ip": {
        "bypass": ["10.0.0.0/8"]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'global',
      'bypassIpList': '172.16.0.0/12',
      'dnsRulesList': '',
    })) as Map<String, dynamic>;
    final ip = (((root['client'] as Map)['routing'] as Map)['ip'] as Map);
    expect(ip['bypass'], isEmpty);
  });

  // L5: non-empty UI dnsRulesList overrides canonical profile dns.rules.
  test('non-empty ui dns rules overrides canonical profile dns rules', () {
    const canonicalProfileJson = '''
{
  "client": {
    "routing": {
      "dns": {
        "rules": ["old.example /cloudflare/tun"]
      }
    }
  }
}
''';
    final root = jsonDecode(ProfileStore.effectiveJson(canonicalProfileJson, {
      'routeMode': 'basic',
      'bypassIpList': '',
      'dnsRulesList': 'new.example /doh.pub/tun',
    })) as Map<String, dynamic>;
    final dns = (((root['client'] as Map)['routing'] as Map)['dns'] as Map);
    expect(dns['rules'], equals(['new.example /doh.pub/tun']));
  });
}
