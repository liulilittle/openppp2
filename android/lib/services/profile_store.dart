import 'dart:async';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/config_profile.dart';
import '../models/launch_route_mode.dart';
import '../models/remote_subscription.dart';
import '../models/telemetry_settings.dart';
import '../utils/server_endpoint.dart';

/// Persistent store for the list of config profiles (locations) plus
/// active selection + raw VPN options. Uses SharedPreferences.
class ProfileStore {
  static const _profilesKey = 'profiles_v2';
  static const _activeIdKey = 'active_profile_id';
  static const _optionsKey = 'vpn_options_json';
  static const _debugPanelKey = 'debug_panel_enabled';

  static const _legacyConfigKey = 'vpn_config_json';

  static final ProfileStore _instance = ProfileStore._();
  factory ProfileStore() => _instance;
  ProfileStore._();

  final _changeController = StreamController<void>.broadcast();
  Stream<void> get changes => _changeController.stream;
  void _emit() {
    if (!_changeController.isClosed) _changeController.add(null);
  }

  /// Default client config. Server-side options (websocket SSL, server.{...},
  /// vmem, ssl, http error page, mappings) are kept as no-op defaults so the
  /// engine accepts the JSON; the UI does not surface them.
  static const String defaultJson = '''{
  "concurrent": 1,
  "cdn": [80, 443],
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "N6HMzdUs7IUnYHwq",
    "transport": "aes-256-cfb",
    "transport-key": "HWFweXu2g5RVMEpy",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "ip": { "public": "0.0.0.0", "interface": "0.0.0.0" },
  "vmem": { "size": 0, "path": "./" },
  "server": {
    "node": 1,
    "log": "./ppp.log",
    "subnet": true,
    "mapping": false,
    "backend": "",
    "backend-key": ""
  },
  "tcp": {
    "inactive": { "timeout": 300 },
    "connect": { "timeout": 5 },
    "listen": { "port": 20000 },
    "turbo": true,
    "backlog": 511,
    "fast-open": true
  },
  "udp": {
    "inactive": { "timeout": 72 },
    "dns": {
      "timeout": 4,
      "ttl": 60,
      "cache": true,
      "turbo": false,
      "redirect": "8.8.8.8:53"
    },
    "listen": { "port": 20000 },
    "static": {
      "keep-alived": [1, 5],
      "dns": true,
      "quic": false,
      "icmp": true,
      "server": "127.0.0.1:20000"
    }
  },
  "dns": {
    "servers": {
      "domestic": "doh.pub",
      "foreign": "cloudflare"
    },
    "intercept-unmatched": true,
    "ecs": {
      "enabled": true,
      "override-ip": ""
    },
    "tls": {
      "verify-peer": true
    }
  },
  "websocket": {
    "host": "",
    "path": "/",
    "listen": { "ws": 0, "wss": 0 },
    "ssl": {
      "certificate-file": "",
      "certificate-chain-file": "",
      "certificate-key-file": "",
      "certificate-key-password": "",
      "ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    },
    "verify-peer": true,
    "http": {
      "error": { "root": "wwwroot/" },
      "request": {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "X-Powered-By": "ASP.NET",
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Microsoft-IIS/10.0"
      }
    }
  },
  "client": {
    "guid": "{F4569420-4E49-4CBA-9C36-94E722C8E363}",
    "server": "ppp://192.168.0.24:20000/",
    "bandwidth": 0,
    "reconnections": { "timeout": 5 },
    "paper-airplane": { "tcp": true },
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 },
    "mappings": []
  }
}''';

  /// Foreign DNS rules for Ookla / Speedtest (force tunnel resolver path).
  static const String defaultSpeedtestDnsRules = '''speedtest.net      /cloudflare/tun
ookla.com          /cloudflare/tun
ooklaserver.net    /cloudflare/tun
cdnst.net          /cloudflare/tun''';

  static const Map<String, dynamic> defaultOptions = {
    'tunIp': '10.0.0.2',
    'tunMask': '255.255.255.0',
    'tunPrefix': 24,
    'gateway': '10.0.0.1',
    'route': '0.0.0.0',
    'routePrefix': 0,
    'dns1': '8.8.8.8',
    'dns2': '1.1.1.1',
    'mtu': 1400,
    'mark': 0,
    'mux': 0,
    'muxMode': 'compat',
    'vnet': false,
    'blockQuic': false,
    'staticMode': true,
    'bypassIpList': '',
    'dnsRulesList': defaultSpeedtestDnsRules,
    // ---- Per-app proxy ----
    // When [perAppProxyEnabled] is true, the VpnService.Builder restricts
    // proxied traffic to the package list in [perAppProxyApps]. Mode picks
    // between Builder.addAllowedApplication (allow) and addDisallowedApplication
    // (deny).
    'perAppProxyEnabled': false,
    'perAppProxyMode': 'allow', // 'allow' | 'deny'
    'perAppProxyApps': <String>[],
    // ---- LAN proxy ----
    // When true, the openppp2 local http/socks proxy listeners bind to
    // 0.0.0.0 so other LAN devices can use this device as a proxy. When
    // false they stay on 127.0.0.1 (the default).
    'allowLan': false,
    // When true, connect in proxy-only mode: minimal VPN route on Android,
    // local HTTP/SOCKS only (no full TUN routing / DNS hijack).
    'proxyOnly': false,
    // Native AppConfiguration `dns` block (spliced into profile.json at
    // connect time by [effectiveJson]). See openppp2/ppp/configurations
    // /AppConfiguration.h for the full schema.
    'dnsConfig': {
      'domestic': 'doh.pub',
      'foreign': 'cloudflare',
      'interceptUnmatched': true,
      'fakeIpEnabled': false,
      'fakeIpRange': '198.18.0.1/16',
      'ecsEnabled': true,
      'ecsOverrideIp': '',
      'tlsVerifyPeer': true,
      // Newline-separated list, one "host:port" per line.
      'stunCandidates': '39.107.142.158:3478\n'
          '74.125.250.129:19302\n'
          '74.125.250.130:19302\n'
          '74.125.250.131:19302\n'
          '74.125.250.132:19302\n'
          '74.125.250.133:19302\n'
          '74.125.250.134:19302',
    },
    // Native AppConfiguration `geo-rules` block.
    'geoRules': {
      'enabled': true,
      'country': 'cn',
      'geoipDat': './rules/GeoIP.dat',
      'geositeDat': './rules/GeoSite.dat',
      'geoipDownloadUrl':
          'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
      'geositeDownloadUrl':
          'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
      // Newline-separated lists of source file paths.
      'geoipFiles': './rules/geoip-cn.txt',
      'geositeFiles': './rules/geosite-cn.txt',
      'dnsProviderDomestic': 'doh.pub',
      'dnsProviderForeign': 'cloudflare',
      'outputBypass': './generated/bypass-cn.txt',
      'outputDnsRules': './generated/dns-rules-cn.txt',
    },
  };

  /// Merge the per-profile `dns` and `geo-rules` form values (under
  /// `options.dnsConfig` / `options.geoRules`) into `profile.json` and return
  /// the resulting JSON string. This is what should be passed to the native
  /// engine via `set_app_configuration` so each profile can carry its own
  /// AppConfiguration tuning without forcing users to hand-edit raw JSON.
  /// [telemetry] when provided, merges native telemetry settings into the JSON
  /// block consumed by `set_app_configuration` (aligned with iOS ProfileStore).
  static String effectiveJson(
    String profileJson,
    Map<String, dynamic> options, {
    TelemetrySettings telemetry = TelemetrySettings.disabled,
  }) {
    Map<String, dynamic> root;
    try {
      final decoded = jsonDecode(profileJson);
      root = (decoded is Map) ? Map<String, dynamic>.from(decoded) : {};
    } catch (_) {
      // Fall back to default if the profile JSON is broken; better to ship a
      // working config than refuse to connect.
      root = Map<String, dynamic>.from(jsonDecode(defaultJson) as Map);
    }

    // ---- dns block ----
    final dnsCfgRaw = options['dnsConfig'];
    if (dnsCfgRaw is Map) {
      final dc = Map<String, dynamic>.from(dnsCfgRaw);
      final dns = (root['dns'] is Map)
          ? Map<String, dynamic>.from(root['dns'] as Map)
          : <String, dynamic>{};
      final servers = (dns['servers'] is Map)
          ? Map<String, dynamic>.from(dns['servers'] as Map)
          : <String, dynamic>{};
      final ecs = (dns['ecs'] is Map)
          ? Map<String, dynamic>.from(dns['ecs'] as Map)
          : <String, dynamic>{};
      final tls = (dns['tls'] is Map)
          ? Map<String, dynamic>.from(dns['tls'] as Map)
          : <String, dynamic>{};
      final stun = (dns['stun'] is Map)
          ? Map<String, dynamic>.from(dns['stun'] as Map)
          : <String, dynamic>{};

      final domestic = (dc['domestic'] ?? '').toString();
      final foreign = (dc['foreign'] ?? '').toString();
      if (domestic.isNotEmpty) servers['domestic'] = domestic;
      if (foreign.isNotEmpty) servers['foreign'] = foreign;
      dns['servers'] = servers;

      // Preserve profile/template defaults when older saved options omit these
      // keys; `== true` used to force them off and break unmatched-domain DNS.
      dns['intercept-unmatched'] =
          dc['interceptUnmatched'] ?? dns['intercept-unmatched'] ?? true;

      final fakeIp = (dns['fake-ip'] is Map)
          ? Map<String, dynamic>.from(dns['fake-ip'] as Map)
          : <String, dynamic>{};
      fakeIp['enabled'] = dc['fakeIpEnabled'] ?? fakeIp['enabled'] ?? false;
      final fakeRange = (dc['fakeIpRange'] ?? '').toString().trim();
      if (fakeRange.isNotEmpty) {
        fakeIp['range'] = fakeRange;
      }
      dns['fake-ip'] = fakeIp;

      ecs['enabled'] = dc['ecsEnabled'] ?? ecs['enabled'] ?? true;
      ecs['override-ip'] = (dc['ecsOverrideIp'] ?? '').toString();
      dns['ecs'] = ecs;
      tls['verify-peer'] = dc['tlsVerifyPeer'] ?? tls['verify-peer'] ?? true;
      dns['tls'] = tls;

      final stunRaw = (dc['stunCandidates'] ?? '').toString();
      final stunList = stunRaw
          .split('\n')
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList();
      if (stunList.isNotEmpty) {
        stun['candidates'] = stunList;
      } else {
        stun.remove('candidates');
      }
      dns['stun'] = stun;

      root['dns'] = dns;
    }

    // ---- geo-rules block ----
    final grRaw = options['geoRules'];
    if (grRaw is Map) {
      final gc = Map<String, dynamic>.from(grRaw);
      final gr = (root['geo-rules'] is Map)
          ? Map<String, dynamic>.from(root['geo-rules'] as Map)
          : <String, dynamic>{};

      gr['enabled'] = gc['enabled'] == true;
      void putIfNonEmpty(String key, dynamic value) {
        final s = (value ?? '').toString();
        if (s.isNotEmpty) gr[key] = s;
      }

      putIfNonEmpty('country', gc['country']);
      putIfNonEmpty('geoip-dat', gc['geoipDat']);
      putIfNonEmpty('geosite-dat', gc['geositeDat']);
      putIfNonEmpty('geoip-download-url', gc['geoipDownloadUrl']);
      putIfNonEmpty('geosite-download-url', gc['geositeDownloadUrl']);
      putIfNonEmpty('dns-provider-domestic', gc['dnsProviderDomestic']);
      putIfNonEmpty('dns-provider-foreign', gc['dnsProviderForeign']);
      putIfNonEmpty('output-bypass', gc['outputBypass']);
      putIfNonEmpty('output-dns-rules', gc['outputDnsRules']);

      List<String> splitLines(dynamic value) => (value ?? '')
          .toString()
          .split('\n')
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList();

      final geoip = splitLines(gc['geoipFiles']);
      final geosite = splitLines(gc['geositeFiles']);
      if (geoip.isNotEmpty) gr['geoip'] = geoip;
      if (geosite.isNotEmpty) gr['geosite'] = geosite;

      root['geo-rules'] = gr;
    }

    // ---- canonical client routing block ----
    // Keep IP/DNS policy in profile JSON so native clients can consume one
    // authoritative bypass source list and DNS source list. The independent
    // client.proxy-only flag controls runtime mode; legacy client.routes and
    // client.peer-routes remain mirrored for older consumers.
    {
      List<String> splitLines(dynamic value) => (value ?? '')
          .toString()
          .split('\n')
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList();

      final client = (root['client'] is Map)
          ? Map<String, dynamic>.from(root['client'] as Map)
          : <String, dynamic>{};
      final routing = (client['routing'] is Map)
          ? Map<String, dynamic>.from(client['routing'] as Map)
          : <String, dynamic>{};
      routing.remove('mode');
      final ip = (routing['ip'] is Map)
          ? Map<String, dynamic>.from(routing['ip'] as Map)
          : <String, dynamic>{};
      final dns = (routing['dns'] is Map)
          ? Map<String, dynamic>.from(routing['dns'] as Map)
          : <String, dynamic>{};

      final routeMode = LaunchRouteMode.fromOptions(options);
      final proxyOnly = options['proxyOnly'] == true;
      // UI options are the user's active override and take precedence over the
      // profile canonical value when they are non-empty.  An empty UI value
      // means "not set by user"; in that case keep whatever the profile already
      // has so that a profile with pre-populated canonical bypass/DNS is not
      // silently discarded.  routeMode==global always forces an empty bypass
      // regardless of UI or profile content.
      final uiBypass = splitLines(options['bypassIpList']);
      if (routeMode == LaunchRouteMode.global) {
        ip['bypass'] = <String>[];
      } else if (uiBypass.isNotEmpty) {
        ip['bypass'] = uiBypass;
      }
      // ip['bypass'] left unchanged when uiBypass is empty and routeMode != global.
      final uiDnsRules = splitLines(options['dnsRulesList']);
      if (uiDnsRules.isNotEmpty) {
        dns['rules'] = uiDnsRules;
      }
      // dns['rules'] left unchanged when uiDnsRules is empty.

      // Do not discard route entries from profiles that predate the canonical
      // block. Nested canonical values win; direct aliases are also retained.
      if (!ip.containsKey('routes')) {
        final routes = routing['routes'] ?? client['routes'];
        if (routes != null) ip['routes'] = routes;
      }
      if (!ip.containsKey('peer-routes')) {
        final peerRoutes = routing['peer-routes'] ?? client['peer-routes'];
        if (peerRoutes != null) ip['peer-routes'] = peerRoutes;
      }
      // Canonical nested values are authoritative and remain mirrored for
      // legacy native consumers that still read client.routes fields.
      if (ip['routes'] != null) client['routes'] = ip['routes'];
      if (ip['peer-routes'] != null) client['peer-routes'] = ip['peer-routes'];
      routing['ip'] = ip;
      routing['dns'] = dns;
      client['routing'] = routing;
      client['proxy-only'] = proxyOnly;
      root['client'] = client;
    }

    final mux = (root['mux'] is Map)
        ? Map<String, dynamic>.from(root['mux'] as Map)
        : <String, dynamic>{};
    mux['mode'] = (options['muxMode'] ?? 'compat').toString();
    root['mux'] = mux;

    // ---- LAN proxy bind override ----
    // When [allowLan] is true, force the local http/socks proxy listeners to
    // bind on 0.0.0.0 so other devices on the same Wi-Fi can use this device
    // as a proxy. When false, lock them back onto loopback (127.0.0.1).
    // In proxy-only mode, always use loopback unless allowLan is explicitly set.
    {
      final proxyOnly = options['proxyOnly'] == true;
      final allowLan = !proxyOnly && options['allowLan'] == true;
      final bindAddr = allowLan ? '0.0.0.0' : '127.0.0.1';
      final client = (root['client'] is Map)
          ? Map<String, dynamic>.from(root['client'] as Map)
          : <String, dynamic>{};
      final hp = (client['http-proxy'] is Map)
          ? Map<String, dynamic>.from(client['http-proxy'] as Map)
          : <String, dynamic>{'port': 8080};
      final sp = (client['socks-proxy'] is Map)
          ? Map<String, dynamic>.from(client['socks-proxy'] as Map)
          : <String, dynamic>{'port': 1080};
      hp['bind'] = bindAddr;
      sp['bind'] = bindAddr;
      client['http-proxy'] = hp;
      client['socks-proxy'] = sp;
      root['client'] = client;
    }

    // ---- telemetry block (native engine OTLP) ----
    root['telemetry'] = TelemetrySettings.appConfigurationBlock(telemetry);

    return const JsonEncoder.withIndent('  ').convert(root);
  }

  Future<List<ConfigProfile>> _readRaw(SharedPreferences prefs) async {
    final raw = prefs.getString(_profilesKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final decoded = jsonDecode(raw);
      if (decoded is List) {
        return decoded
            .whereType<Map>()
            .map((m) => ConfigProfile.fromMap(Map<String, dynamic>.from(m)))
            .toList();
      }
    } catch (_) {}
    return [];
  }

  Future<List<ConfigProfile>> getProfiles() async {
    final prefs = await SharedPreferences.getInstance();
    var list = await _readRaw(prefs);
    if (list.isEmpty) {
      final legacy = prefs.getString(_legacyConfigKey);
      final seedJson = (legacy != null && legacy.trim().isNotEmpty)
          ? legacy
          : defaultJson;
      final seed = ConfigProfile(
        id: _newId(),
        name: 'Default',
        subtitle: _hostFromJson(seedJson) ?? '',
        json: seedJson,
      );
      await _writeProfiles(prefs, [seed]);
      await prefs.setString(_activeIdKey, seed.id);
      list = [seed];
    }
    return list;
  }

  Future<void> _writeProfiles(SharedPreferences prefs, List<ConfigProfile> list) async {
    final encoded = jsonEncode(list.map((p) => p.toMap()).toList());
    await prefs.setString(_profilesKey, encoded);
    _emit();
  }

  Future<ConfigProfile?> getActive() async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    if (list.isEmpty) return null;
    final id = prefs.getString(_activeIdKey);
    if (id != null) {
      for (final p in list) {
        if (p.id == id) return p;
      }
    }
    return list.first;
  }

  Future<void> setActive(String id) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_activeIdKey, id);
    _emit();
  }

  Future<ConfigProfile> add({
    String? name,
    String? subtitle,
    String? flag,
    String? json,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final profile = ConfigProfile(
      id: _newId(),
      name: name?.trim().isNotEmpty == true ? name!.trim() : 'New Profile',
      subtitle: subtitle ?? '',
      flag: flag ?? '',
      json: json ?? defaultJson,
    );
    list.add(profile);
    await _writeProfiles(prefs, list);
    return profile;
  }

  Future<int> upsertSubscription({
    required String url,
    required RemoteSubscriptionResult subscription,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final now = DateTime.now().millisecondsSinceEpoch;
    var changed = 0;

    for (final node in subscription.nodes) {
      final existingIndex = list.indexWhere(
        (p) => p.subscriptionUrl == url && p.subscriptionNodeId == node.id,
      );
      if (existingIndex >= 0) {
        final prev = list[existingIndex];
        var history = List<ConfigSnapshot>.from(prev.history);
        if (prev.json != node.json) {
          history.insert(
            0,
            ConfigSnapshot(timestampMs: now, json: prev.json),
          );
          if (history.length > ConfigProfile.historyLimit) {
            history = history.sublist(0, ConfigProfile.historyLimit);
          }
        }
        list[existingIndex] = prev.copyWith(
          name: node.name,
          subtitle:
              node.subtitle.isNotEmpty ? node.subtitle : (_hostFromJson(node.json) ?? ''),
          flag: node.flag,
          json: node.json,
          options: node.options.isEmpty ? prev.options : node.options,
          subscriptionUrl: url,
          subscriptionNodeId: node.id,
          subscriptionUpdatedAtMs: now,
          history: history,
        );
      } else {
        list.add(ConfigProfile(
          id: _newId(),
          name: node.name,
          subtitle:
              node.subtitle.isNotEmpty ? node.subtitle : (_hostFromJson(node.json) ?? ''),
          flag: node.flag,
          json: node.json,
          options: node.options,
          subscriptionUrl: url,
          subscriptionNodeId: node.id,
          subscriptionUpdatedAtMs: now,
        ));
      }
      changed++;
    }

    if (changed > 0) {
      await _writeProfiles(prefs, list);
    }
    return changed;
  }

  /// Update an existing profile. The previous JSON is pushed onto its
  /// history stack (most-recent-first, capped) so users can revert.
  Future<void> update(ConfigProfile profile, {bool snapshot = true}) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final idx = list.indexWhere((p) => p.id == profile.id);
    if (idx == -1) {
      // Defensive: if it disappeared, append it instead of silently dropping.
      list.add(profile);
      await _writeProfiles(prefs, list);
      return;
    }
    final prev = list[idx];
    var newHistory = List<ConfigSnapshot>.from(profile.history);
    if (snapshot && prev.json != profile.json) {
      newHistory.insert(
        0,
        ConfigSnapshot(
          timestampMs: DateTime.now().millisecondsSinceEpoch,
          json: prev.json,
        ),
      );
      if (newHistory.length > ConfigProfile.historyLimit) {
        newHistory = newHistory.sublist(0, ConfigProfile.historyLimit);
      }
    }
    list[idx] = profile.copyWith(history: newHistory);
    await _writeProfiles(prefs, list);
  }

  /// Restore the most recent history snapshot for `id`. Returns the new
  /// active JSON or null if no history was available.
  Future<String?> restorePrevious(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final idx = list.indexWhere((p) => p.id == id);
    if (idx == -1) return null;
    final p = list[idx];
    if (p.history.isEmpty) return null;
    final restored = p.history.first;
    // The current json becomes a redo-style entry at position 0; we keep
    // monotonic history so we just rotate: drop snapshot 0 and insert
    // current as new newest of remaining (still capped).
    final remaining = p.history.sublist(1);
    final newHistory = <ConfigSnapshot>[
      ConfigSnapshot(
        timestampMs: DateTime.now().millisecondsSinceEpoch,
        json: p.json,
      ),
      ...remaining,
    ];
    if (newHistory.length > ConfigProfile.historyLimit) {
      newHistory.removeRange(ConfigProfile.historyLimit, newHistory.length);
    }
    list[idx] = p.copyWith(json: restored.json, history: newHistory);
    await _writeProfiles(prefs, list);
    return restored.json;
  }

  Future<void> remove(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    list.removeWhere((p) => p.id == id);
    if (list.isEmpty) {
      list.add(ConfigProfile(
        id: _newId(),
        name: 'Default',
        json: defaultJson,
      ));
    }
    await _writeProfiles(prefs, list);
    final activeId = prefs.getString(_activeIdKey);
    if (activeId == id) {
      await prefs.setString(_activeIdKey, list.first.id);
    }
  }

  Future<void> toggleFavorite(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final idx = list.indexWhere((p) => p.id == id);
    if (idx == -1) return;
    list[idx] = list[idx].copyWith(favorite: !list[idx].favorite);
    await _writeProfiles(prefs, list);
  }

  static const _speedtestCompatKey = 'vpn_speedtest_compat_applied_v1';

  /// Append Ookla/Speedtest DNS rules when missing so GEO split does not
  /// resolve test hosts through domestic ECS edges.
  static String ensureSpeedtestDnsRules(String existing) {
    const needles = [
      'speedtest.net',
      'ookla.com',
      'ooklaserver.net',
      'cdnst.net',
    ];
    final lower = existing.toLowerCase();
    if (needles.every(lower.contains)) {
      return existing;
    }
    final buf = StringBuffer();
    if (existing.trim().isNotEmpty) {
      buf.writeln(existing.trimRight());
    }
    for (final line in defaultSpeedtestDnsRules.split('\n')) {
      final domain = line.trim().split(RegExp(r'\s+')).first;
      if (!lower.contains(domain.toLowerCase())) {
        buf.writeln(line);
      }
    }
    return buf.toString().trimRight();
  }

  static Map<String, dynamic> patchOptionsForSpeedtest(
    Map<String, dynamic> options,
  ) {
    final out = Map<String, dynamic>.from(options);
    out['staticMode'] = true;
    if (out['blockQuic'] == true) {
      out['blockQuic'] = false;
    }
    out['dnsRulesList'] = ensureSpeedtestDnsRules(
      (out['dnsRulesList'] ?? '').toString(),
    );
    return out;
  }

  Future<void> _applySpeedtestCompatMigration() async {
    final prefs = await SharedPreferences.getInstance();
    if (prefs.getBool(_speedtestCompatKey) == true) return;

    final list = await getProfiles();
    var profilesChanged = false;
    final updated = <ConfigProfile>[];
    for (final profile in list) {
      final patched = patchOptionsForSpeedtest(profile.options);
      if (!_optionsEqual(profile.options, patched)) {
        updated.add(profile.copyWith(options: patched));
        profilesChanged = true;
      } else {
        updated.add(profile);
      }
    }
    if (profilesChanged) {
      await _writeProfiles(prefs, updated);
    }

    final global = await getOptions();
    final patchedGlobal = patchOptionsForSpeedtest(global);
    if (!_optionsEqual(global, patchedGlobal)) {
      await setOptions(patchedGlobal);
    }

    await prefs.setBool(_speedtestCompatKey, true);
  }

  static bool _optionsEqual(
    Map<String, dynamic> a,
    Map<String, dynamic> b,
  ) {
    return jsonEncode(a) == jsonEncode(b);
  }

  /// Returns the effective per-profile launch options: profile-specific
  /// values overlaid on top of [defaultOptions]. Falls back to the global
  /// (legacy) options blob when both are empty so old installs keep working.
  Future<Map<String, dynamic>> getProfileOptions(String id) async {
    await _applySpeedtestCompatMigration();
    final list = await getProfiles();
    final p = list.firstWhere(
      (e) => e.id == id,
      orElse: () => list.isNotEmpty
          ? list.first
          : ConfigProfile(id: '_', name: '_', json: defaultJson),
    );
    Map<String, dynamic> deepMerge(Map<String, dynamic> a, Map<String, dynamic> b) {
      final out = Map<String, dynamic>.from(a);
      b.forEach((k, v) {
        final existing = out[k];
        if (existing is Map && v is Map) {
          out[k] = deepMerge(
            Map<String, dynamic>.from(existing),
            Map<String, dynamic>.from(v),
          );
        } else {
          out[k] = v;
        }
      });
      return out;
    }

    var result = _deepCopy(defaultOptions);
    if (p.options.isEmpty) {
      // back-compat: hydrate from legacy global options if present
      final legacy = await getOptions();
      result = deepMerge(result, legacy);
    } else {
      result = deepMerge(result, Map<String, dynamic>.from(p.options));
    }
    return result;
  }

  /// Apply a partial update to one profile's launch options.
  Future<void> updateProfileOptions(
    String id,
    void Function(Map<String, dynamic> options) mutate,
  ) async {
    final current = await getProfileOptions(id);
    final next = Map<String, dynamic>.from(current);
    mutate(next);
    if (_optionsEqual(current, next)) return;
    await setProfileOptions(id, next);
  }

  static Map<String, dynamic> _deepCopy(Map<String, dynamic> src) {
    final out = <String, dynamic>{};
    src.forEach((k, v) {
      if (v is Map) {
        out[k] = _deepCopy(Map<String, dynamic>.from(v));
      } else if (v is List) {
        out[k] = List<dynamic>.from(v);
      } else {
        out[k] = v;
      }
    });
    return out;
  }

  Future<void> setProfileOptions(String id, Map<String, dynamic> options) async {
    final prefs = await SharedPreferences.getInstance();
    final list = await getProfiles();
    final idx = list.indexWhere((p) => p.id == id);
    if (idx == -1) return;
    list[idx] = list[idx].copyWith(options: Map<String, dynamic>.from(options));
    await _writeProfiles(prefs, list);
  }

  Future<Map<String, dynamic>> getOptions() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_optionsKey);
    if (raw == null || raw.isEmpty) {
      return Map<String, dynamic>.from(defaultOptions);
    }
    try {
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        final m = Map<String, dynamic>.from(defaultOptions);
        m.addAll(Map<String, dynamic>.from(decoded));
        return m;
      }
    } catch (_) {}
    return Map<String, dynamic>.from(defaultOptions);
  }

  Future<void> setOptions(Map<String, dynamic> options) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_optionsKey, jsonEncode(options));
    _emit();
  }

  Future<bool> getDebugPanelEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_debugPanelKey) ?? false;
  }

  Future<void> setDebugPanelEnabled(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_debugPanelKey, value);
    _emit();
  }

  /// Delete all profiles and restore a single default blank profile.
  Future<void> resetAll() async {
    final prefs = await SharedPreferences.getInstance();
    final seed = ConfigProfile(
      id: _newId(),
      name: 'Default',
      json: defaultJson,
    );
    await _writeProfiles(prefs, [seed]);
    await prefs.setString(_activeIdKey, seed.id);
    await prefs.remove(_optionsKey);
  }

  static String _newId() {
    final now = DateTime.now().microsecondsSinceEpoch;
    return 'p_${now.toRadixString(36)}';
  }

  static String? _hostFromJson(String json) {
    try {
      final decoded = jsonDecode(json);
      if (decoded is Map) {
        final client = decoded['client'];
        if (client is Map) {
          final s = client['server']?.toString();
          if (s != null) {
            final endpoint = ServerEndpoint.parse(s);
            if (endpoint.host.isNotEmpty) return endpoint.host;
          }
        }
      }
    } catch (_) {}
    return null;
  }
}
