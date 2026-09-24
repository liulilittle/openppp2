import 'dart:async';
import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../runtime/runtime_store.dart';
import '../services/profile_store.dart';
import '../vpn_service.dart';
import '../widgets/app_section_card.dart';
import '../widgets/vmux_mode_selector.dart';
import 'per_app_proxy_page.dart';

/// Android-specific and extended launch options (VNet, per-app proxy, geo-rules).
class OptionsAdvancedPage extends StatefulWidget {
  const OptionsAdvancedPage({super.key});

  @override
  State<OptionsAdvancedPage> createState() => _OptionsAdvancedPageState();
}

class _OptionsAdvancedPageState extends State<OptionsAdvancedPage> {
  final _store = ProfileStore();
  final RuntimeStore _runtimeStore = VpnService().runtimeStore;

  final _mark = TextEditingController();
  final _mux = TextEditingController();
  final _geoIpDownloadUrl = TextEditingController();
  final _geoSiteDownloadUrl = TextEditingController();
  final _geoIpFiles = TextEditingController();
  final _geoSiteFiles = TextEditingController();
  final _geoDnsProviderDomestic = TextEditingController();
  final _geoDnsProviderForeign = TextEditingController();
  final _geoOutputBypass = TextEditingController();
  final _geoOutputDnsRules = TextEditingController();

  bool _vnet = false;
  bool _blockQuic = false;
  bool _staticMode = true;
  bool _geoEnabled = true;
  bool _proxyOnly = false;
  bool _perAppProxyEnabled = false;
  String _perAppProxyMode = 'allow';
  List<String> _perAppProxyApps = const <String>[];
  bool _experimentalMode = false;
  String _muxMode = 'compat';

  ConfigProfile? _profile;
  bool _loading = true;
  bool _dirty = false;
  StreamSubscription<void>? _storeSub;

  @override
  void initState() {
    super.initState();
    _storeSub = _store.changes.listen((_) => _reloadFromStore());
    _runtimeStore.addListener(_runtimeChanged);
    _load();
  }

  void _runtimeChanged() {
    if (mounted) setState(() {});
  }

  Future<void> _reloadFromStore() async {
    if (_dirty || !mounted) return;
    final active = await _store.getActive();
    if (active == null) return;
    if (_profile?.id != active.id) {
      await _load();
      return;
    }
    final m = await _store.getProfileOptions(active.id);
    final experimental = await _store.getDebugPanelEnabled();
    if (!mounted) return;
    _hydrate(m);
    setState(() {
      _profile = active;
      _experimentalMode = experimental;
    });
  }

  Future<void> _load() async {
    final active = await _store.getActive();
    if (active == null) {
      if (!mounted) return;
      setState(() {
        _profile = null;
        _loading = false;
      });
      return;
    }
    final m = await _store.getProfileOptions(active.id);
    final experimental = await _store.getDebugPanelEnabled();
    if (!mounted) return;
    _hydrate(m);
    setState(() {
      _profile = active;
      _loading = false;
      _dirty = false;
      _experimentalMode = experimental;
    });
  }

  void _hydrate(Map<String, dynamic> m) {
    _mark.text = (m['mark'] ?? '0').toString();
    _mux.text = (m['mux'] ?? '0').toString();
    _muxMode = (m['muxMode'] ?? 'compat').toString();
    _vnet = m['vnet'] == true;
    _blockQuic = m['blockQuic'] == true;
    _staticMode = m['staticMode'] == true;
    _proxyOnly = m['proxyOnly'] == true;
    _perAppProxyEnabled = m['perAppProxyEnabled'] == true;
    final mode = (m['perAppProxyMode'] ?? 'allow').toString();
    _perAppProxyMode = mode == 'deny' ? 'deny' : 'allow';
    final apps = m['perAppProxyApps'];
    _perAppProxyApps = (apps is List)
        ? apps.whereType<String>().where((s) => s.isNotEmpty).toList()
        : const <String>[];

    final geo = (m['geoRules'] is Map)
        ? Map<String, dynamic>.from(m['geoRules'] as Map)
        : <String, dynamic>{};
    _geoEnabled = geo['enabled'] == true;
    _geoIpDownloadUrl.text = (geo['geoipDownloadUrl'] ?? '').toString();
    _geoSiteDownloadUrl.text = (geo['geositeDownloadUrl'] ?? '').toString();
    _geoIpFiles.text = (geo['geoipFiles'] ?? '').toString();
    _geoSiteFiles.text = (geo['geositeFiles'] ?? '').toString();
    _geoDnsProviderDomestic.text =
        (geo['dnsProviderDomestic'] ?? '').toString();
    _geoDnsProviderForeign.text =
        (geo['dnsProviderForeign'] ?? '').toString();
    _geoOutputBypass.text = (geo['outputBypass'] ?? '').toString();
    _geoOutputDnsRules.text = (geo['outputDnsRules'] ?? '').toString();
  }

  Map<String, dynamic> _readForm(Map<String, dynamic> base) {
    final options = Map<String, dynamic>.from(base);
    options
      ..['mark'] = int.tryParse(_mark.text.trim()) ?? 0
      ..['mux'] = int.tryParse(_mux.text.trim()) ?? 0
      ..['muxMode'] = _muxMode
      ..['vnet'] = _vnet
      ..['blockQuic'] = _blockQuic
      ..['staticMode'] = _staticMode
      ..['proxyOnly'] = _proxyOnly
      ..['perAppProxyEnabled'] = _perAppProxyEnabled
      ..['perAppProxyMode'] = _perAppProxyMode
      ..['perAppProxyApps'] = List<String>.from(_perAppProxyApps);
    options.remove('autoAppendApps');

    final geo = (options['geoRules'] is Map)
        ? Map<String, dynamic>.from(options['geoRules'] as Map)
        : <String, dynamic>{};
    geo['enabled'] = _geoEnabled;
    geo['geoipDownloadUrl'] = _geoIpDownloadUrl.text.trim();
    geo['geositeDownloadUrl'] = _geoSiteDownloadUrl.text.trim();
    geo['geoipFiles'] = _geoIpFiles.text;
    geo['geositeFiles'] = _geoSiteFiles.text;
    geo['dnsProviderDomestic'] = _geoDnsProviderDomestic.text.trim();
    geo['dnsProviderForeign'] = _geoDnsProviderForeign.text.trim();
    geo['outputBypass'] = _geoOutputBypass.text.trim();
    geo['outputDnsRules'] = _geoOutputDnsRules.text.trim();
    options['geoRules'] = geo;
    return options;
  }

  void _markDirty() {
    if (!_dirty) setState(() => _dirty = true);
  }

  Future<void> _save() async {
    final p = _profile;
    if (p == null) return;
    final current = await _store.getProfileOptions(p.id);
    await _store.setProfileOptions(p.id, _readForm(current));
    if (!mounted) return;
    setState(() => _dirty = false);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Takes effect on next connection')),
    );
  }

  String _perAppProxySubtitle() {
    if (!_perAppProxyEnabled) return '未启用 · 全部应用走 VPN';
    final n = _perAppProxyApps.length;
    final modeLabel = _perAppProxyMode == 'deny' ? '排除选中' : '仅代理选中';
    return '$modeLabel · 已选 $n 个应用';
  }

  Future<void> _openPerAppProxyPage() async {
    if (_dirty) await _save();
    if (!mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const PerAppProxyPage()),
    );
    await _load();
  }

  Future<void> _copyToAll() async {
    final p = _profile;
    if (p == null) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('应用到所有配置文件'),
        content: const Text('将当前高级参数应用到所有配置文件？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('应用全部'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final current = await _store.getProfileOptions(p.id);
    final m = _readForm(current);
    final list = await _store.getProfiles();
    for (final it in list) {
      final base = await _store.getProfileOptions(it.id);
      await _store.setProfileOptions(it.id, {...base, ...m});
    }
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('已应用到 ${list.length} 个配置文件')),
    );
  }

  @override
  void dispose() {
    _storeSub?.cancel();
    _runtimeStore.removeListener(_runtimeChanged);
    for (final c in [
      _mark,
      _mux,
      _geoIpDownloadUrl,
      _geoSiteDownloadUrl,
      _geoIpFiles,
      _geoSiteFiles,
      _geoDnsProviderDomestic,
      _geoDnsProviderForeign,
      _geoOutputBypass,
      _geoOutputDnsRules,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('高级参数'),
        centerTitle: true,
        actions: [
          IconButton(
            tooltip: '应用到所有配置文件',
            icon: const Icon(Icons.copy_all_rounded),
            onPressed: _profile == null ? null : _copyToAll,
          ),
          IconButton(
            icon: const Icon(Icons.save_rounded),
            tooltip: '保存',
            onPressed: _profile == null || !_dirty ? null : _save,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _profile == null
              ? const Center(child: Text('请先选择一个配置'))
              : ListView(
                  padding: const EdgeInsets.all(16),
                  children: [
                    AppSectionCard(
                      title: 'Android 代理',
                      icon: Icons.android_rounded,
                      tint: Colors.green,
                      children: [
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _proxyOnly,
                          title: const Text('仅代理模式'),
                          subtitle: const Text('只暴露本机 HTTP/SOCKS，不改系统路由'),
                          onChanged: (v) => setState(() {
                            _proxyOnly = v;
                            _markDirty();
                          }),
                        ),
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const Icon(Icons.apps_rounded),
                          title: const Text('分应用代理'),
                          subtitle: Text(_perAppProxySubtitle()),
                          trailing: const Icon(Icons.chevron_right_rounded),
                          onTap: _openPerAppProxyPage,
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: false,
                          title: const Text('系统 HTTP 代理'),
                          subtitle: const Text('为防止本地端口被抢占，Android 上不可用'),
                          onChanged: null,
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    AppSectionCard(
                      title: 'VNet / 网络',
                      icon: Icons.tune_rounded,
                      tint: Colors.purple,
                      children: [
                        VmuxModeSelector(
                          snapshot: _runtimeStore.state,
                          selectedMode: _muxMode,
                          experimental: _experimentalMode,
                          onChanged: (mode) => setState(() {
                            _muxMode = mode;
                            _markDirty();
                          }),
                        ),
                        const SizedBox(height: 12),
                        Row(
                          children: [
                            Expanded(
                              child: _text(_mark, 'Mark',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: _text(_mux, 'Mux',
                                  keyboardType: TextInputType.number,
                                  onChanged: _markDirty),
                            ),
                          ],
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _vnet,
                          title: const Text('VNet'),
                          onChanged: (v) => setState(() {
                            _vnet = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _blockQuic,
                          title: const Text('Block QUIC'),
                          onChanged: (v) => setState(() {
                            _blockQuic = v;
                            _markDirty();
                          }),
                        ),
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _staticMode,
                          title: const Text('Static Mode'),
                          onChanged: (v) => setState(() {
                            _staticMode = v;
                            _markDirty();
                          }),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    AppSectionCard(
                      title: 'Geo 规则生成器',
                      icon: Icons.travel_explore_rounded,
                      tint: Colors.deepOrange,
                      children: [
                        SwitchListTile(
                          contentPadding: EdgeInsets.zero,
                          value: _geoEnabled,
                          title: const Text('启用 GeoIP / GeoSite 规则生成'),
                          onChanged: (v) => setState(() {
                            _geoEnabled = v;
                            _markDirty();
                          }),
                        ),
                        if (_geoEnabled) ...[
                          _text(_geoIpDownloadUrl, 'GeoIP 下载 URL',
                              onChanged: _markDirty),
                          _text(_geoSiteDownloadUrl, 'GeoSite 下载 URL',
                              onChanged: _markDirty),
                          _multiline(_geoIpFiles, label: 'GeoIP 文本源',
                              onChanged: _markDirty, height: 90),
                          _multiline(_geoSiteFiles, label: 'GeoSite 文本源',
                              onChanged: _markDirty, height: 90),
                          Row(
                            children: [
                              Expanded(
                                child: _text(_geoDnsProviderDomestic,
                                    'dns-provider-domestic',
                                    onChanged: _markDirty),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: _text(_geoDnsProviderForeign,
                                    'dns-provider-foreign',
                                    onChanged: _markDirty),
                              ),
                            ],
                          ),
                          _text(_geoOutputBypass, 'output-bypass 路径',
                              onChanged: _markDirty),
                          _text(_geoOutputDnsRules, 'output-dns-rules 路径',
                              onChanged: _markDirty),
                        ],
                      ],
                    ),
                    const SizedBox(height: 12),
                    FilledButton.icon(
                      onPressed: _dirty ? _save : null,
                      icon: const Icon(Icons.save_rounded),
                      label: Text(_dirty ? '保存' : '已保存'),
                    ),
                  ],
                ),
    );
  }

  Widget _text(
    TextEditingController c,
    String label, {
    TextInputType? keyboardType,
    VoidCallback? onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        keyboardType: keyboardType,
        onChanged: onChanged == null ? null : (_) => onChanged(),
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }

  Widget _multiline(
    TextEditingController c, {
    required String label,
    VoidCallback? onChanged,
    double height = 120,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 6),
          SizedBox(
            height: height,
            child: TextField(
              controller: c,
              maxLines: null,
              expands: true,
              textAlignVertical: TextAlignVertical.top,
              onChanged: onChanged == null ? null : (_) => onChanged(),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                contentPadding: EdgeInsets.all(12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
