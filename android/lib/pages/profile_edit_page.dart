import 'dart:convert';
import 'package:flutter/material.dart';
import '../models/config_profile.dart';
import '../services/profile_store.dart';
import '../utils/server_endpoint.dart';

/// Edit (or create) a single ConfigProfile.
///
/// Layout: sectioned tile cards (基本信息 / 服务器 / 加密 / 本地代理 / 高级).
/// Only client-relevant fields are exposed as form controls. The full JSON
/// can still be edited via the "Raw JSON" expansion at the bottom for power users.
class ProfileEditPage extends StatefulWidget {
  final ConfigProfile? profile;
  const ProfileEditPage({super.key, this.profile});

  @override
  State<ProfileEditPage> createState() => _ProfileEditPageState();
}

class _ProfileEditPageState extends State<ProfileEditPage> {
  final _store = ProfileStore();

  // Meta
  final _nameController = TextEditingController();
  final _subtitleController = TextEditingController();
  final _flagController = TextEditingController();

  // Server
  final _serverHostController = TextEditingController();
  final _serverPortController = TextEditingController();
  final _serverPathController = TextEditingController();
  String _serverScheme = 'ppp'; // ppp | ws | wss
  final _guidController = TextEditingController();
  final _bandwidthController = TextEditingController();

  // Cipher (key)
  final _protocolController = TextEditingController();
  final _protocolKeyController = TextEditingController();
  final _transportController = TextEditingController();
  final _transportKeyController = TextEditingController();
  final _kfController = TextEditingController();
  final _kxController = TextEditingController();
  final _klController = TextEditingController();
  final _khController = TextEditingController();
  bool _masked = false;
  bool _plaintext = false;
  bool _deltaEncode = false;
  bool _shuffleData = false;

  // Proxy
  final _httpProxyPortController = TextEditingController();
  final _socksProxyPortController = TextEditingController();

  // Raw JSON (advanced)
  final _jsonController = TextEditingController();
  bool _showRaw = false;

  Map<String, dynamic> _jsonMap = {};
  bool _saving = false;

  static const _commonProtocols = [
    'aes-128-cfb', 'aes-256-cfb', 'aes-128-gcm', 'aes-256-gcm',
    'chacha20-poly1305',
  ];

  @override
  void initState() {
    super.initState();
    final p = widget.profile;
    final initialJson = p?.json ?? ProfileStore.defaultJson;
    _jsonController.text = _prettify(initialJson);
    _nameController.text = p?.name ?? 'New Profile';
    _subtitleController.text = p?.subtitle ?? '';
    _flagController.text = p?.flag ?? '';
    _hydrateFormFromJson(initialJson, syncSubtitle: p == null);
  }

  String _prettify(String json) {
    try {
      return const JsonEncoder.withIndent('  ').convert(jsonDecode(json));
    } catch (_) {
      return json;
    }
  }

  void _hydrateFormFromJson(String json, {bool syncSubtitle = false}) {
    try {
      final decoded = jsonDecode(json);
      _jsonMap = (decoded is Map) ? Map<String, dynamic>.from(decoded) : {};
    } catch (_) {
      _jsonMap = {};
    }

    Map<String, dynamic> mapAt(String key) =>
        (_jsonMap[key] is Map) ? Map<String, dynamic>.from(_jsonMap[key] as Map) : {};

    final client = mapAt('client');
    final key = mapAt('key');

    final serverUrl = client['server']?.toString() ?? '';
    final endpoint = ServerEndpoint.parse(serverUrl);
    _serverScheme = endpoint.scheme == 'ws' || endpoint.scheme == 'wss'
        ? endpoint.scheme
        : 'ppp';
    _serverHostController.text = endpoint.host;
    _serverPortController.text = endpoint.port?.toString() ?? '';
    _serverPathController.text = endpoint.path;
    _guidController.text = client['guid']?.toString() ?? '';
    _bandwidthController.text = (client['bandwidth'] ?? 0).toString();

    _protocolController.text = key['protocol']?.toString() ?? 'aes-128-cfb';
    _protocolKeyController.text = key['protocol-key']?.toString() ?? '';
    _transportController.text = key['transport']?.toString() ?? 'aes-256-cfb';
    _transportKeyController.text = key['transport-key']?.toString() ?? '';
    _kfController.text = (key['kf'] ?? 154543927).toString();
    _kxController.text = (key['kx'] ?? 128).toString();
    _klController.text = (key['kl'] ?? 10).toString();
    _khController.text = (key['kh'] ?? 12).toString();
    _masked = key['masked'] == true;
    _plaintext = key['plaintext'] == true;
    _deltaEncode = key['delta-encode'] == true;
    _shuffleData = key['shuffle-data'] == true;

    final hp = client['http-proxy'];
    _httpProxyPortController.text =
        (hp is Map ? hp['port'] : null)?.toString() ?? '8080';
    final sp = client['socks-proxy'];
    _socksProxyPortController.text =
        (sp is Map ? sp['port'] : null)?.toString() ?? '1080';

    if (syncSubtitle) {
      final host = _serverHostController.text;
      final port = _serverPortController.text;
      if (host.isNotEmpty) {
        _subtitleController.text = port.isNotEmpty ? '$host:$port' : host;
      }
    }
  }

  String _applyFormToJson() {
    final map = Map<String, dynamic>.from(_jsonMap);

    Map<String, dynamic> ensureMap(String key) {
      final v = map[key];
      return (v is Map) ? Map<String, dynamic>.from(v) : <String, dynamic>{};
    }

    final client = ensureMap('client');
    final key = ensureMap('key');

    final host = _serverHostController.text.trim();
    final port = int.tryParse(_serverPortController.text.trim()) ?? 0;
    if (host.isNotEmpty) {
      final path = _serverPathController.text.trim().isEmpty
          ? '/'
          : _serverPathController.text.trim();
      client['server'] = ServerEndpoint(
        scheme: _serverScheme,
        host: host,
        port: port > 0 ? port : null,
        path: path,
      ).toUrl();
    }
    if (_guidController.text.trim().isNotEmpty) {
      client['guid'] = _guidController.text.trim();
    }
    final bw = int.tryParse(_bandwidthController.text.trim());
    if (bw != null) client['bandwidth'] = bw;

    // Cipher
    if (_protocolController.text.trim().isNotEmpty) {
      key['protocol'] = _protocolController.text.trim();
    }
    if (_protocolKeyController.text.trim().isNotEmpty) {
      key['protocol-key'] = _protocolKeyController.text.trim();
    }
    if (_transportController.text.trim().isNotEmpty) {
      key['transport'] = _transportController.text.trim();
    }
    if (_transportKeyController.text.trim().isNotEmpty) {
      key['transport-key'] = _transportKeyController.text.trim();
    }
    final kf = int.tryParse(_kfController.text.trim());
    if (kf != null) key['kf'] = kf;
    final kx = int.tryParse(_kxController.text.trim());
    if (kx != null) key['kx'] = kx;
    final kl = int.tryParse(_klController.text.trim());
    if (kl != null) key['kl'] = kl;
    final kh = int.tryParse(_khController.text.trim());
    if (kh != null) key['kh'] = kh;
    key['masked'] = _masked;
    key['plaintext'] = _plaintext;
    key['delta-encode'] = _deltaEncode;
    key['shuffle-data'] = _shuffleData;

    // Proxy
    final hp = (client['http-proxy'] is Map)
        ? Map<String, dynamic>.from(client['http-proxy'] as Map)
        : <String, dynamic>{'bind': '127.0.0.1'};
    final hpPort = int.tryParse(_httpProxyPortController.text.trim());
    if (hpPort != null) hp['port'] = hpPort;
    client['http-proxy'] = hp;

    final sp = (client['socks-proxy'] is Map)
        ? Map<String, dynamic>.from(client['socks-proxy'] as Map)
        : <String, dynamic>{'bind': '127.0.0.1'};
    final spPort = int.tryParse(_socksProxyPortController.text.trim());
    if (spPort != null) sp['port'] = spPort;
    client['socks-proxy'] = sp;

    // Android: ensure no reverse-proxy mappings.
    client['mappings'] = const [];

    map['client'] = client;
    map['key'] = key;
    _jsonMap = map;
    return const JsonEncoder.withIndent('  ').convert(map);
  }

  Future<void> _save() async {
    if (_saving) return;
    setState(() => _saving = true);
    try {
      String finalJson;
      if (_showRaw) {
        try {
          jsonDecode(_jsonController.text);
        } catch (e) {
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Raw JSON 格式错误: $e')),
          );
          return;
        }
        finalJson = _jsonController.text;
      } else {
        finalJson = _applyFormToJson();
        _jsonController.text = finalJson;
      }

      final existing = widget.profile;
      if (existing == null) {
        await _store.add(
          name: _nameController.text.trim().isEmpty
              ? 'New Profile'
              : _nameController.text.trim(),
          subtitle: _subtitleController.text.trim(),
          flag: _flagController.text.trim(),
          json: finalJson,
        );
      } else {
        final updated = existing.copyWith(
          name: _nameController.text.trim().isEmpty
              ? existing.name
              : _nameController.text.trim(),
          subtitle: _subtitleController.text.trim(),
          flag: _flagController.text.trim(),
          json: finalJson,
        );
        await _store.update(updated);
      }
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('已保存')),
      );
      Navigator.of(context).pop(true);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _restorePrevious() async {
    final p = widget.profile;
    if (p == null) return;
    if (p.history.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('没有可恢复的历史版本')),
      );
      return;
    }
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('恢复上一个版本'),
        content: Text(
          '配置「${p.name}」共有 ${p.history.length} 个历史版本，恢复后当前未保存的修改将被覆盖。是否继续？',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('恢复'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    final restored = await _store.restorePrevious(p.id);
    if (restored == null) return;
    if (!mounted) return;
    _jsonController.text = _prettify(restored);
    _hydrateFormFromJson(restored);
    setState(() {});
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('已恢复上一版本')),
    );
  }

  @override
  void dispose() {
    for (final c in [
      _nameController,
      _subtitleController,
      _flagController,
      _serverHostController,
      _serverPortController,
      _serverPathController,
      _guidController,
      _bandwidthController,
      _protocolController,
      _protocolKeyController,
      _transportController,
      _transportKeyController,
      _kfController,
      _kxController,
      _klController,
      _khController,
      _httpProxyPortController,
      _socksProxyPortController,
      _jsonController,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isNew = widget.profile == null;
    final hasHistory = (widget.profile?.history.isNotEmpty ?? false);
    return Scaffold(
      appBar: AppBar(
        title: Text(isNew ? '新增配置' : '编辑配置'),
        centerTitle: true,
        actions: [
          if (!isNew)
            IconButton(
              tooltip: '恢复上一版本',
              icon: Stack(
                clipBehavior: Clip.none,
                children: [
                  const Icon(Icons.history_rounded),
                  if (hasHistory)
                    Positioned(
                      right: -2,
                      top: -2,
                      child: Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(
                          color: Colors.amber,
                          shape: BoxShape.circle,
                        ),
                      ),
                    ),
                ],
              ),
              onPressed: hasHistory ? _restorePrevious : null,
            ),
          IconButton(
            icon: const Icon(Icons.save_rounded),
            tooltip: '保存',
            onPressed: _saving ? null : _save,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _Section(
            title: '基本信息',
            icon: Icons.bookmark_outline_rounded,
            children: [
              _text(_nameController, '名称'),
              _text(_subtitleController, '副标题 / 城市 (可选)'),
              _text(_flagController, '图标 / Emoji (可选)'),
            ],
          ),
          _Section(
            title: '服务器',
            icon: Icons.cloud_outlined,
            children: [
              DropdownButtonFormField<String>(
                value: _serverScheme,
                decoration: const InputDecoration(
                  labelText: '协议 (ppp=TCP, ws/wss=WebSocket)',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                items: const [
                  DropdownMenuItem(value: 'ppp', child: Text('ppp (TCP)')),
                  DropdownMenuItem(value: 'ws', child: Text('ws (WebSocket)')),
                  DropdownMenuItem(value: 'wss', child: Text('wss (TLS WebSocket)')),
                ],
                onChanged: (v) {
                  if (v == null) return;
                  setState(() => _serverScheme = v);
                },
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    flex: 3,
                    child: _text(_serverHostController, 'Host'),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    flex: 1,
                    child: _text(_serverPortController, 'Port',
                        keyboardType: TextInputType.number),
                  ),
                ],
              ),
              if (_serverScheme == 'ws' || _serverScheme == 'wss')
                _text(_serverPathController, 'WebSocket Path (e.g. /tun)'),
              _text(_bandwidthController, 'Bandwidth (kbps, 0=不限)',
                  keyboardType: TextInputType.number),
              _text(_guidController, 'GUID (可选)'),
            ],
          ),
          _Section(
            title: '加密',
            icon: Icons.shield_outlined,
            children: [
              Row(
                children: [
                  Expanded(child: _dropdown(_protocolController, 'Protocol')),
                  const SizedBox(width: 8),
                  Expanded(child: _dropdown(_transportController, 'Transport')),
                ],
              ),
              _text(_protocolKeyController, 'Protocol Key'),
              _text(_transportKeyController, 'Transport Key'),
              ExpansionTile(
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(top: 4),
                title: Text(
                  'KF/KX/KL/KH 与混淆 (高级)',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                children: [
                  Row(
                    children: [
                      Expanded(
                          child: _text(_kfController, 'kf',
                              keyboardType: TextInputType.number)),
                      const SizedBox(width: 8),
                      Expanded(
                          child: _text(_kxController, 'kx',
                              keyboardType: TextInputType.number)),
                    ],
                  ),
                  Row(
                    children: [
                      Expanded(
                          child: _text(_klController, 'kl',
                              keyboardType: TextInputType.number)),
                      const SizedBox(width: 8),
                      Expanded(
                          child: _text(_khController, 'kh',
                              keyboardType: TextInputType.number)),
                    ],
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: _masked,
                    title: const Text('Masked'),
                    onChanged: (v) => setState(() => _masked = v),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: _plaintext,
                    title: const Text('Plaintext'),
                    onChanged: (v) => setState(() => _plaintext = v),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: _deltaEncode,
                    title: const Text('Delta Encode'),
                    onChanged: (v) => setState(() => _deltaEncode = v),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    value: _shuffleData,
                    title: const Text('Shuffle Data'),
                    onChanged: (v) => setState(() => _shuffleData = v),
                  ),
                ],
              ),
            ],
          ),
          _Section(
            title: '本地代理 (可选)',
            icon: Icons.lan_outlined,
            children: [
              Row(
                children: [
                  Expanded(
                    child: _text(_httpProxyPortController, 'HTTP Port',
                        keyboardType: TextInputType.number),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: _text(_socksProxyPortController, 'SOCKS Port',
                        keyboardType: TextInputType.number),
                  ),
                ],
              ),
              Padding(
                padding: const EdgeInsets.only(top: 4, bottom: 4),
                child: Text(
                  '提示：Android 客户端不使用反向代理 (mappings)，无需配置。',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
              ),
            ],
          ),
          _Section(
            title: '高级 (Raw JSON)',
            icon: Icons.code_rounded,
            children: [
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: _showRaw,
                title: const Text('使用 Raw JSON 模式'),
                subtitle: const Text('开启后保存以 Raw 文本为准；关闭则以表单为准'),
                onChanged: (v) {
                  setState(() {
                    _showRaw = v;
                    if (v) {
                      _jsonController.text = _applyFormToJson();
                    } else {
                      _hydrateFormFromJson(_jsonController.text);
                    }
                  });
                },
              ),
              if (_showRaw) ...[
                Row(
                  children: [
                    OutlinedButton.icon(
                      onPressed: () {
                        _jsonController.text = _prettify(_jsonController.text);
                      },
                      icon: const Icon(Icons.auto_fix_high_rounded),
                      label: const Text('格式化'),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton.icon(
                      onPressed: () {
                        _jsonController.text =
                            _prettify(ProfileStore.defaultJson);
                      },
                      icon: const Icon(Icons.restart_alt_rounded),
                      label: const Text('恢复默认'),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                SizedBox(
                  height: 320,
                  child: TextField(
                    controller: _jsonController,
                    maxLines: null,
                    expands: true,
                    textAlignVertical: TextAlignVertical.top,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 12),
                    decoration: InputDecoration(
                      border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10)),
                      contentPadding: const EdgeInsets.all(12),
                    ),
                  ),
                ),
              ],
            ],
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: _saving ? null : _save,
            icon: const Icon(Icons.save_rounded),
            label: const Text('保存配置'),
          ),
        ],
      ),
    );
  }

  Widget _dropdown(TextEditingController c, String label) {
    final items = {..._commonProtocols, c.text}
        .where((s) => s.isNotEmpty)
        .toList();
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: DropdownButtonFormField<String>(
        initialValue: items.contains(c.text) ? c.text : items.first,
        items: items
            .map((s) => DropdownMenuItem(value: s, child: Text(s)))
            .toList(),
        onChanged: (v) {
          if (v != null) c.text = v;
        },
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }

  Widget _text(TextEditingController c, String label,
      {TextInputType? keyboardType}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        keyboardType: keyboardType,
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }
}

class _Section extends StatelessWidget {
  final String title;
  final IconData icon;
  final List<Widget> children;
  const _Section({
    required this.title,
    required this.icon,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Material(
        color: theme.colorScheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                children: [
                  Icon(icon, size: 18, color: theme.colorScheme.primary),
                  const SizedBox(width: 8),
                  Text(
                    title,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              ...children,
            ],
          ),
        ),
      ),
    );
  }
}
