enum RuntimePhase {
  idle,
  starting,
  preparingHost,
  connecting,
  handshaking,
  applyingPolicy,
  connected,
  reconnecting,
  stopping,
  failed,
  unknown;

  static RuntimePhase parse(String value) {
    switch (value) {
      case 'idle':
        return RuntimePhase.idle;
      case 'starting':
        return RuntimePhase.starting;
      case 'preparing_host':
        return RuntimePhase.preparingHost;
      case 'connecting':
        return RuntimePhase.connecting;
      case 'handshaking':
        return RuntimePhase.handshaking;
      case 'applying_policy':
        return RuntimePhase.applyingPolicy;
      case 'connected':
        return RuntimePhase.connected;
      case 'reconnecting':
        return RuntimePhase.reconnecting;
      case 'stopping':
        return RuntimePhase.stopping;
      case 'failed':
        return RuntimePhase.failed;
      case 'unknown':
        return RuntimePhase.unknown;
      default:
        throw FormatException('Unknown runtime phase: $value');
    }
  }
}

enum P2PState {
  disabled('disabled', 'Disabled'),
  unavailable('unavailable', 'Unavailable'),
  relay('relay', 'Relay'),
  eligible('eligible', 'Eligible'),
  probing('probing', 'Probing'),
  direct('direct', 'Direct'),
  suspect('suspect', 'Suspect'),
  fallingBack('falling_back', 'Falling back'),
  failed('failed', 'Failed');

  const P2PState(this.wireName, this.displayName);

  final String wireName;
  final String displayName;

  static P2PState parse(String value) {
    for (final state in values) {
      if (state.wireName == value) return state;
    }
    return P2PState.unavailable;
  }
}

class RuntimeErrorSnapshot {
  const RuntimeErrorSnapshot({
    this.code = 0,
    this.severity = '',
    this.retryable = false,
    this.userMessageKey = '',
    this.diagnosticDetail = '',
  });

  final int code;
  final String severity;
  final bool retryable;
  final String userMessageKey;
  final String diagnosticDetail;

  factory RuntimeErrorSnapshot.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const RuntimeErrorSnapshot();
    return RuntimeErrorSnapshot(
      code: runtimeNonNegInt(json['code'], 'code', required: false),
      severity: json['severity'] as String? ?? '',
      retryable: json['retryable'] as bool? ?? false,
      userMessageKey: json['user_message_key'] as String? ?? '',
      diagnosticDetail: json['diagnostic_detail'] as String? ?? '',
    );
  }
}

class RuntimeTrafficSnapshot {
  const RuntimeTrafficSnapshot({
    this.rxBytes = 0,
    this.txBytes = 0,
  });

  final int rxBytes;
  final int txBytes;

  factory RuntimeTrafficSnapshot.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const RuntimeTrafficSnapshot();
    return RuntimeTrafficSnapshot(
      rxBytes: runtimeNonNegInt(
        json['rx_bytes'],
        'rx_bytes',
        required: false,
      ),
      txBytes: runtimeNonNegInt(
        json['tx_bytes'],
        'tx_bytes',
        required: false,
      ),
    );
  }
}

class RuntimeSnapshot {
  static const bundledCapabilities = <String>[
    'mux.compat',
    'mux.flow',
    'mux.balance',
    'mux.stripe',
  ];

  const RuntimeSnapshot({
    required this.generation,
    required this.monotonicMs,
    required this.phase,
    this.role = '',
    this.server = '',
    this.transport = '',
    this.capabilities = const <String>[],
    this.requestedMuxMode = '',
    this.effectiveMuxMode = '',
    this.muxReceiverOrdering = '',
    this.muxActiveLinks = 0,
    this.muxFallbackReason = '',
    this.p2pState = P2PState.disabled,
    this.traffic = const RuntimeTrafficSnapshot(),
    this.connectedMonotonicMs = 0,
    this.lastError = const RuntimeErrorSnapshot(),
  });

  static const int schemaVersion = 1;

  final int generation;
  final int monotonicMs;
  final RuntimePhase phase;
  final String role;
  final String server;
  final String transport;
  final List<String> capabilities;
  final String requestedMuxMode;
  final String effectiveMuxMode;
  final String muxReceiverOrdering;
  final int muxActiveLinks;
  final String muxFallbackReason;
  final P2PState p2pState;
  String get effectivePath => p2pState == P2PState.direct ? 'direct' : 'relay';
  final RuntimeTrafficSnapshot traffic;

  /// `monotonic_ms` at which the session entered `connected`, or 0 when it is
  /// not connected. Elapsed time is `monotonicMs - connectedMonotonicMs`, so it
  /// stays correct across a UI process restart.
  final int connectedMonotonicMs;
  final RuntimeErrorSnapshot lastError;

  factory RuntimeSnapshot.fromJson(Map<String, dynamic> json) {
    final version = json['schema_version'];
    if (version != schemaVersion) {
      throw FormatException('Unsupported runtime schema version: $version');
    }
    // JsonCpp may emit large counters as JSON numbers that dart:convert keeps
    // as double on some paths; accept int|num so a live connected snapshot is
    // not rejected as "Invalid runtime snapshot".
    final generation = runtimeNonNegInt(json['generation'], 'generation');
    final monotonicMs = runtimeNonNegInt(json['monotonic_ms'], 'monotonic_ms');
    final phaseValue = json['phase'];
    if (phaseValue is! String) {
      throw const FormatException('Runtime phase is required');
    }

    return RuntimeSnapshot(
      generation: generation,
      monotonicMs: monotonicMs,
      phase: RuntimePhase.parse(phaseValue),
      role: json['role'] as String? ?? '',
      server: json['server'] as String? ?? '',
      transport: json['transport'] as String? ?? '',
      capabilities: json.containsKey('capabilities')
          ? (json['capabilities'] as List<dynamic>? ?? const <dynamic>[])
              .whereType<String>()
              .toList(growable: false)
          : bundledCapabilities,
      requestedMuxMode: json['requested_mux_mode'] as String? ?? '',
      effectiveMuxMode: json['effective_mux_mode'] as String? ?? '',
      muxReceiverOrdering: json['mux_receiver_ordering'] as String? ?? '',
      muxActiveLinks: runtimeNonNegInt(
        json['mux_active_links'],
        'mux_active_links',
        required: false,
      ),
      muxFallbackReason: json['mux_fallback_reason'] as String? ?? '',
      p2pState: P2PState.parse(json['p2p_state'] as String? ?? 'disabled'),
      traffic: RuntimeTrafficSnapshot.fromJson(
        json['traffic'] as Map<String, dynamic>?,
      ),
      connectedMonotonicMs: runtimeNonNegInt(
        json['connected_monotonic_ms'],
        'connected_monotonic_ms',
        required: false,
      ),
      lastError: RuntimeErrorSnapshot.fromJson(
        json['last_error'] as Map<String, dynamic>?,
      ),
    );
  }

  List<String> availableMuxModes({bool experimental = false}) {
    const modes = <String>['compat', 'flow', 'balance', 'stripe'];
    return modes
        .where((mode) => capabilities.contains('mux.$mode'))
        .where((mode) => mode != 'stripe' || experimental)
        .toList(growable: false);
  }

  String get effectiveMuxDisplayName =>
      effectiveMuxMode == 'compat' ? 'Compatibility mode' : effectiveMuxMode;

  List<String> get muxDiagnosticLines => <String>[
        if (requestedMuxMode.isNotEmpty) 'Requested VMUX: $requestedMuxMode',
        if (effectiveMuxMode.isNotEmpty)
          'Effective VMUX: $effectiveMuxDisplayName',
        if (muxFallbackReason.isNotEmpty)
          'Fallback reason: $muxFallbackReason',
      ];

  String get effectivePathDisplayName =>
      effectivePath == 'direct' ? 'Direct' : 'Relay';

  List<String> get p2pDiagnosticLines => <String>[
        'P2P: ${p2pState.displayName}',
        'Effective path: $effectivePathDisplayName',
      ];
}

/// Accepts JSON ints and whole-number doubles (JsonCpp / dart:convert edge).
int runtimeNonNegInt(
  Object? value,
  String field, {
  bool required = true,
}) {
  if (value == null) {
    if (required) {
      throw FormatException('Runtime $field is required');
    }
    return 0;
  }
  if (value is int) {
    if (value < 0) {
      throw FormatException('Runtime $field must be non-negative');
    }
    return value;
  }
  if (value is num) {
    final asInt = value.toInt();
    if (asInt < 0 || value != asInt) {
      throw FormatException('Runtime $field must be a non-negative integer');
    }
    return asInt;
  }
  throw FormatException('Runtime $field is required');
}
