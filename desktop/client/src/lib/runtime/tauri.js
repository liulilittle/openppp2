import { createEmptyClientState } from './model.js'
import { redactText } from '../security.js'

function clone(value) {
  return structuredClone(value)
}

export function createTauriRuntime(bridge = window.__TAURI__) {
  let state = createEmptyClientState()
  const listeners = new Set()
  let unlisteners = []
  let freshnessTimer = null

  function emit() {
    const snapshot = clone(state)
    listeners.forEach((listener) => listener(snapshot))
  }

  function appendEvent(event) {
    state.events = [...state.events, {
      id: `${Date.now()}-${Math.random()}`,
      time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      message: redactText(event.message, state.subscription.sources?.map((s) => s.url) || [state.subscription.url]),
      severity: event.severity || 'info',
      sessionId: state.connection.sessionId, timestamp: Date.now(),
    }].slice(-500)
  }

  function processEvent(event) {
    if (event.sessionId != null && event.sessionId < state.connection.sessionId) return
    if (event.connection) {
      state.connection = { ...state.connection, ...event.connection, statsAvailable: !!event.connection.stats }
      if (event.connection.stats) state.stats = { ...state.stats, ...event.connection.stats }
      else state.connection.statsStale = false
    }
    if (event.type === 'telemetry') {
      appendEvent(event.payload)
      if (!event.connection && event.payload.signal === 'connected') {
        state.connection.status = 'connected'
        state.connection.connectedAt ||= Date.now()
        state.connection.lastError = ''
        if (state.connection.currentNodeId) void probeLatency([state.connection.currentNodeId])
      } else if (!event.connection && event.payload.signal === 'failed') {
        state.connection.status = 'error'
        state.connection.lastError = event.payload.message
      }
    } else if (event.type === 'stats') {
      state.stats = { ...state.stats, ...event.payload }
      state.connection.statsAvailable = true
      state.stats.sampledAt = event.payload.sampledAt || Date.now()
      state.connection.statsStale = false
      const point = { time: state.stats.sampledAt, rx: state.stats.rxRateMbps, tx: state.stats.txRateMbps }
      state.history = [...state.history.filter((previous) => Math.floor(previous.time / 1000) !== Math.floor(point.time / 1000)), point].filter((point) => point.time > Date.now() - 60_000).slice(-60)
    } else if (event.type === 'exited') {
      const recoveryPending = !!(event.connection?.recoveryPending || event.payload.recoveryPending)
      state.connection.recoveryPending = recoveryPending
      state.connection.status = recoveryPending
        ? 'recovery_pending'
        : event.connection?.status || (state.connection.status === 'stopping' || event.payload.success ? 'disconnected' : 'error')
      state.connection.exitCode = event.payload.code
      state.connection.connectedAt = null
      state.connection.statsAvailable = false
      state.connection.pid = null
      if (recoveryPending) {
        state.connection.lastError = 'network recovery is pending'
      } else if (state.connection.status === 'error' && !event.payload.success && !state.connection.lastError) {
        state.connection.lastError = `ppp 进程异常退出，退出码 ${event.payload.code ?? '未知'}`
      }
    }
    emit()
  }

  function applyLatencies(latencies) {
    state.subscription.nodes = state.subscription.nodes.map((node) => (
      Object.hasOwn(latencies, node.id)
        ? { ...node, latencyMs: Number.isFinite(latencies[node.id]) ? latencies[node.id] : null }
        : node
    ))
    emit()
  }

  async function probeLatency(nodeIds = null) {
    try {
      const latencies = await bridge.core.invoke('client_probe_latency', { nodeIds })
      if (latencies) applyLatencies(latencies)
    } catch {
      // A failed reference probe is represented by unchanged/null latency data.
    }
  }

  async function initialize() {
    unlisteners = await Promise.all([
      bridge.event.listen('client://process', ({ payload }) => processEvent(payload)),
      bridge.event.listen('client://latency', ({ payload }) => applyLatencies(payload)),
      bridge.event.listen('client://tray-error', ({ payload }) => { appendEvent({ message: String(payload), severity: 'error' }); state.proxyRecoveryPending = true; emit() }),
    ])
    const bootstrap = await bridge.core.invoke('client_bootstrap')
    if (bootstrap.subscription) state.subscription = bootstrap.subscription
    state.config = bootstrap.config || '{}'
    state.launchOptions = bootstrap.launchOptions || {}
    state.settings = { ...state.settings, ...bootstrap.settings }
    state.networkOverrides = bootstrap.networkOverrides || {}
    state.administrator = !!bootstrap.administrator
    state.proxyRecoveryPending = !!bootstrap.proxyRecoveryPending
    if (bootstrap.connection?.recoveryPending) {
      state.connection.recoveryPending = true
      state.connection.status = 'recovery_pending'
    }
    state.policyDir = bootstrap.policyDir || ''
    state.policyEnabled = !!bootstrap.policyEnabled
    if (bootstrap.connection) {
      state.connection = { ...state.connection, ...bootstrap.connection, currentNodeId: bootstrap.currentNodeId, mode: state.settings.connectionMode, statsAvailable: !!bootstrap.connection.stats }
      if (bootstrap.connection.stats) state.stats = { ...state.stats, ...bootstrap.connection.stats }
    }
    state.stats = { ...state.stats, ...(bootstrap.network || {}) }
    freshnessTimer = setInterval(() => {
      const stale = state.connection.statsAvailable && Date.now() - (state.stats.sampledAt || 0) > 5000
      if (stale !== state.connection.statsStale) { state.connection.statsStale = stale; emit() }
    }, 1000)
    freshnessTimer.unref?.()
    emit()
    void probeLatency()
    if (state.settings.pppPath) void runtime.inspectKernel().catch(() => {})
  }

  const runtime = {
    kind: 'tauri',
    ready: null,
    subscribe(listener) {
      listeners.add(listener)
      listener(clone(state))
      return async () => {
        listeners.delete(listener)
        if (listeners.size === 0 && unlisteners.length) {
          unlisteners.forEach((unlisten) => unlisten())
          unlisteners = []
          clearInterval(freshnessTimer)
        }
      }
    },
    navigate(route) { state.route = route; emit() },
    selectNode(nodeId) { if (!state.connection.pid) { state.connection.currentNodeId = nodeId; emit() } },
    async connect(nodeId = state.connection.currentNodeId || state.subscription.nodes[0]?.id) {
      if (!nodeId) return
      if (state.connection.pid || ['starting', 'connecting', 'connected', 'reconnecting', 'stopping'].includes(state.connection.status)) return
      state.history = []
      state.connection = { ...state.connection, status: 'connecting', currentNodeId: nodeId, exitCode: null, statsAvailable: false, lastError: '', mode: state.settings.connectionMode || 'client' }
      emit()
      try {
        const process = await bridge.core.invoke('client_connect', { nodeId })
        if (process) {
          const sessionId = process.sessionId || 0
          if (sessionId < state.connection.sessionId) return
          const exited = sessionId === state.connection.sessionId && ['disconnected', 'error'].includes(state.connection.status)
          if (!exited) state.connection.pid = process.pid ?? null
          state.connection.sessionId = Math.max(state.connection.sessionId, sessionId)
          state.stats = { ...state.stats, ...(process.network || {}) }
          emit()
        }
      } catch (error) {
        state.connection.status = 'error'
        state.connection.lastError = String(error)
        appendEvent({ message: String(error), severity: 'error' })
        emit()
      }
    },
    async disconnect() {
      state.connection.status = 'stopping'; emit()
      try {
        const connection = await bridge.core.invoke('client_disconnect')
        if (connection) processEvent({type:'state',sessionId:connection.sessionId,connection})
        else { state.connection = {...state.connection,status:'disconnected',phase:'idle',pid:null,connectedAt:null,statsAvailable:false}; emit() }
      } catch (error) { state.connection.lastError = String(error); appendEvent({ message: String(error), severity: 'error' }); emit(); throw error }
    },
    async retryRecovery() {
      const result = await bridge.core.invoke('client_retry_recovery')
      if (result?.networkRecoveryPending) {
        state.connection.recoveryPending = true
        state.connection.status = 'recovery_pending'
        state.connection.lastError = result.message || 'network recovery is pending'
      } else {
        state.connection.recoveryPending = false
        state.connection.status = 'disconnected'
        state.connection.phase = 'idle'
        state.connection.lastError = ''
      }
      if (result && Object.hasOwn(result, 'proxyRecoveryPending')) state.proxyRecoveryPending = !!result.proxyRecoveryPending
      emit()
      return result
    },
    async cancel() { await runtime.disconnect() },
    async switchNode(nodeId) {
      if (state.connection.pid || ['connected', 'connecting', 'starting', 'reconnecting'].includes(state.connection.status)) {
        await bridge.core.invoke('client_disconnect')
      }
      state.connection.pid = null; state.connection.status = 'disconnected'
      await runtime.connect(nodeId)
    },
    async toggleFavorite(nodeId) {
      await bridge.core.invoke('client_toggle_favorite', { nodeId })
      state.subscription.nodes = state.subscription.nodes.map((node) => node.id === nodeId ? { ...node, favorite: !node.favorite } : node)
      emit()
    },
    async refreshSubscription(url = state.subscription.url, sourceId = null) {
      try {
        const subscription = await bridge.core.invoke('subscription_refresh', { url, sourceId })
        state.subscription = subscription
        void probeLatency()
      } catch (error) {
        appendEvent({ message: String(error), severity: 'error' })
      }
      emit()
    },
    async saveSubscription(source) { state.subscription = await bridge.core.invoke('client_save_subscription', { source }); emit() },
    async deleteSubscription(sourceId) { state.subscription = await bridge.core.invoke('client_delete_subscription', { sourceId }); emit() },
    async updateNetwork(overrides) { state.networkOverrides = await bridge.core.invoke('client_update_network', { overrides }); emit(); return state.networkOverrides },
    async restoreProxy(force = false) { await bridge.core.invoke('client_restore_proxy', { force }); state.proxyRecoveryPending = false; emit() },
    async pickExecutable() { const path = await bridge.core.invoke('client_pick_executable'); if (path) await runtime.updateSetting('pppPath', path) },
    async elevate() { await bridge.core.invoke('client_elevate') },
    async inspectKernel() { state.kernel = await bridge.core.invoke('client_kernel_info'); emit(); return state.kernel },
    async preview() { return bridge.core.invoke('client_preview', { nodeId: state.connection.currentNodeId || state.subscription.nodes[0]?.id || null }) },
    async openData() { await bridge.core.invoke('client_open_data') },
    async probeNodes(nodeIds = null) { await probeLatency(nodeIds) },
    async updateConfig(config) {
      await bridge.core.invoke('client_update_config', { config })
      state.config = config
      emit()
    },
    async updateClientConfig(config, options) {
      const saved = await bridge.core.invoke('client_update_client_config', { config, options })
      state.config = config
      state.launchOptions = saved || {}
      emit()
      return state.launchOptions
    },
    async saveManualNode(node) {
      const subscription = await bridge.core.invoke('client_upsert_manual_node', { node })
      state.subscription = subscription
      emit()
      void probeLatency()
      return subscription
    },
    async deleteManualNode(nodeId) {
      const subscription = await bridge.core.invoke('client_delete_manual_node', { nodeId })
      state.subscription = subscription
      emit()
      return subscription
    },
    async updateLaunchOptions(options) {
      const saved = await bridge.core.invoke('client_update_launch_options', { options })
      state.launchOptions = saved || {}
      emit()
      return state.launchOptions
    },
    async updateSetting(key, value) {
      await bridge.core.invoke('client_update_setting', { key, value })
      state.settings = { ...state.settings, [key]: value }
      emit()
    },
    async clearEvents() {
      state.events = []
      emit()
    },
    // Policy v2 workspace and offline `ppp policy` commands; the page keeps the draft.
    policyLoad() { return bridge.core.invoke('policy_load') },
    async policySetEnabled(enabled) { state.policyEnabled = await bridge.core.invoke('policy_set_enabled', { enabled }); emit(); return state.policyEnabled },
    policySave(policy, rules) { return bridge.core.invoke('policy_save', { policy, rules }) },
    policyCheck(policy, rules) { return bridge.core.invoke('policy_check', { policy, rules }) },
    policyExplain(policy, rules, target, network, port) { return bridge.core.invoke('policy_explain', { policy, rules, target, network, port: port || null }) },
    policyInit(template, geoip, geosite) { return bridge.core.invoke('policy_init', { template, geoip: geoip || null, geosite: geosite || null }) },
    policyMigrate() { return bridge.core.invoke('policy_migrate') },
    policyStatus() { return bridge.core.invoke('policy_status') },
    policyUpdate() { return bridge.core.invoke('policy_update') },
    policyResetFakeIp() { return bridge.core.invoke('policy_reset_fake_ip') },
  }
  runtime.ready = initialize()
  return runtime
}
