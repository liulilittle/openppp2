import { createEmptyClientState } from './model.js'

function clone(value) {
  return structuredClone(value)
}

export function createTauriRuntime(bridge = window.__TAURI__) {
  let state = createEmptyClientState()
  const listeners = new Set()
  let unlisteners = []

  function emit() {
    const snapshot = clone(state)
    listeners.forEach((listener) => listener(snapshot))
  }

  function appendEvent(event) {
    state.events = [...state.events, {
      id: `${Date.now()}-${Math.random()}`,
      time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      message: event.message,
      severity: event.severity || 'info',
    }].slice(-500)
  }

  function processEvent(event) {
    if (event.type === 'telemetry') {
      appendEvent(event.payload)
      if (event.payload.signal === 'connected') {
        state.connection.status = 'connected'
        state.connection.connectedAt ||= Date.now()
        state.connection.lastError = ''
        if (state.connection.currentNodeId) void probeLatency([state.connection.currentNodeId])
      } else if (event.payload.signal === 'failed') {
        state.connection.status = 'error'
        state.connection.lastError = event.payload.message
      }
    } else if (event.type === 'stats') {
      state.stats = { ...state.stats, ...event.payload }
      state.connection.statsAvailable = true
    } else if (event.type === 'exited') {
      state.connection.status = event.payload.success ? 'disconnected' : 'error'
      state.connection.exitCode = event.payload.code
      state.connection.connectedAt = null
      state.connection.statsAvailable = false
      state.connection.pid = null
      if (!event.payload.success && !state.connection.lastError) {
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
    ])
    const bootstrap = await bridge.core.invoke('client_bootstrap')
    if (bootstrap.subscription) state.subscription = bootstrap.subscription
    state.config = bootstrap.config || '{}'
    state.launchOptions = bootstrap.launchOptions || {}
    state.settings = { ...state.settings, ...bootstrap.settings }
    emit()
    void probeLatency()
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
        }
      }
    },
    navigate(route) { state.route = route; emit() },
    async connect(nodeId = state.connection.currentNodeId || state.subscription.nodes[0]?.id) {
      if (!nodeId) return
      state.connection = { ...state.connection, status: 'connecting', currentNodeId: nodeId, exitCode: null, statsAvailable: false, lastError: '' }
      emit()
      try {
        const process = await bridge.core.invoke('client_connect', { nodeId })
        if (process) {
          state.connection.pid = process.pid ?? null
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
    async disconnect() { await bridge.core.invoke('client_disconnect') },
    async cancel() { await bridge.core.invoke('client_disconnect') },
    async switchNode(nodeId) {
      if (state.connection.status === 'connected' || state.connection.status === 'connecting') {
        await bridge.core.invoke('client_disconnect')
      }
      await runtime.connect(nodeId)
    },
    async toggleFavorite(nodeId) {
      state.subscription.nodes = state.subscription.nodes.map((node) => node.id === nodeId ? { ...node, favorite: !node.favorite } : node)
      emit()
      await bridge.core.invoke('client_toggle_favorite', { nodeId })
    },
    async refreshSubscription(url = state.subscription.url) {
      try {
        const subscription = await bridge.core.invoke('subscription_refresh', { url })
        state.subscription = subscription
        void probeLatency()
      } catch (error) {
        appendEvent({ message: String(error), severity: 'error' })
      }
      emit()
    },
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
  }
  runtime.ready = initialize()
  return runtime
}
