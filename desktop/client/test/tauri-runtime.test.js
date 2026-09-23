import test from 'node:test'
import assert from 'node:assert/strict'
import { createTauriRuntime } from '../src/lib/runtime/tauri.js'

function fakeBridge() {
  const calls = []
  const eventHandlers = new Map()
  const bootstrap = {
    subscription: {
      url: 'https://sub.test/token', name: 'Real nodes', updatedAt: '2026-07-19T12:00:00Z',
      lastSyncedAt: '2026-07-19T12:01:00Z', cached: false, cacheAgeMinutes: 0,
      nodes: [{ id: 'real-1', name: 'Real 1', subtitle: 'edge', address: '127.0.0.1:20000', latencyMs: null, favorite: false }],
    },
    config: '{"concurrent":1}',
    launchOptions: { mux: 2, muxMode: 'compat' },
    settings: { autostart: false, closeToTray: true, disconnectOnExit: true, language: '简体中文', appearance: '深色', pppPath: '' },
  }
  return {
    calls,
    bridge: {
      core: { invoke: async (command, args) => {
        calls.push([command, args])
        if (command === 'client_bootstrap') return bootstrap
        if (command === 'subscription_refresh') return bootstrap.subscription
        if (command === 'client_probe_latency') return { 'real-1': 17 }
        if (command === 'client_upsert_manual_node') return {
          ...bootstrap.subscription,
          nodes: [{ id: 'manual:1', name: args.node.name, subtitle: '', address: '127.0.0.1:21000', latencyMs: null, favorite: false, source: 'manual', config: args.node.config, options: args.node.options }],
        }
        if (command === 'client_delete_manual_node') return { ...bootstrap.subscription, nodes: [] }
        if (command === 'client_update_launch_options') return args.options
        if (command === 'client_update_client_config') return args.options
        return null
      } },
      event: { listen: async (name, handler) => {
        eventHandlers.set(name, handler)
        return () => eventHandlers.delete(name)
      } },
    },
    emit(payload, name = 'client://process') { eventHandlers.get(name)?.({ payload }) },
    listenerCount() { return eventHandlers.size },
  }
}

test('tauri runtime bootstraps without demo data and cleans up listener', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  const snapshots = []
  const unsubscribe = runtime.subscribe((state) => snapshots.push(state))
  await runtime.ready
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(runtime.kind, 'tauri')
  assert.equal(snapshots[0].subscription.nodes.length, 0)
  assert.equal(snapshots.at(-1).subscription.nodes[0].id, 'real-1')
  assert.equal(snapshots.at(-1).connection.status, 'disconnected')
  await unsubscribe()
  assert.equal(fake.listenerCount(), 0)
  assert.equal(fake.calls[0][0], 'client_bootstrap')
  assert.equal(fake.calls.some(([name, args]) => name === 'client_probe_latency' && args.nodeIds === null), true)
})

test('tauri runtime invokes commands and derives connection state only from events', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready

  await runtime.connect('real-1')
  assert.equal(state.connection.status, 'connecting')
  assert.equal(fake.calls.at(-1)[0], 'client_connect')
  fake.emit({ type: 'telemetry', payload: { message: 'session established role=main', severity: 'success', signal: 'connected' } })
  await new Promise((resolve) => setImmediate(resolve))
  assert.equal(state.connection.status, 'connected')
  assert.equal(state.events.at(-1).message, 'session established role=main')
  assert.equal(fake.calls.some(([name, args]) => name === 'client_probe_latency' && args.nodeIds?.[0] === 'real-1'), true)

  fake.emit({ type: 'exited', payload: { code: 7, success: false } })
  assert.equal(state.connection.status, 'error')
  assert.equal(state.connection.exitCode, 7)
})

test('tauri runtime merges latency only for known nodes and reprobes after refresh', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready
  fake.emit({ 'real-1': 24, stale: 1 }, 'client://latency')
  assert.equal(state.subscription.nodes[0].latencyMs, 24)
  assert.equal(state.subscription.nodes.some((node) => node.id === 'stale'), false)

  const before = fake.calls.filter(([name]) => name === 'client_probe_latency').length
  await runtime.refreshSubscription('https://sub.test/next')
  await new Promise((resolve) => setImmediate(resolve))
  const after = fake.calls.filter(([name]) => name === 'client_probe_latency').length
  assert.equal(after, before + 1)
})

test('tauri runtime maps stats and persists edits through explicit commands', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready
  fake.emit({ type: 'stats', payload: { rxRateMbps: 8, txRateMbps: 2, rxBytes: 100, txBytes: 50, qualityPercent: 99, qualityGrade: 'Good', activeLinks: 2, effectivePath: 'direct' } })
  assert.equal(state.connection.statsAvailable, true)
  assert.equal(state.stats.rxRateMbps, 8)

  await runtime.updateConfig('{"concurrent":2}')
  await runtime.updateSetting('pppPath', 'C:\\ppp.exe')
  await runtime.toggleFavorite('real-1')
  assert.deepEqual(fake.calls.slice(-3).map(([name]) => name), ['client_update_config', 'client_update_setting', 'client_toggle_favorite'])
})

test('tauri runtime persists manual profiles and launch options through backend snapshots', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready
  assert.deepEqual(state.launchOptions, { mux: 2, muxMode: 'compat' })

  const node = {
    id: null,
    name: 'Local',
    subtitle: '',
    config: { key: { 'protocol-key': 'p' }, client: { server: 'ppp://127.0.0.1:21000/' } },
    options: {},
  }
  await runtime.saveManualNode(node)
  assert.equal(fake.calls.some(([name]) => name === 'client_upsert_manual_node'), true)
  assert.equal(state.subscription.nodes[0].source, 'manual')

  await runtime.updateLaunchOptions({ mux: 4, muxMode: 'flow' })
  assert.equal(fake.calls.at(-1)[0], 'client_update_launch_options')
  assert.deepEqual(state.launchOptions, { mux: 4, muxMode: 'flow' })

  await runtime.updateClientConfig('{"concurrent":3}', { mux: 6, muxMode: 'balance' })
  assert.equal(fake.calls.at(-1)[0], 'client_update_client_config')
  assert.equal(state.config, '{"concurrent":3}')
  assert.deepEqual(state.launchOptions, { mux: 6, muxMode: 'balance' })

  await runtime.deleteManualNode('manual:1')
  assert.equal(fake.calls.at(-1)[0], 'client_delete_manual_node')
  assert.equal(state.subscription.nodes.length, 0)
})
