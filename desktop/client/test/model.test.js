import test from 'node:test'
import assert from 'node:assert/strict'

import {
  connectionStates,
  createClientState,
  latencyTone,
  subscriptionNotice,
} from '../src/lib/runtime/model.js'

test('exposes exactly the four documented connection states', () => {
  assert.deepEqual(Object.keys(connectionStates), [
    'connected',
    'connecting',
    'disconnected',
    'error',
  ])
})

test('client state contains only subscription fields available to the client', () => {
  const state = createClientState()
  assert.equal(state.subscription.name, '个人订阅')
  assert.equal(state.subscription.nodes.length, 4)
  assert.equal('quota' in state.subscription, false)
  assert.equal('load' in state.subscription.nodes[0], false)
  assert.equal('online' in state.subscription.nodes[0], false)
})

test('latency tone follows the direct-reference latency thresholds', () => {
  assert.equal(latencyTone(32), 'good')
  assert.equal(latencyTone(86), 'warning')
  assert.equal(latencyTone(138), 'danger')
  assert.equal(latencyTone(null), 'muted')
})

test('cached subscription notice reports cache age without changing connection state', () => {
  const notice = subscriptionNotice({ cached: true, cacheAgeMinutes: 125 })
  assert.equal(notice, '正在使用 2 小时前的缓存')
  assert.equal(subscriptionNotice({ cached: false }), '')
})
