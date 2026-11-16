import test from 'node:test'
import assert from 'node:assert/strict'
import { getPath, setPath, effective, parseBase, completeListeners } from '../src/lib/overrides.js'

test('effective values prefer overrides, then the base configuration, then the fallback', () => {
  const base = { dns: { servers: { domestic: 'alidns' } } }
  assert.equal(effective({}, base, 'dns/servers/domestic', 'doh.pub'), 'alidns')
  assert.equal(effective({ dns: { servers: { domestic: '114' } } }, base, 'dns/servers/domestic', 'doh.pub'), '114')
  assert.equal(effective({}, {}, 'dns/servers/foreign', 'cloudflare'), 'cloudflare')
  assert.equal(effective({ udp: { dns: { cache: false } } }, {}, 'udp/dns/cache', true), false)
})

test('setPath copies, creates intermediate objects and removes on undefined', () => {
  const source = { a: { b: 1 } }
  const next = setPath(source, 'a/c/d', 2)
  assert.deepEqual(next, { a: { b: 1, c: { d: 2 } } })
  assert.deepEqual(source, { a: { b: 1 } })
  assert.deepEqual(setPath(next, 'a/c/d', undefined), { a: { b: 1, c: {} } })
  assert.equal(getPath(next, 'a/missing/deep'), undefined)
})

test('an unreadable base configuration is treated as empty', () => {
  assert.deepEqual(parseBase('not json'), {})
  assert.deepEqual(parseBase('[1]'), {})
  assert.deepEqual(parseBase('{"x":1}'), { x: 1 })
})

test('a partial listener edit is completed from the effective values', () => {
  const base = { client: { 'http-proxy': { bind: '0.0.0.0', port: 8888 } } }
  const next = completeListeners({ client: { 'http-proxy': { port: 9000 } } }, base)
  assert.deepEqual(next.client['http-proxy'], { port: 9000, bind: '0.0.0.0' })
  assert.equal(next.client['socks-proxy'], undefined)
})
