import test from 'node:test'
import assert from 'node:assert/strict'
import { parseRules, serializeRules, listRules, addRule, setRuleAction } from '../src/lib/policyRules.js'
import {
  LAN_RANGES, PRESETS, applyOptions, readOptions, matchPreset, presetOptions, optionErrors, geoFormat,
} from '../src/lib/routingPresets.js'

const base = () => ({ version: 2, dns: { mode: 'auto' } })
const header = 'default direct\ndns direct local\ndns proxy remote\n'

test('a preset fills visible options that round-trip through rules and policy', () => {
  const options = presetOptions('split-cn', { geositeSource: 'geosite-cn.txt', geoipSource: 'https://example.test/GeoIP.dat' })
  const { model, policy } = applyOptions(parseRules(header), base(), options)
  const read = readOptions(model, policy)
  assert.equal(read.defaultAction, 'proxy')
  assert.equal(read.lan, true)
  assert.equal(read.geosite, true)
  assert.equal(read.geoip, true)
  assert.equal(read.geositeSource, 'geosite-cn.txt')
  assert.equal(matchPreset(read), 'split-cn')
  assert.deepEqual(policy['rule-sets']['geosite-cn'], { format: 'geosite-text', tag: 'cn', source: { path: 'geosite-cn.txt' } })
  assert.deepEqual(policy['rule-sets']['geoip-cn'], { format: 'geoip-dat', tag: 'cn', source: { url: 'https://example.test/GeoIP.dat' } })
  const text = serializeRules(model)
  assert.match(text, /^default proxy/m)
  for (const range of LAN_RANGES) assert.match(text, new RegExp(`^${range.replace(/\./g, '\\.')}$`, 'm'))
  assert.match(text, /^set:geosite-cn$/m)
})

test('switching an option off removes only its rules and rule set', () => {
  let model = addRule(parseRules(header), { action: 'proxy', type: 'suffix', value: 'example.com' })
  ;({ model } = applyOptions(model, base(), { ...PRESETS['proxy-all'] }))
  const off = applyOptions(model, base(), { ...PRESETS['direct-all'] })
  const values = listRules(off.model).map((rule) => rule.value)
  assert.deepEqual(values, ['example.com'])
  assert.equal(off.model.defaultAction, 'direct')
  assert.equal(off.policy['rule-sets'], undefined)
  assert.equal(matchPreset(readOptions(off.model, off.policy)), 'direct-all')
})

test('an existing rule for an option is reused instead of duplicated', () => {
  let model = addRule(parseRules(header), { action: 'proxy', type: 'cidr', value: '10.0.0.0/8' })
  ;({ model } = applyOptions(model, base(), { ...PRESETS['proxy-all'] }))
  const lan = listRules(model).filter((rule) => rule.value === '10.0.0.0/8')
  assert.equal(lan.length, 1)
  assert.equal(lan[0].action, 'direct')
})

test('editing a managed rule elsewhere shows up as a custom combination', () => {
  let { model, policy } = applyOptions(parseRules(header), base(), { ...PRESETS['proxy-all'] })
  const rule = listRules(model).find((item) => item.value === '192.168.0.0/16')
  model = setRuleAction(model, rule.id, 'proxy')
  const read = readOptions(model, policy)
  assert.equal(read.lan, false)
  assert.equal(matchPreset(read), '')
})

test('a geo option needs a source and picks the format from the file name', () => {
  assert.deepEqual(optionErrors({ geosite: true, geositeSource: ' ', geoip: false }), { geosite: 'source' })
  assert.deepEqual(optionErrors({ geosite: false, geoip: true, geoipSource: 'cn.txt' }), {})
  assert.equal(geoFormat('geoip', 'C:/data/GeoIP.dat'), 'geoip-dat')
  assert.equal(geoFormat('geosite', 'https://example.test/list.txt?x=1'), 'geosite-text')
})
