import test from 'node:test'
import assert from 'node:assert/strict'
import {
  parseRules, serializeRules, listRules, addRule, removeRule, setRuleEnabled, setRuleAction,
  setDefaultAction, validateRule, parseToken, toToken, summarize,
} from '../src/lib/policyRules.js'

const SAMPLE = `default proxy              # exactly one
dns direct direct
dns proxy proxy

[direct]
=router.lan                # exact domain
example.cn
*.corp.example
keyword:intranet
regexp:^api[0-9]+\\.example\\.com$
192.168.0.0/16
set:geosite-cn

[proxy]
example.com

[reject]
ads.example

[dns:direct]
special.example
`

test('an untouched file round-trips byte for byte', () => {
  assert.equal(serializeRules(parseRules(SAMPLE)), SAMPLE)
})

test('rule tokens map to the kernel condition types', () => {
  const rules = listRules(parseRules(SAMPLE))
  assert.deepEqual(rules.map((r) => [r.action, r.type, r.value]), [
    ['direct', 'exact', 'router.lan'],
    ['direct', 'suffix', 'example.cn'],
    ['direct', 'subdomain', 'corp.example'],
    ['direct', 'keyword', 'intranet'],
    ['direct', 'regexp', '^api[0-9]+\\.example\\.com$'],
    ['direct', 'cidr', '192.168.0.0/16'],
    ['direct', 'set', 'geosite-cn'],
    ['proxy', 'suffix', 'example.com'],
    ['reject', 'suffix', 'ads.example'],
  ])
  assert.equal(rules[0].note, 'exact domain')
  assert.equal(parseRules(SAMPLE).defaultAction, 'proxy')
})

test('[dns:*] entries are not routing rules and survive edits', () => {
  const model = addRule(parseRules(SAMPLE), { action: 'proxy', type: 'suffix', value: 'github.com' })
  const text = serializeRules(model)
  assert.match(text, /\[dns:direct\]\nspecial\.example\n$/)
  assert.ok(!listRules(model).some((r) => r.value === 'special.example'))
})

test('a new rule lands at the end of its own section', () => {
  const text = serializeRules(addRule(parseRules(SAMPLE), { action: 'proxy', type: 'suffix', value: 'github.com' }))
  assert.match(text, /\[proxy\]\nexample\.com\ngithub\.com\n\n\[reject\]/)
})

test('a rule for an action without a section creates one before [dns:*]', () => {
  const base = 'default direct\ndns direct d\ndns proxy p\n\n[direct]\n10.0.0.0/8\n\n[dns:d]\nlan.example\n'
  const text = serializeRules(addRule(parseRules(base), { action: 'reject', type: 'keyword', value: 'ads' }))
  assert.equal(text, 'default direct\ndns direct d\ndns proxy p\n\n[direct]\n10.0.0.0/8\n\n[reject]\nkeyword:ads\n\n[dns:d]\nlan.example\n')
})

test('disabling writes a comment the kernel ignores, and re-enabling restores the rule', () => {
  let model = parseRules(SAMPLE)
  const id = listRules(model).find((r) => r.value === 'example.com').id
  model = setRuleEnabled(model, id, false)
  let text = serializeRules(model)
  assert.match(text, /\[proxy\]\n# off: example\.com\n/)
  model = parseRules(text)
  const reparsed = listRules(model).find((r) => r.value === 'example.com')
  assert.equal(reparsed.enabled, false)
  text = serializeRules(setRuleEnabled(model, reparsed.id, true))
  assert.match(text, /\[proxy\]\nexample\.com\n/)
})

test('plain comments inside a section stay comments, not disabled rules', () => {
  const model = parseRules('default proxy\n[direct]\n# my note\nexample.cn\n')
  assert.equal(listRules(model).length, 1)
  assert.equal(serializeRules(model), 'default proxy\n[direct]\n# my note\nexample.cn\n')
})

test('changing an action moves the rule and keeps the rest in place', () => {
  let model = parseRules(SAMPLE)
  const id = listRules(model).find((r) => r.value === 'ads.example').id
  model = setRuleAction(model, id, 'direct')
  const text = serializeRules(model)
  assert.match(text, /set:geosite-cn\nads\.example\n\n\[proxy\]/)
  assert.match(text, /\[reject\]\n\n\[dns:direct\]/)
})

test('removing and default changes serialise correctly', () => {
  let model = parseRules(SAMPLE)
  model = removeRule(model, listRules(model).find((r) => r.value === 'example.com').id)
  model = setDefaultAction(model, 'direct')
  const text = serializeRules(model)
  assert.ok(text.startsWith('default direct\n'))
  assert.ok(!/^example\.com$/m.test(text))
  assert.deepEqual(summarize(model), { direct: 7, proxy: 0, reject: 1, disabled: 0 })
})

test('a file without a default line gets one when the user picks a default', () => {
  const text = serializeRules(setDefaultAction(parseRules('[direct]\na.cn\n'), 'proxy'))
  assert.equal(text, 'default proxy\n[direct]\na.cn\n')
})

test('validation rejects values the kernel would refuse', () => {
  assert.equal(validateRule('suffix', 'example.com'), '')
  assert.equal(validateRule('suffix', 'https://example.com'), 'domain-only')
  assert.equal(validateRule('exact', 'bad domain'), 'whitespace')
  assert.equal(validateRule('cidr', '10.0.0.0/8'), '')
  assert.equal(validateRule('cidr', '10.0.0.0/33'), 'cidr')
  assert.equal(validateRule('cidr', '300.0.0.0/8'), 'cidr')
  assert.equal(validateRule('regexp', '^(a'), 'regexp')
  assert.equal(validateRule('set', 'geoip-cn', ['geoip-cn']), '')
  assert.equal(validateRule('set', 'missing', ['geoip-cn']), 'set-unknown')
  assert.equal(validateRule('keyword', ''), 'empty')
})

test('tokens round-trip through parse/toToken', () => {
  for (const token of ['=a.b', '*.a.b', 'keyword:x', 'regexp:^x$', 'set:geo', '1.2.3.0/24', 'a.b']) {
    const { type, value } = parseToken(token)
    assert.equal(toToken(type, value), token)
  }
})

test('CRLF input is normalised without losing rules', () => {
  const model = parseRules('default proxy\r\n[direct]\r\na.cn\r\n')
  assert.equal(listRules(model).length, 1)
  assert.equal(serializeRules(model), 'default proxy\n[direct]\na.cn\n')
})
