import test from 'node:test'
import assert from 'node:assert/strict'
import { redactText } from '../src/lib/security.js'
test('logs redact credentials and subscription URL paths',() => {
  const text=redactText('protocol-key=secret token="abc" URL=https://host.test/sub/private?token=x')
  assert(!text.includes('secret')); assert(!text.includes('abc')); assert(!text.includes('/private')); assert(!text.includes('token=x'))
  const diagnostics=redactText(JSON.stringify({key:{'protocol-key':'secret'},password:'private'}))
  assert.equal(JSON.parse(diagnostics).key['protocol-key'],'[redacted]')
  assert(!diagnostics.includes('private'))
})
