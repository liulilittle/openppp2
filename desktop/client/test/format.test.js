import test from 'node:test'
import assert from 'node:assert/strict'
import {formatBytes} from '../src/lib/format.js'

test('small nonzero traffic is visible with the appropriate byte unit', () => {
  assert.equal(formatBytes(7),'7 B')
  assert.equal(formatBytes(2048),'2.0 KB')
  assert.equal(formatBytes(1024 ** 2),'1.0 MB')
  assert.equal(formatBytes(1024 ** 3),'1.00 GB')
})
