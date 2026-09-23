import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const clientDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifestPath = resolve(clientDir, 'src-tauri', 'Cargo.toml')

function tomlSection(source, name) {
  const marker = `[${name}]`
  const start = source.indexOf(marker)
  if (start < 0) return ''
  const body = source.slice(start + marker.length)
  const nextSection = body.search(/^\[/m)
  return nextSection < 0 ? body : body.slice(0, nextSection)
}

test('release builds use embedded assets while the desktop script stays in dev mode', () => {
  const cargoToml = readFileSync(manifestPath, 'utf8')
  const features = tomlSection(cargoToml, 'features')
  assert.match(features, /^default\s*=\s*\["custom-protocol"\]\s*$/m)
  assert.match(features, /^custom-protocol\s*=\s*\["tauri\/custom-protocol"\]\s*$/m)

  const packageJson = JSON.parse(readFileSync(resolve(clientDir, 'package.json'), 'utf8'))
  assert.match(packageJson.scripts.desktop, /--no-default-features/)
})
