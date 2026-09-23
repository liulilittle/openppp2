import { createMockRuntime } from './mock.js'
import { createTauriRuntime } from './tauri.js'

export function createRuntime() {
  return globalThis.window?.__TAURI__ ? createTauriRuntime(window.__TAURI__) : Object.assign(createMockRuntime(), { kind: 'demo' })
}
