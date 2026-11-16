// Path helpers for the network overrides object (`client_update_network`).
// A value missing from the overrides falls back to the base configuration, so
// the pages show what the next connection will actually use.

export function getPath(source, path) {
  return path.split('/').reduce((value, key) => (value == null ? undefined : value[key]), source)
}

/** Effective value: the override when set, else the base configuration, else `fallback`. */
export function effective(overrides, base, path, fallback) {
  return getPath(overrides, path) ?? getPath(base, path) ?? fallback
}

/** Returns a copy of `source` with `path` set; `undefined` removes the key. */
export function setPath(source, path, value) {
  const next = structuredClone(source || {})
  const keys = path.split('/')
  let node = next
  for (const key of keys.slice(0, -1)) {
    if (!node[key] || typeof node[key] !== 'object' || Array.isArray(node[key])) node[key] = {}
    node = node[key]
  }
  if (value === undefined) delete node[keys.at(-1)]
  else node[keys.at(-1)] = value
  return next
}

/** Parses the base configuration text; an unreadable config is treated as empty. */
export function parseBase(configText) {
  try {
    const value = JSON.parse(configText || '{}')
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  } catch {
    return {}
  }
}

// HTTP/SOCKS listeners need both bind and port; fill the missing half from the
// effective value so a partial edit never writes a listener the kernel rejects.
export function completeListeners(overrides, base) {
  let next = overrides
  for (const [name, port] of [['http-proxy', 8080], ['socks-proxy', 1080]]) {
    if (!getPath(next, `client/${name}`)) continue
    if (getPath(next, `client/${name}/bind`) === undefined) next = setPath(next, `client/${name}/bind`, effective(next, base, `client/${name}/bind`, '127.0.0.1'))
    if (getPath(next, `client/${name}/port`) === undefined) next = setPath(next, `client/${name}/port`, effective(next, base, `client/${name}/port`, port))
  }
  return next
}

export const DOMESTIC_DNS = ['doh.pub', 'alidns', '114', 'tuna', 'baidu', '360']
export const FOREIGN_DNS = ['cloudflare', 'google', 'quad9', 'adguard', 'nextdns', 'mullvad']
// Kernel providers with a DoH/DoT endpoint; policy resolvers use nothing else.
export const ENCRYPTED_DNS = [...DOMESTIC_DNS, ...FOREIGN_DNS].filter((name) => name !== '114' && name !== 'baidu')
