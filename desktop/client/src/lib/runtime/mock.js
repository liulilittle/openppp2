import { createClientState, createEmptyClientState } from './model.js'

function clone(value) {
  return structuredClone(value)
}

export function createMockRuntime() {
  let state = createClientState()
  const empty=createEmptyClientState()
  state={ ...empty,...state, connection:{...empty.connection,...state.connection}, settings:{...empty.settings,...state.settings}, subscription:{...empty.subscription,...state.subscription} }
  state.networkOverrides={}; state.history=[]
  const listeners = new Set()
  let transitionTimer = null

  function emit() {
    const snapshot = clone(state)
    listeners.forEach((listener) => listener(snapshot))
  }

  function appendEvent(message, severity = 'info') {
    state.events = [
      ...state.events,
      {
        id: Date.now() + Math.random(),
        time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
        message,
        severity,
      },
    ].slice(-200)
  }

  function finishConnection(nodeId) {
    const node = state.subscription.nodes.find((item) => item.id === nodeId)
    state.connection.status = 'connected'
    state.connection.currentNodeId = nodeId
    state.connection.connectedAt = Date.now()
    state.connection.exitCode = null
    appendEvent(`session established role=main node=${node?.name || nodeId}`, 'success')
    emit()
  }

  return {
    ready: Promise.resolve(),
    selectNode(nodeId) { state.connection.currentNodeId=nodeId; emit() },
    async updateNetwork(overrides) { state.networkOverrides=structuredClone(overrides); emit(); return overrides },
    async saveSubscription(source) { const saved={...source,id:source.id || `s${Date.now()}`}; state.subscription.sources=[...state.subscription.sources.filter((s) => s.id !== saved.id),saved]; emit() },
    async deleteSubscription(sourceId) { state.subscription.sources=state.subscription.sources.filter((s) => s.id !== sourceId); emit() },
    async restoreProxy() { state.proxyRecoveryPending=false; emit() },
    async retryRecovery() {
      state.connection.recoveryPending = false
      state.connection.status = 'disconnected'
      state.connection.phase = 'idle'
      state.connection.lastError = ''
      emit()
      return { networkRecoveryPending: false, proxyRecoveryPending: state.proxyRecoveryPending }
    },
    async inspectKernel() { throw new Error('Kernel inspection requires the Windows desktop app') },
    async pickExecutable() { throw new Error('File selection requires the Windows desktop app') },
    async elevate() { throw new Error('Elevation requires the Windows desktop app') },
    async openData() { throw new Error('Opening app data requires the Windows desktop app') },
    async preview() { return {config:state.networkOverrides,args:[]} },
    async probeNodes() { emit() },
    ...createMockPolicy(),
    subscribe(listener) {
      listeners.add(listener)
      listener(clone(state))
      return () => listeners.delete(listener)
    },
    navigate(route) {
      state.route = route
      emit()
    },
    connect(nodeId = state.connection.currentNodeId || state.subscription.nodes[0].id) {
      clearTimeout(transitionTimer)
      state.connection.status = 'connecting'
      state.connection.currentNodeId = nodeId
      state.connection.statsAvailable = false
      appendEvent(`tcp connecting ${nodeId}`)
      emit()
      transitionTimer = setTimeout(() => {
        state.connection.statsAvailable = true
        appendEvent('exchanger connected', 'success')
        finishConnection(nodeId)
      }, 900)
    },
    disconnect() {
      clearTimeout(transitionTimer)
      state.connection.status = 'disconnected'
      state.connection.connectedAt = null
      state.connection.statsAvailable = false
      appendEvent('process exited code=0')
      emit()
    },
    cancel() {
      clearTimeout(transitionTimer)
      state.connection.status = 'disconnected'
      state.connection.statsAvailable = false
      appendEvent('connection cancelled')
      emit()
    },
    switchNode(nodeId) {
      this.connect(nodeId)
    },
    toggleFavorite(nodeId) {
      state.subscription.nodes = state.subscription.nodes.map((node) =>
        node.id === nodeId ? { ...node, favorite: !node.favorite } : node,
      )
      emit()
    },
    async refreshSubscription() {
      state.subscription.lastSyncedAt = new Date().toISOString()
      state.subscription.cached = false
      state.subscription.cacheAgeMinutes = 0
      appendEvent('subscription refreshed', 'success')
      emit()
    },
    updateConfig(config) {
      state.config = config
      emit()
    },
    async updateClientConfig(config, options) {
      state.config = config
      state.launchOptions = structuredClone(options)
      emit()
      return state.launchOptions
    },
    async saveManualNode(node) {
      const id = node.id || `manual:${Date.now()}`
      const server = node.config?.client?.server || ''
      const address = server.replace(/^ppp:\/\/(?:wss?\/)?/, '').split('/')[0]
      const saved = { ...node, id, address, latencyMs: null, favorite: false, source: 'manual' }
      const index = state.subscription.nodes.findIndex((item) => item.id === id)
      if (index >= 0) state.subscription.nodes[index] = saved
      else state.subscription.nodes = [saved, ...state.subscription.nodes]
      emit()
      return state.subscription
    },
    async deleteManualNode(nodeId) {
      state.subscription.nodes = state.subscription.nodes.filter((node) => node.id !== nodeId)
      emit()
      return state.subscription
    },
    async updateLaunchOptions(options) {
      state.launchOptions = structuredClone(options)
      emit()
      return state.launchOptions
    },
    updateSetting(key, value) {
      state.settings = { ...state.settings, [key]: value }
      emit()
    },
    clearEvents() {
      state.events = []
      emit()
    },
    simulate(status) {
      clearTimeout(transitionTimer)
      state.connection.status = status
      state.connection.statsAvailable = status === 'connected'
      state.connection.exitCode = status === 'error' ? -1 : null
      if (status === 'error') appendEvent('authentication failed / server rejected', 'error')
      emit()
    },
  }
}

// Demo policy commands: shaped like `ppp policy --json` reports, no kernel involved.
// Explain approximates the documented priority (explicit rules before rule sets;
// exact > suffix/subdomain with the longest winning > keyword > regex; longest
// IPv4 prefix) so the preview behaves plausibly. Real answers come from the kernel.
const DEMO_GEOSITE_CN = ['cn', 'baidu.com', 'qq.com', 'bilibili.com', 'taobao.com', 'zhihu.com', 'jd.com']
const DEMO_GEOIP_CN = ['114.114.114.114/32', '223.5.5.0/24', '119.29.29.0/24', '36.152.44.0/24']
const DEMO_CIDR = /^\d+\.\d+\.\d+\.\d+\/\d+$/

function demoIp(text) {
  const parts = text.split('.').map(Number)
  if (parts.length !== 4 || !parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255)) return null
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}

function demoInCidr(ip, cidr) {
  const [net, bits] = cidr.split('/')
  const network = demoIp(net), prefix = Number(bits)
  if (network === null || !(prefix >= 0 && prefix <= 32)) return false
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  return ((ip & mask) >>> 0) === ((network & mask) >>> 0)
}

function demoExplain(rulesText, target) {
  const host = String(target || '').trim().toLowerCase()
  const ip = demoIp(host)
  const lines = String(rulesText || '').split('\n')
  let section = null, best = null, defaultAction = 'proxy'
  const consider = (score, action, token, line) => { if (!best || score > best.score) best = { score, action, token, line } }
  lines.forEach((raw, index) => {
    const text = raw.replace(/\s#.*$/, '').trim()
    const header = /^\[([^\]]+)\]$/.exec(text)
    if (header) { section = header[1]; return }
    const def = /^default\s+(direct|proxy|reject)/.exec(text)
    if (def && section === null) { defaultAction = def[1]; return }
    if (!['direct', 'proxy', 'reject'].includes(section) || !text || text.startsWith('#')) return
    const line = index + 1
    if (ip !== null) {
      if (DEMO_CIDR.test(text) && demoInCidr(ip, text)) consider(2000 + Number(text.split('/')[1]), section, text, line)
      if (text === 'set:geoip-cn' && DEMO_GEOIP_CN.some((c) => demoInCidr(ip, c))) consider(100, section, text, line)
      return
    }
    if (text.startsWith('=')) { if (host === text.slice(1)) consider(4000, section, text, line) }
    else if (text.startsWith('*.')) { const v = text.slice(2); if (host.endsWith(`.${v}`)) consider(3000 + v.length + 0.5, section, text, line) }
    else if (text.startsWith('keyword:')) { if (host.includes(text.slice(8))) consider(2000, section, text, line) }
    else if (text.startsWith('regexp:')) { try { if (new RegExp(text.slice(7)).test(host)) consider(1000, section, text, line) } catch { /* invalid in demo */ } }
    else if (text === 'set:geosite-cn') { if (DEMO_GEOSITE_CN.some((d) => host === d || host.endsWith(`.${d}`))) consider(100, section, text, line) }
    else if (!text.includes(':') && !DEMO_CIDR.test(text)) { if (host === text || host.endsWith(`.${text}`)) consider(3000 + text.length, section, text, line) }
  })
  const dnsLine = lines.findIndex((l) => /^\s*dns\s+proxy\s+/.test(l))
  return {
    route: best
      ? { action: best.action, matched: true, rule_id: best.token, source: 'explicit', file: 'routing.rules', line: best.line, needs_ip: false }
      : { action: defaultAction, matched: false, rule_id: 'default', source: 'default', file: 'routing.rules', line: 1, reason: 'default action' },
    dns: { applicable: ip === null, resolver: 'remote', via: 'proxy', rejected: false, rule_id: 'dns proxy', file: 'routing.rules', line: dnsLine + 1 },
  }
}

function createMockPolicy() {
  const report = (command, extra = {}) => ({ exitCode: 0, report: { schema: 1, command, status: 'ok', diagnostics: [], ...extra } })
  const basePolicy = () => ({ version: 2, rules: { path: 'routing.rules' }, ipv6: 'block', dns: { mode: 'auto', 'fake-ip': { range: '198.18.0.0/16', storage: './dns-fake-ip', identity: 'client-default' }, resolvers: { local: { via: 'direct', servers: ['doh.pub'] }, remote: { via: 'proxy', servers: ['cloudflare'] } } } })
  const header = (action) => `default ${action}\ndns direct local\ndns proxy remote\n`
  const lan = '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n'
  const template = (name = 'proxy-all', geoip = '', geosite = '') => {
    if (name === 'direct-all') return { policy: basePolicy(), rules: header('direct') }
    if (name === 'split-cn') {
      const policy = basePolicy()
      const source = (value) => (/^https?:\/\//i.test(value) ? { url: value } : { path: value })
      policy['rule-sets'] = {
        'geoip-cn': { format: 'geoip-dat', tag: 'cn', source: source(geoip || './GeoIP.dat') },
        'geosite-cn': { format: 'geosite-dat', tag: 'cn', source: source(geosite || './GeoSite.dat') },
      }
      return { policy, rules: `${header('proxy')}\n[direct]\nset:geosite-cn\nset:geoip-cn\n${lan}\n[reject]\nkeyword:adservice\n` }
    }
    return { policy: basePolicy(), rules: `${header('proxy')}\n[direct]\n${lan}` }
  }
  const countRules = (rules) => String(rules || '').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && !/^(default|dns)\s|^\[/.test(l)).length
  let saved = null, enabled = false
  return {
    async policyLoad() { return { enabled, policyDir: 'C:\\Users\\demo\\AppData\\Roaming\\OpenPPP2\\policy', policy: saved?.policy || null, rules: saved?.rules || '', kernelSupported: true, kernelError: '' } },
    async policySetEnabled(value) { if (value && !saved) throw new Error('Create and save a policy before enabling it'); enabled = value; return value },
    async policySave(policy, rules) { saved = { policy, rules }; return { policy, rules, result: report('check', { rule_count: countRules(rules) }) } },
    async policyCheck(policy, rules) { return report('check', { policy_version: 1, rule_count: countRules(rules) }) },
    async policyExplain(policy, rules, target) { return report('explain', demoExplain(rules, target)) },
    async policyInit(name, geoip, geosite) { return { ...template(name, geoip, geosite), result: report('init', { template: name }) } },
    async policyMigrate() { return { ...template('proxy-all'), result: { exitCode: 5, report: { schema: 1, command: 'migrate', status: 'draft', diagnostics: [], migration: { status: 'draft', routing_equivalence: 'unverified', whole_policy_equivalence: 'draft', diagnostics: [{ code: 'E_MIGRATE_DNS_RUNTIME', message: 'Legacy Fake-IP, cache, or ECS behavior differs from policy-scoped v2 DNS.' }] } } } } },
    async policyStatus() { throw new Error('No policy status yet: connect once with policy v2 enabled') },
    async policyUpdate() { throw new Error('Connect first: manual update uses the session\'s SOCKS listener') },
    async policyResetFakeIp() { return 'Fake-IP storage cleared' },
  }
}
