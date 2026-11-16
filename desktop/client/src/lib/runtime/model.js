export const connectionStates = Object.freeze({
  connected: { label: '已连接', action: '断开', tone: 'success' },
  connecting: { label: '连接中', action: '取消', tone: 'warning' },
  disconnected: { label: '未连接', action: '连接', tone: 'muted' },
  error: { label: '连接失败', action: '重新连接', tone: 'danger' },
  starting: { label: '启动中', action: '取消', tone: 'warning' },
  reconnecting: { label: '重连中', action: '取消', tone: 'warning' },
  stopping: { label: '停止中', action: '等待', tone: 'muted' },
  recovery_pending: { label: '网络恢复待处理', action: '恢复网络', tone: 'danger' },
})

export function latencyTone(latency) {
  if (!Number.isFinite(latency)) return 'muted'
  if (latency < 60) return 'good'
  if (latency < 120) return 'warning'
  return 'danger'
}

export function subscriptionNotice(subscription) {
  if (!subscription?.cached) return ''
  const minutes = Math.max(1, subscription.cacheAgeMinutes || 0)
  if (minutes < 60) return `正在使用 ${minutes} 分钟前的缓存`
  return `正在使用 ${Math.floor(minutes / 60)} 小时前的缓存`
}

export function createClientState() {
  return {
    route: 'connection',
    connection: {
      status: 'connected',
      currentNodeId: 'tokyo-01',
      connectedAt: Date.now() - 2 * 60 * 60 * 1000 - 14 * 60 * 1000 - 36 * 1000,
      exitCode: null,
      statsAvailable: true,
    },
    stats: {
      rxRateMbps: 12.4,
      txRateMbps: 2.1,
      rxBytes: 1.81 * 1024 ** 3,
      txBytes: 215.5 * 1024 ** 2,
      qualityPercent: 99.2,
      qualityGrade: '优',
      activeLinks: 4,
      requestedLinks: 4,
      effectivePath: 'direct',
      p2pState: 'direct',
      peers: [{ virtualIp: '10.8.0.7', state: 'direct', effectivePath: 'direct' }],
      tunIp: '10.8.0.2/24',
      gateway: '10.8.0.1',
      httpProxy: '127.0.0.1:1080',
      socksProxy: '127.0.0.1:1081',
    },
    events: [
      { id: 1, time: '19:03:07', message: 'tcp connected 47.102.41.18:32000', severity: 'info' },
      { id: 2, time: '19:03:09', message: 'exchanger connected', severity: 'success' },
      { id: 3, time: '19:03:11', message: 'session established role=main', severity: 'success' },
    ],
    subscription: {
      url: 'https://sub.example.com/sub/demo-client',
      name: '个人订阅',
      updatedAt: '2026-07-19T11:58:04Z',
      lastSyncedAt: '2026-07-19T12:00:04Z',
      cached: false,
      cacheAgeMinutes: 0,
      nodes: [
        { id: 'tokyo-01', name: '东京 01', subtitle: 'jp-tokyo-eq', address: '47.102.41.18:32000', latencyMs: 32, favorite: true, source: 'subscription', config: null, options: null },
        { id: 'osaka-02', name: '大阪 02', subtitle: 'jp-osaka-xt', address: '103.85.24.196:24000', latencyMs: 48, favorite: true, source: 'subscription', config: null, options: null },
        { id: 'singapore-01', name: '新加坡 01', subtitle: 'sg-sin-eq', address: '156.234.110.8:20000', latencyMs: 86, favorite: true, source: 'subscription', config: null, options: null },
        { id: 'los-angeles-03', name: '洛杉矶 03', subtitle: 'us-lax-tx', address: '45.88.190.66:28000', latencyMs: 138, favorite: false, source: 'subscription', config: null, options: null },
      ],
    },
    config: JSON.stringify({
      concurrent: 4,
      client: { guid: 'DEMO-CLIENT-GUID', server: 'ppp://47.102.41.18:32000/' },
    }, null, 2),
    launchOptions: {
      tunIp: '', tunMask: '', gateway: '', dns1: '8.8.8.8', dns2: '1.1.1.1',
      mux: 0, muxMode: 'compat', vnet: true, blockQuic: false, staticMode: false,
    },
    settings: {
      autostart: false,
      closeToTray: true,
      disconnectOnExit: true,
      language: '简体中文',
      appearance: '深色',
    },
  }
}

export function createEmptyClientState() {
  return {
    route: 'connection',
    connection: {
      status: 'disconnected', currentNodeId: null, connectedAt: null,
      exitCode: null, statsAvailable: false, pid: null, lastError: '', mode: 'client', sessionId: 0, phase: 'idle', statsStale: false, recoveryPending: false,
    },
    stats: {
      rxRateMbps: 0, txRateMbps: 0, rxBytes: 0, txBytes: 0,
      qualityPercent: 0, qualityGrade: '', activeLinks: 0,
      effectivePath: '', p2pState: '', peers: [], tcpStack: '', tunIp: '', gateway: '', httpProxy: '', socksProxy: '',
    },
    events: [],
    subscription: {
      url: '', name: '', updatedAt: null, lastSyncedAt: null,
      cached: false, cacheAgeMinutes: 0, nodes: [], sources: [],
    },
    config: '{}',
    launchOptions: {},
    networkOverrides: {}, history: [], kernel: null, administrator: false, proxyRecoveryPending: false, policyDir: '', policyEnabled: false,
    settings: {
      autostart: false, closeToTray: true, disconnectOnExit: true,
      language: '简体中文', appearance: 'system', connectionMode: 'client', pppPath: '', autoSystemProxy: true,
    },
  }
}
