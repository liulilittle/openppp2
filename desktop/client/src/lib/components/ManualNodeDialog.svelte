<script>
  import { Code2, Eye, EyeOff, Save, X } from 'lucide-svelte'

  export let node = null
  export let onClose = () => {}
  export let onSave = async () => {}

  const protocols = ['aes-128-cfb', 'aes-256-cfb', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305']
  const defaultConfig = {
    concurrent: 1,
    key: {
      kf: 154543927, kx: 128, kl: 10, kh: 12,
      protocol: 'aes-128-cfb', 'protocol-key': '',
      transport: 'aes-256-cfb', 'transport-key': '',
      masked: false, plaintext: false, 'delta-encode': false, 'shuffle-data': false,
    },
    client: {
      guid: '', server: 'ppp://127.0.0.1:20000/', bandwidth: 0,
      'http-proxy': { bind: '127.0.0.1', port: 8080 },
      'socks-proxy': { bind: '127.0.0.1', port: 1080 }, mappings: [],
    },
  }

  const initial = structuredClone(node?.config || defaultConfig)
  const endpoint = parseServer(initial.client?.server || '')
  let name = node?.name || ''
  let subtitle = node?.subtitle || ''
  let transportType = endpoint.transport
  let host = endpoint.host
  let port = endpoint.port
  let path = endpoint.path
  let guid = initial.client?.guid || ''
  let bandwidth = initial.client?.bandwidth ?? 0
  let concurrent = initial.concurrent ?? 1
  let protocol = initial.key?.protocol || 'aes-128-cfb'
  let protocolKey = initial.key?.['protocol-key'] || ''
  let transport = initial.key?.transport || 'aes-256-cfb'
  let transportKey = initial.key?.['transport-key'] || ''
  let kf = initial.key?.kf ?? 154543927
  let kx = initial.key?.kx ?? 128
  let kl = initial.key?.kl ?? 10
  let kh = initial.key?.kh ?? 12
  let masked = initial.key?.masked === true
  let plaintext = initial.key?.plaintext === true
  let deltaEncode = initial.key?.['delta-encode'] === true
  let shuffleData = initial.key?.['shuffle-data'] === true
  let httpBind = initial.client?.['http-proxy']?.bind || '127.0.0.1'
  let httpPort = initial.client?.['http-proxy']?.port ?? 8080
  let socksBind = initial.client?.['socks-proxy']?.bind || '127.0.0.1'
  let socksPort = initial.client?.['socks-proxy']?.port ?? 1080
  let showSecrets = false
  let rawMode = false
  let raw = JSON.stringify(initial, null, 2)
  let saving = false
  let error = ''

  function parseServer(server) {
    const match = server.match(/^ppp:\/\/(?:(ws|wss)\/)?(\[[^\]]+\]|[^/:]+)(?::(\d+))?(\/.*)?$/i)
    return {
      transport: match?.[1]?.toLowerCase() || 'tcp',
      host: match?.[2]?.replace(/^\[|\]$/g, '') || '',
      port: Number(match?.[3] || 20000),
      path: match?.[4] || '/',
    }
  }

  function positivePort(value, label) {
    const number = Number(value)
    if (!Number.isInteger(number) || number < 1 || number > 65535) throw new Error(`${label}必须在 1 到 65535 之间`)
    return number
  }

  function buildConfig() {
    if (!name.trim()) throw new Error('请输入节点名称')
    if (!host.trim()) throw new Error('请输入服务器 Host')
    if (!protocolKey.trim()) throw new Error('请输入 Protocol Key')
    const serverPort = positivePort(port, '服务器端口')
    const proxyHttpPort = positivePort(httpPort, 'HTTP 端口')
    const proxySocksPort = positivePort(socksPort, 'SOCKS 端口')
    const authority = host.includes(':') && !host.startsWith('[') ? `[${host.trim()}]` : host.trim()
    const suffix = transportType === 'tcp' ? '/' : `${path.startsWith('/') ? path : `/${path}`}`
    const server = `ppp://${transportType === 'tcp' ? '' : `${transportType}/`}${authority}:${serverPort}${suffix}`
    const config = structuredClone(initial)
    config.concurrent = Math.max(1, Number(concurrent) || 1)
    config.key = {
      ...(config.key || {}), protocol, 'protocol-key': protocolKey.trim(),
      transport, 'transport-key': transportKey.trim(),
      kf: Number(kf), kx: Number(kx), kl: Number(kl), kh: Number(kh),
      masked, plaintext, 'delta-encode': deltaEncode, 'shuffle-data': shuffleData,
    }
    config.client = {
      ...(config.client || {}), server, guid: guid.trim(), bandwidth: Number(bandwidth) || 0,
      'http-proxy': { bind: httpBind.trim() || '127.0.0.1', port: proxyHttpPort },
      'socks-proxy': { bind: socksBind.trim() || '127.0.0.1', port: proxySocksPort },
      mappings: [],
    }
    return config
  }

  function toggleRaw() {
    if (!rawMode) {
      try { raw = JSON.stringify(buildConfig(), null, 2); error = '' } catch (cause) { error = cause.message; return }
    }
    rawMode = !rawMode
  }

  async function save() {
    if (saving) return
    error = ''
    try {
      let config
      if (rawMode) {
        config = JSON.parse(raw)
        if (!config || Array.isArray(config) || typeof config !== 'object') throw new Error('高级 JSON 根节点必须是 object')
      } else {
        config = buildConfig()
      }
      saving = true
      await onSave({ id: node?.id || null, name: name.trim(), subtitle: subtitle.trim(), config, options: node?.options || {} })
    } catch (cause) {
      error = String(cause?.message || cause)
    } finally {
      saving = false
    }
  }
</script>

<div class="modal-backdrop" role="presentation" on:click|self={onClose}>
  <section class="node-dialog" role="dialog" aria-modal="true" aria-labelledby="node-dialog-title">
    <header class="dialog-head">
      <div><h2 id="node-dialog-title">{node ? '编辑手动节点' : '添加手动节点'}</h2><p>配置格式与移动端节点 Profile 对齐</p></div>
      <button class="icon-button" title="关闭" aria-label="关闭" on:click={onClose}><X size={16} /></button>
    </header>

    <div class="dialog-body">
      {#if !rawMode}
        <div class="form-section">
          <h3>基本信息</h3>
          <div class="form-grid two"><label class="field"><span>名称</span><input class="text-input" bind:value={name} placeholder="例如：东京自建节点" /></label><label class="field"><span>副标题</span><input class="text-input" bind:value={subtitle} placeholder="地区或用途，可选" /></label></div>
        </div>
        <div class="form-section">
          <h3>服务器</h3>
          <div class="form-grid server-grid">
            <label class="field"><span>传输</span><select class="select-input" bind:value={transportType}><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="wss">WebSocket TLS</option></select></label>
            <label class="field host"><span>Host</span><input class="text-input mono" bind:value={host} placeholder="server.example.com" /></label>
            <label class="field"><span>Port</span><input class="text-input number" type="number" min="1" max="65535" bind:value={port} /></label>
          </div>
          {#if transportType !== 'tcp'}<label class="field inline-field"><span>Path</span><input class="text-input mono" bind:value={path} placeholder="/tunnel" /></label>{/if}
          <div class="form-grid three"><label class="field"><span>GUID</span><input class="text-input mono" bind:value={guid} placeholder="可选" /></label><label class="field"><span>带宽 kbps</span><input class="text-input number" type="number" min="0" bind:value={bandwidth} /></label><label class="field"><span>并发连接</span><input class="text-input number" type="number" min="1" bind:value={concurrent} /></label></div>
        </div>
        <div class="form-section">
          <div class="section-title"><h3>加密</h3><button class="inline-link icon-text" on:click={() => (showSecrets = !showSecrets)}>{#if showSecrets}<EyeOff size={13} />隐藏密钥{:else}<Eye size={13} />显示密钥{/if}</button></div>
          <div class="form-grid two"><label class="field"><span>Protocol</span><select class="select-input" bind:value={protocol}>{#each protocols as item}<option value={item}>{item}</option>{/each}</select></label><label class="field"><span>Transport</span><select class="select-input" bind:value={transport}>{#each protocols as item}<option value={item}>{item}</option>{/each}</select></label></div>
          <div class="form-grid two"><label class="field"><span>Protocol Key</span>{#if showSecrets}<input class="text-input mono" type="text" bind:value={protocolKey} />{:else}<input class="text-input mono" type="password" bind:value={protocolKey} />{/if}</label><label class="field"><span>Transport Key</span>{#if showSecrets}<input class="text-input mono" type="text" bind:value={transportKey} />{:else}<input class="text-input mono" type="password" bind:value={transportKey} />{/if}</label></div>
          <div class="form-grid four"><label class="field"><span>KF</span><input class="text-input number" type="number" bind:value={kf} /></label><label class="field"><span>KX</span><input class="text-input number" type="number" bind:value={kx} /></label><label class="field"><span>KL</span><input class="text-input number" type="number" bind:value={kl} /></label><label class="field"><span>KH</span><input class="text-input number" type="number" bind:value={kh} /></label></div>
          <div class="switch-grid"><label><input type="checkbox" bind:checked={masked} /><span>Masked</span></label><label><input type="checkbox" bind:checked={plaintext} /><span>Plaintext</span></label><label><input type="checkbox" bind:checked={deltaEncode} /><span>Delta Encode</span></label><label><input type="checkbox" bind:checked={shuffleData} /><span>Shuffle Data</span></label></div>
        </div>
        <div class="form-section">
          <h3>本地代理</h3>
          <div class="proxy-row"><strong>HTTP</strong><input class="text-input mono" bind:value={httpBind} aria-label="HTTP Bind" /><input class="text-input number port" type="number" min="1" max="65535" bind:value={httpPort} aria-label="HTTP Port" /></div>
          <div class="proxy-row"><strong>SOCKS</strong><input class="text-input mono" bind:value={socksBind} aria-label="SOCKS Bind" /><input class="text-input number port" type="number" min="1" max="65535" bind:value={socksPort} aria-label="SOCKS Port" /></div>
        </div>
      {:else}
        <div class="raw-editor"><label class="field"><span>完整 appsettings JSON</span><textarea class="text-area" bind:value={raw} spellcheck="false"></textarea></label></div>
      {/if}
    </div>

    <footer class="dialog-actions">
      <button class="secondary-button icon-text" on:click={toggleRaw}><Code2 size={14} />{rawMode ? '返回表单' : '高级 JSON'}</button>
      <span class="dialog-error">{error}</span>
      <button class="secondary-button" on:click={onClose}>取消</button>
      <button class="primary-button icon-text" disabled={saving} on:click={save}><Save size={14} />{saving ? '保存中' : '保存节点'}</button>
    </footer>
  </section>
</div>

<style>
  .modal-backdrop { position: fixed; inset: 0; z-index: 50; display: grid; place-items: center; padding: 24px; background: rgba(0,0,0,.68); }
  .node-dialog { width: min(760px, 100%); max-height: min(760px, calc(100vh - 48px)); display: grid; grid-template-rows: auto minmax(0,1fr) auto; overflow: hidden; background: var(--surface); border: 1px solid var(--border-strong); border-radius: 8px; box-shadow: 0 24px 80px rgba(0,0,0,.45); }
  .dialog-head { min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 10px 16px 10px 18px; border-bottom: 1px solid var(--border); }
  h2, h3, p { margin: 0; } h2 { font-size: 14px; } .dialog-head p { margin-top: 4px; color: var(--text-3); font-size: 11px; }
  .dialog-body { min-height: 0; overflow-y: auto; }
  .form-section { padding: 15px 18px 16px; border-bottom: 1px solid var(--border); }
  .form-section h3 { margin-bottom: 12px; font-size: 12px; color: var(--text-2); }
  .section-title { display: flex; align-items: center; justify-content: space-between; }
  .form-grid { display: grid; gap: 10px; margin-top: 10px; } .form-grid:first-of-type { margin-top: 0; }
  .two { grid-template-columns: repeat(2, minmax(0,1fr)); } .three { grid-template-columns: 2fr 1fr 1fr; } .four { grid-template-columns: repeat(4, minmax(0,1fr)); }
  .server-grid { grid-template-columns: 130px minmax(0,1fr) 120px; } .inline-field { margin-top: 10px; }
  .field span { color: var(--text-3); font-size: 11px; }
  .switch-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 8px; margin-top: 12px; }
  .switch-grid label { min-height: 34px; display: flex; align-items: center; gap: 7px; color: var(--text-2); font-size: 11px; }
  .proxy-row { display: grid; grid-template-columns: 54px minmax(0,1fr) 110px; gap: 8px; align-items: center; margin-top: 8px; } .proxy-row strong { color: var(--text-3); font-size: 11px; }
  .raw-editor { padding: 16px 18px; } .raw-editor .text-area { min-height: 480px; }
  .dialog-actions { min-height: 58px; display: flex; align-items: center; gap: 8px; padding: 10px 16px; border-top: 1px solid var(--border); }
  .dialog-error { min-width: 0; flex: 1; color: var(--red); font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .icon-text { display: inline-flex; align-items: center; justify-content: center; gap: 7px; }
  button:disabled { opacity: .55; cursor: default; }
  @media (max-width: 640px) {
    .modal-backdrop { padding: 0; place-items: stretch; }
    .node-dialog { width: 100%; max-height: 100vh; border: 0; border-radius: 0; }
    .two, .three, .four, .server-grid { grid-template-columns: 1fr; }
    .switch-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
    .dialog-actions { flex-wrap: wrap; } .dialog-error { order: -1; flex-basis: 100%; }
  }
</style>
