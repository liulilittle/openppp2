<script>
  import { Check, RotateCcw, Save } from 'lucide-svelte'
  export let state
  export let runtime

  const defaults = {
    tunIp: '', tunMask: '', gateway: '', dns1: '', dns2: '',
    mux: 0, muxMode: 'compat', vnet: true, blockQuic: false, staticMode: false,
  }
  let draft = state.config
  let options = { ...defaults, ...(state.launchOptions || {}) }
  let message = ''
  let saving = false

  function validate() {
    try {
      const value = JSON.parse(draft)
      if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('JSON 根节点必须是 object')
      message = '配置格式有效'
    } catch (error) { message = String(error.message || error) }
  }

  async function save() {
    if (saving) return
    try {
      const value = JSON.parse(draft)
      if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('JSON 根节点必须是 object')
      saving = true
      options = await runtime.updateClientConfig(JSON.stringify(value, null, 2), { ...options })
      draft = JSON.stringify(value, null, 2)
      message = '配置已保存'
    } catch (error) { message = String(error.message || error) } finally { saving = false }
  }

  function reset() {
    draft = state.config
    options = { ...defaults, ...(state.launchOptions || {}) }
    message = '已恢复到上次保存内容'
  }
</script>

<div class="page">
  <section class="panel config-panel">
    <div class="panel-head"><h1 class="panel-title">启动参数</h1><div class="toolbar"><button class="secondary-button action" on:click={validate}><Check size={14} />校验</button><button class="secondary-button action" on:click={reset}><RotateCcw size={14} />恢复</button><button class="primary-button action" disabled={saving} on:click={save}><Save size={14} />{saving ? '保存中' : '保存'}</button></div></div>

    <div class="config-section">
      <h2>虚拟网卡</h2>
      <div class="config-grid three">
        <label class="field"><span>TUN IP</span><input class="text-input mono" bind:value={options.tunIp} placeholder="自动分配" /></label>
        <label class="field"><span>子网掩码</span><input class="text-input mono" bind:value={options.tunMask} placeholder="自动" /></label>
        <label class="field"><span>网关</span><input class="text-input mono" bind:value={options.gateway} placeholder="自动" /></label>
      </div>
    </div>

    <div class="config-section">
      <h2>DNS</h2>
      <div class="config-grid two">
        <label class="field"><span>首选 DNS</span><input class="text-input mono" bind:value={options.dns1} placeholder="8.8.8.8" /></label>
        <label class="field"><span>备用 DNS</span><input class="text-input mono" bind:value={options.dns2} placeholder="1.1.1.1" /></label>
      </div>
    </div>

    <div class="config-section">
      <h2>多路复用</h2>
      <div class="config-grid two compact-grid">
        <label class="field"><span>MUX 数量</span><input class="text-input number" type="number" min="0" max="65535" bind:value={options.mux} /></label>
        <label class="field"><span>MUX 模式</span><select class="select-input" bind:value={options.muxMode}><option value="compat">Compat</option><option value="flow">Flow</option><option value="balance">Balance</option><option value="stripe">Stripe（实验）</option></select></label>
      </div>
    </div>

    <div class="config-section policy-section">
      <h2>网络策略</h2>
      <div class="toggle-grid">
        <label class="toggle-row"><span>VNet</span><input type="checkbox" bind:checked={options.vnet} /></label>
        <label class="toggle-row"><span>Block QUIC</span><input type="checkbox" bind:checked={options.blockQuic} /></label>
        <label class="toggle-row"><span>Static Mode</span><input type="checkbox" bind:checked={options.staticMode} /></label>
      </div>
    </div>

    <details class="advanced-json">
      <summary>高级 appsettings JSON</summary>
      <div class="advanced-body"><label class="field"><span>原始 JSON</span><textarea class="text-area" bind:value={draft} spellcheck="false"></textarea></label></div>
    </details>

    {#if message}<div class="message mono">{message}</div>{/if}
  </section>
</div>

<style>
  .action { display: inline-flex; align-items: center; gap: 7px; }
  button:disabled { opacity: .55; cursor: default; }
  .config-section { padding: 15px 18px 17px; border-bottom: 1px solid var(--border); }
  h2 { margin: 0 0 12px; color: var(--text-2); font-size: 12px; font-weight: 650; }
  .config-grid { display: grid; gap: 10px; } .config-grid.two { grid-template-columns: repeat(2, minmax(0,1fr)); } .config-grid.three { grid-template-columns: repeat(3, minmax(0,1fr)); }
  .compact-grid { max-width: 560px; }
  .field span { color: var(--text-3); font-size: 11px; }
  .toggle-grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 8px; max-width: 660px; }
  .toggle-row { height: 38px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 0 11px; border: 1px solid var(--border); border-radius: 7px; color: var(--text-2); background: #0d1014; }
  .toggle-row input { accent-color: var(--green); }
  .advanced-json { border-bottom: 1px solid var(--border); }
  .advanced-json summary { min-height: 42px; display: flex; align-items: center; padding: 0 18px; color: var(--text-2); font-size: 12px; cursor: pointer; list-style: none; }
  .advanced-json summary::-webkit-details-marker { display: none; }
  .advanced-json summary::before { content: '›'; margin-right: 8px; color: var(--text-3); transition: transform .15s ease; }
  .advanced-json[open] summary::before { transform: rotate(90deg); }
  .advanced-body { padding: 0 18px 16px; } .advanced-body .text-area { min-height: 300px; }
  .message { padding: 10px 18px; color: #91b4d5; font-size: 11px; }
  @media (max-width: 680px) {
    .panel-head { align-items: flex-start; flex-direction: column; padding-top: 10px; padding-bottom: 10px; }
    .config-grid.two, .config-grid.three, .toggle-grid { grid-template-columns: 1fr; }
  }
</style>
