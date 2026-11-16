<script>
  import { FolderOpen, RefreshCw, ShieldCheck, Undo2, Download, Save, RotateCcw, Eye } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  import { downloadText, redactText } from '../lib/security.js'
  import { effective, setPath as setIn, parseBase, completeListeners } from '../lib/overrides.js'
  import Config from './Config.svelte'
  export let state
  export let runtime

  const tabs=[['general','General','常规'],['kernel','Kernel','内核'],['network','Network','网络'],['advanced','Advanced','高级']]
  const listeners=[['client/http-proxy/bind','HTTP bind','HTTP 监听地址','text','127.0.0.1'],['client/http-proxy/port','HTTP port','HTTP 端口','number',8080],['client/socks-proxy/bind','SOCKS bind','SOCKS 监听地址','text','127.0.0.1'],['client/socks-proxy/port','SOCKS port','SOCKS 端口','number',1080]]
  const p2pModes=[['relay','Relay through server','经服务器中转'],['direct-preferred','Prefer P2P direct','优先 P2P 直连']]
  const legacyRouting=[['client/routing/ip/bypass','Bypass IP/CIDR','直连 IP/CIDR','lines','One address or range per line; these never enter the tunnel.','每行一个地址或网段，这些流量不进隧道。'],['client/routing/dns/rules','DNS rules','DNS 规则','lines','One rule per line.','每行一条规则。'],['client/routing/ip/routes','Routes (JSON)','路由（JSON）','json','',''],['client/routing/ip/peer-routes','Peer prefix routes (JSON)','Peer 前缀路由（JSON）','json','Routes to other clients\' LAN prefixes.','到其他客户端局域网前缀的路由。']]

  let tab='general', error='', busy=false, message=''
  const base=parseBase(state.config)
  let overrides=structuredClone(state.networkOverrides || {}), raw=JSON.stringify(overrides,null,2), preview=null

  async function run(action) { busy=true; error=''; try { await action() } catch(cause) { error=String(cause) } finally { busy=false } }
  async function diagnostics() { const result=await runtime.preview(); downloadText('openppp2-diagnostics.json',redactText(JSON.stringify({kernel:state.kernel,connection:state.connection,preview:result,events:state.events},null,2))) }

  // Reactive so template calls re-run when the draft changes.
  $: get=(path,fallback) => effective(overrides,base,path,fallback)
  function set(path,value) { overrides=completeListeners(setIn(overrides,path,value),base); raw=JSON.stringify(overrides,null,2); message=''; error='' }
  function edit(path,type,value) {
    try { set(path,type === 'lines' ? value.split('\n').map((line) => line.trim()).filter(Boolean) : type === 'json' ? JSON.parse(value) : type === 'number' ? Number(value) : value) }
    catch(cause) { error=String(cause) }
  }
  $: display=(path,type) => { const value=get(path,type === 'lines' ? [] : type === 'json' ? [] : ''); return type === 'json' ? JSON.stringify(value,null,2) : Array.isArray(value) ? value.join('\n') : String(value) }
  function applyRaw() { try { overrides=JSON.parse(raw); error='' } catch(cause) { error=String(cause) } }
  async function saveOverrides() { await run(async () => { const value=JSON.parse(raw); await runtime.updateNetwork(value); overrides=value; message=$t('Saved; applies on next connection','已保存，下次连接生效') }) }
  function resetOverrides() { overrides=structuredClone(state.networkOverrides || {}); raw=JSON.stringify(overrides,null,2); message=''; error='' }
  async function inspect() { await run(async () => { preview=await runtime.preview() }) }

  $: dirty=raw !== JSON.stringify(state.networkOverrides || {},null,2)
  $: policyOwnsRouting=!!state.policyEnabled || !!base?.client?.policy
</script>

<div class="page">
  <div class="page-heading"><h1>{$t('Settings','设置')}</h1>
    {#if tab === 'network' || tab === 'advanced'}<div class="toolbar"><span class="subtle">{dirty ? $t('Unsaved network changes','网络设置未保存') : message}</span>
      <button class="icon-button" title={$t('Discard changes','放弃修改')} aria-label={$t('Discard changes','放弃修改')} disabled={!dirty || busy} on:click={resetOverrides}><RotateCcw size={16}/></button>
      <button class="primary-button action" disabled={!dirty || busy} on:click={saveOverrides}><Save size={16}/>{$t('Save','保存')}</button></div>{/if}
  </div>
  <div class="tabs" role="tablist" aria-label={$t('Settings sections','设置分区')}>{#each tabs as [id,en,zh]}<button role="tab" aria-selected={tab === id} class:active={tab === id} on:click={() => { applyRaw(); tab=id }}>{$t(en,zh)}</button>{/each}</div>
  {#if error}<div class="error-line" role="alert">{error}</div>{/if}

  {#if tab === 'general'}
    <section class="card"><div class="card-head"><h2>{$t('System','系统')}</h2></div><div class="card-body">
      {#each [['autostart','Start at sign-in','开机启动'],['closeToTray','Close to tray','关闭到托盘'],['autoSystemProxy','Set system proxy on connection','连接后设置系统代理']] as [key,en,zh]}<label class="setting-row"><span>{$t(en,zh)}</span><input type="checkbox" role="switch" checked={state.settings[key]} disabled={busy || (key === 'autoSystemProxy' && !!state.connection.pid)} on:change={(event) => run(() => runtime.updateSetting(key,event.currentTarget.checked))}/></label>{/each}
      <div class="setting-row"><span>{$t('System proxy recovery','系统代理恢复')}{#if state.proxyRecoveryPending} · <span class="warning">{$t('Pending','待处理')}</span>{/if}</span><button class="secondary-button action" disabled={busy} on:click={() => { if(confirm($t('Restore the saved system proxy settings?','恢复保存的系统代理设置？'))) run(() => runtime.restoreProxy(true)) }}><Undo2 size={16}/>{$t('Restore','恢复')}</button></div>
    </div></section>
    <section class="card"><div class="card-head"><h2>{$t('Appearance','外观')}</h2></div><div class="card-body">
      <label class="setting-row"><span>{$t('Theme','主题')}</span><select class="select-input" aria-label={$t('Theme','主题')} value={state.settings.appearance} on:change={(event) => run(() => runtime.updateSetting('appearance',event.currentTarget.value))}><option value="system">{$t('System','跟随系统')}</option><option value="light">{$t('Light','浅色')}</option><option value="dark">{$t('Dark','深色')}</option></select></label>
      <label class="setting-row"><span>{$t('Language','语言')}</span><select class="select-input" aria-label={$t('Language','语言')} value={state.settings.language} on:change={(event) => run(() => runtime.updateSetting('language',event.currentTarget.value))}><option>简体中文</option><option>English</option></select></label>
    </div></section>

  {:else if tab === 'kernel'}
    <section class="card"><div class="card-head"><h2>{$t('Kernel','内核')}</h2></div><div class="card-body">
      <div class="setting-row path"><label class="field grow"><span class="label">ppp.exe</span><input class="text-input mono" value={state.settings.pppPath} on:change={(event) => run(() => runtime.updateSetting('pppPath',event.currentTarget.value.trim()))}/></label><button class="icon-button" disabled={busy} title={$t('Browse','浏览')} aria-label={$t('Browse','浏览')} on:click={() => run(() => runtime.pickExecutable())}><FolderOpen size={17}/></button><button class="icon-button" disabled={busy} title={$t('Inspect kernel','检查内核')} aria-label={$t('Inspect kernel','检查内核')} on:click={() => run(() => runtime.inspectKernel())}><RefreshCw size={17}/></button></div>
      {#if state.settings.pppPath}<div class="setting-row"><span class="subtle">{$t('A custom kernel is selected. Clear it to use the ppp.exe shipped next to this client.','当前使用自定义内核路径。清空后将使用客户端同目录下自带的 ppp.exe。')}</span><button class="secondary-button action" disabled={busy || !!state.connection.pid} title={state.connection.pid ? $t('Disconnect first','请先断开连接') : ''} on:click={() => run(async () => { await runtime.updateSetting('pppPath',''); await runtime.inspectKernel() })}>{$t('Use bundled kernel','改用自带内核')}</button></div>{/if}
      {#if state.kernel}<div class="kernel-details"><span>{state.kernel.version}</span><span>{$t('Statistics','统计')}: {state.kernel.statsSupported ? '✓' : '—'}</span><span>Proxy: {state.kernel.proxySupported ? '✓' : '—'}</span></div>{:else}<p class="subtle">{$t('Without a path the client looks next to its own executable.','未设置路径时，在客户端程序所在目录查找。')}</p>{/if}
      <div class="setting-row"><span>{$t('Privileges','运行权限')}: {state.administrator ? $t('Administrator','管理员') : $t('Standard user','普通用户')}<small class="subtle block">{$t('Adapter mode needs administrator rights.','网卡模式需要管理员权限。')}</small></span><button class="secondary-button action" disabled={busy || !!state.connection.pid || state.administrator} on:click={() => { if(confirm($t('Restart as administrator?','以管理员身份重启？'))) run(() => runtime.elevate()) }}><ShieldCheck size={16}/>{$t('Restart as administrator','以管理员身份重启')}</button></div>
    </div></section>

  {:else if tab === 'network'}
    <section class="card"><div class="card-head"><h2>{$t('Local proxy listeners','本地代理监听')}</h2><span class="subtle">{$t('Used in proxy mode and by the system proxy','代理模式和系统代理使用')}</span></div>
      <div class="card-body form-grid two">{#each listeners as [path,en,zh,type,fallback]}<label class="field"><span class="label">{$t(en,zh)}</span><input class="text-input mono" type={type === 'number' ? 'number' : 'text'} min="1" max="65535" value={get(path,fallback)} on:change={(event) => edit(path,type,event.currentTarget.value)}/></label>{/each}</div></section>
    <section class="card"><div class="card-head"><h2>P2P</h2></div><div class="card-body">
      <label class="setting-row"><span>{$t('Enable P2P','启用 P2P')}<small class="subtle block">{$t('Lets clients of the same server reach each other.','允许同一服务器下的客户端互相访问。')}</small></span><input type="checkbox" role="switch" checked={get('p2p/enabled',true) !== false} on:change={(event) => set('p2p/enabled',event.currentTarget.checked)}/></label>
      <label class="setting-row"><span>{$t('Data path','数据路径')}</span><select class="select-input wide-select" value={get('p2p/mode','relay')} disabled={get('p2p/enabled',true) === false} on:change={(event) => set('p2p/mode',event.currentTarget.value)}>{#each p2pModes as [value,en,zh]}<option {value}>{$t(en,zh)}</option>{/each}</select></label>
      <label class="setting-row"><span>{$t('Join the virtual subnet in proxy mode','代理模式下接入虚拟子网')}<small class="subtle block">{$t('No adapter is created: the client joins inside its own process, and traffic to other clients through the local proxy goes P2P or via the server.','不创建网卡，在客户端进程内接入；经本地代理访问其他客户端，走 P2P 或经服务器中转。')}</small></span><input type="checkbox" role="switch" checked={state.launchOptions?.proxySubnet !== false} disabled={busy} on:change={(event) => run(() => runtime.updateLaunchOptions({...state.launchOptions,proxySubnet:event.currentTarget.checked}))}/></label>
      <label class="setting-row"><span>{$t('Proxy Internet in proxy mode','代理模式下代理上网')}<small class="subtle block">{$t('Off: the local proxy only reaches other clients and the system proxy is not set.','关闭后本地代理只能访问其他客户端，也不再设置系统代理。')}</small></span><input type="checkbox" role="switch" checked={state.launchOptions?.proxyInternet !== false} disabled={busy} on:change={(event) => run(() => runtime.updateLaunchOptions({...state.launchOptions,proxyInternet:event.currentTarget.checked}))}/></label>
      <label class="field"><span class="label">{$t('Ports open to other clients','开放给其他客户端的端口')}</span><input class="text-input mono" placeholder="22, 8080:3000" value={state.launchOptions?.proxyForwards || ''} disabled={busy || state.launchOptions?.proxySubnet === false} on:change={(event) => run(() => runtime.updateLaunchOptions({...state.launchOptions,proxyForwards:event.currentTarget.value.trim()}))}/><small class="subtle">{$t('TCP only. "8080:3000" forwards port 8080 of your virtual IP to 127.0.0.1:3000; unlisted ports stay closed.','仅 TCP。"8080:3000" 表示把本机虚拟 IP 的 8080 端口转发到 127.0.0.1:3000；未列出的端口一律拒绝。')}</small></label>
      <p class="subtle small">{$t('P2P direct on Windows has not been accepted on real NATs yet. The server must also allow direct-preferred; otherwise traffic stays on the relay.','Windows 上的 P2P 直连尚未经过真实 NAT 验收。服务器也需允许 direct-preferred，否则流量仍经服务器中转。')}</p>
    </div></section>
    <section class="card"><div class="card-body">{#if state.settings.connectionMode === 'proxy'}<p class="subtle small">{$t('In proxy mode, TUN IP, mask and gateway set the virtual-subnet address of this client; the other adapter options apply to adapter mode only.','代理模式下，TUN IP、子网掩码和网关决定本机在虚拟子网中的地址；其余选项只用于网卡模式。')}</p>{/if}<Config {state} {runtime} section="adapter"/></div></section>

  {:else}
    <section class="card"><div class="card-body"><Config {state} {runtime} section="advanced"/></div></section>
    <section class="card">
      <div class="card-head"><h2>{$t('Legacy routing','传统分流')}</h2><button class="inline-link accent" on:click={() => runtime.navigate('routing')}>{$t('Open Routing','前往分流页')}</button></div>
      <div class="card-body stack">
        <div class="notice" role="note">{policyOwnsRouting ? $t('A routing policy is in use; these settings do not apply.','正在使用分流策略，这里的设置不会生效。') : $t('Used only while no routing policy is enabled. The Routing page can migrate them into a policy.','仅在未启用分流策略时使用。可在「分流」页把它们迁移为策略。')}</div>
        <fieldset class="plain stack" disabled={policyOwnsRouting}>
          {#each legacyRouting as [path,en,zh,type,enHint,zhHint]}<label class="field"><span class="label">{$t(en,zh)}{#if enHint}<small class="subtle"> · {$t(enHint,zhHint)}</small>{/if}</span><textarea class="text-area short mono" value={display(path,type)} on:change={(event) => edit(path,type,event.currentTarget.value)} spellcheck="false"></textarea></label>{/each}
          <label class="field"><span class="label">GeoIP / GeoSite (JSON)</span><textarea class="text-area short mono" value={JSON.stringify(get('geo-rules',{}),null,2)} on:change={(event) => edit('geo-rules','json',event.currentTarget.value)} spellcheck="false"></textarea></label>
        </fieldset>
      </div>
    </section>
    <details class="card"><summary class="card-head"><h2>{$t('Network overrides JSON','网络覆盖 JSON')}</h2></summary><div class="card-body"><textarea class="text-area mono" bind:value={raw} on:change={applyRaw} on:input={() => error=''} spellcheck="false" aria-label={$t('Network overrides JSON','网络覆盖 JSON')}></textarea></div></details>
    <section class="card"><div class="card-head"><h2>{$t('Diagnostics','诊断')}</h2></div><div class="card-body stack">
      <div class="toolbar"><button class="secondary-button action" on:click={inspect}><Eye size={16}/>{$t('Preview saved configuration','预览已保存配置')}</button><button class="secondary-button action" on:click={() => run(() => runtime.openData())}><FolderOpen size={16}/>{$t('Open data directory','打开数据目录')}</button><button class="secondary-button action" on:click={() => run(diagnostics)}><Download size={16}/>{$t('Export diagnostics','导出诊断')}</button></div>
      {#if preview}<pre class="preview">{JSON.stringify(preview,null,2)}</pre>{/if}
    </div></section>
  {/if}
</div>

<style>
  .page { gap:16px; }
  .setting-row { display:flex; align-items:center; justify-content:space-between; gap:12px; min-height:56px; border-bottom:1px solid var(--border); }
  .setting-row:last-child { border:0; } .setting-row .select-input { width:160px; } .setting-row .wide-select { width:200px; }
  .setting-row.path { align-items:end; padding-bottom:12px; } .grow { flex:1; min-width:0; }
  .label { font-size:12px; color:var(--text-2); } .block { display:block; margin-top:3px; } .small { font-size:12px; margin:12px 0 0; }
  .kernel-details { display:flex; flex-wrap:wrap; gap:20px; padding:12px 0; color:var(--text-2); }
  .stack { display:grid; gap:14px; } .plain { border:0; margin:0; padding:0; min-width:0; } .short { min-height:120px; }
  .accent { color:var(--accent); }
  details.card > summary { cursor:pointer; list-style-position:inside; } details.card > summary h2 { display:inline; } details.card:not([open]) > summary { border-bottom:0; }
  .preview { overflow:auto; max-height:400px; padding:16px; margin:0; background:var(--surface); border-radius:8px; font-size:12px; }
  @media(max-width:760px) { .setting-row { flex-wrap:wrap; padding:12px 0; } }
</style>
