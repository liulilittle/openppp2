<script>
  import { onMount } from 'svelte'
  import { Save, RotateCcw, Plus, X, Trash2 } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  import { effective, setPath as setIn, parseBase, DOMESTIC_DNS, FOREIGN_DNS, ENCRYPTED_DNS } from '../lib/overrides.js'
  export let state
  export let runtime

  const providerNames={ 'doh.pub':'DNSPod', alidns:['AliDNS','阿里 DNS'], '114':'114DNS', tuna:['TUNA','清华 TUNA'], baidu:['Baidu','百度'], '360':'360', cloudflare:'Cloudflare', google:'Google', quad9:'Quad9', adguard:'AdGuard', nextdns:'NextDNS', mullvad:'Mullvad' }
  const modes=[['auto','Auto','自动','Fake-IP in adapter mode, real resolution in proxy mode','网卡模式用 Fake-IP，代理模式用真实解析'],['real','Real IP','真实 IP','Answers carry real addresses','返回真实地址'],['fake-ip','Fake-IP','Fake-IP','Answers carry pool addresses mapped back to names; adapter mode only','返回地址池中的虚拟地址并映射回域名；仅网卡模式']]

  let loading=true, busy=false, error='', message='', needsReconnect=false
  let info={ enabled:false, policy:null, rules:'' }
  // Policy DNS draft (used when a routing policy is enabled).
  let policy=null, savedPolicy=null
  // Legacy DNS draft (network overrides; used without a policy).
  let overrides=structuredClone(state.networkOverrides || {})
  const base=parseBase(state.config)
  let newServer={}

  onMount(async () => {
    try { info=await runtime.policyLoad(); policy=info.policy ? structuredClone(info.policy) : null; savedPolicy=info.policy ? structuredClone(info.policy) : null }
    catch(cause) { error=String(cause) }
    finally { loading=false }
  })

  function label(name) {
    if(name && typeof name === 'object') return name.uri || JSON.stringify(name)
    const value=providerNames[name]
    return Array.isArray(value) ? $t(...value) : value || name
  }
  // Legacy helpers
  // Reactive so template calls re-run when the draft changes.
  $: get=(path,fallback) => effective(overrides,base,path,fallback)
  function set(path,value) { overrides=setIn(overrides,path,value); message=''; error='' }
  // Policy helpers
  $: pget=(path,fallback) => path.split('/').reduce((value,key) => value?.[key],policy) ?? fallback
  function pset(path,value) { const next=structuredClone(policy); const keys=path.split('/'); let node=next; for(const key of keys.slice(0,-1)) { if(!node[key] || typeof node[key] !== 'object') node[key]={}; node=node[key] } if(value === undefined) delete node[keys.at(-1)]; else node[keys.at(-1)]=value; policy=next; message=''; error='' }
  function addServer(name) { const value=(newServer[name] || '').trim(); if(!value) return; pset(`dns/resolvers/${name}/servers`,[...pget(`dns/resolvers/${name}/servers`,[]),value]); newServer={ ...newServer,[name]:'' } }
  function removeServer(name,index) { pset(`dns/resolvers/${name}/servers`,pget(`dns/resolvers/${name}/servers`,[]).filter((_,i) => i !== index)) }

  async function save() {
    busy=true; error=''; message=''
    try {
      if(policyMode) {
        const result=await runtime.policySave(policy,info.rules)
        if(result.result.exitCode !== 0) throw new Error((result.result.report.diagnostics || []).map((d) => `${d.code} ${d.message}`).join('\n') || $t('The kernel rejected the policy','内核拒绝了该策略'))
        savedPolicy=structuredClone(policy)
      } else {
        await runtime.updateNetwork(overrides)
      }
      needsReconnect=connected
      message=$t('Saved; applies on next connection','已保存，下次连接生效')
    } catch(cause) { error=String(cause) } finally { busy=false }
  }
  async function reconnect() {
    busy=true; error=''
    try { needsReconnect=false; await runtime.switchNode(state.connection.currentNodeId) } catch(cause) { error=String(cause) } finally { busy=false }
  }
  function reset() { if(policyMode) policy=structuredClone(savedPolicy); else overrides=structuredClone(state.networkOverrides || {}); message=''; error='' }
  async function resetFakeIp() {
    if(!confirm($t('Clear all Fake-IP mappings? Applications that cached old answers must be restarted.','清除全部 Fake-IP 映射？缓存了旧解析结果的应用需要重启。'))) return
    busy=true; try { message=await runtime.policyResetFakeIp() } catch(cause) { error=String(cause) } finally { busy=false }
  }

  $: policyMode=!loading && info.enabled && !!policy
  $: connected=state.connection.status === 'connected'
  // Fake-IP needs the adapter's DNS interception; proxy mode answers with real addresses.
  $: proxyMode=state.settings.connectionMode === 'proxy'
  $: dirty=policyMode ? JSON.stringify(policy) !== JSON.stringify(savedPolicy) : JSON.stringify(overrides) !== JSON.stringify(state.networkOverrides || {})
  $: resolvers=Object.entries(pget('dns/resolvers',{}) || {})
  $: bindings=Object.fromEntries([...String(info.rules || '').matchAll(/^\s*dns\s+(direct|proxy)\s+(\S+)/gm)].map((m) => [m[1],m[2]]))
  $: upstreams=[['dns/servers/domestic','Domestic upstream','国内上游','Resolves mainland names; queries leave directly','解析国内域名，直连发出',DOMESTIC_DNS,'doh.pub'],['dns/servers/foreign','Foreign upstream','国外上游','Resolves everything else through the tunnel','解析其余域名，经隧道发出',FOREIGN_DNS,'cloudflare']]
  $: legacyOptions=[
    ['udp/dns/cache','Cache answers','缓存解析结果','Repeat lookups are answered locally.','重复查询直接返回，减少延迟。',true,['udp/dns/ttl','Cache TTL (seconds)','缓存时间（秒）','number',60]],
    ['dns/tls/verify-peer','Verify TLS certificates','校验 TLS 证书','Checks the server certificate for DoH/DoT. Keep on.','加密 DNS（DoH/DoT）校验服务器证书，建议保持开启。',true,null],
    ['dns/ecs/enabled','EDNS client subnet (ECS)','EDNS 客户端子网（ECS）','Tells upstreams your egress subnet so CDNs answer nearby; reveals rough location.','把出口网段告诉上游，让 CDN 返回更近的地址；会暴露大致位置。',false,['dns/ecs/override-ip','ECS egress IP','ECS 出口 IP','text','']],
    ['dns/fake-ip/enabled','Fake-IP','Fake-IP','Answers with pool addresses and routes by name; a few apps that need real IPs may misbehave.','先返回虚拟地址再按域名分流，域名规则更准确；个别依赖真实 IP 的应用可能异常。',false,['dns/fake-ip/range','Address pool','地址池','text','198.18.0.1/16']],
  ]
</script>

<div class="page">
  <div class="page-heading">
    <div><h1>DNS</h1><p class="page-lead">{policyMode ? $t('A routing policy is enabled, so DNS follows its resolvers. Name-based rules live on the Routing page.','已启用分流策略，DNS 按策略中的解析器工作；按域名的规则在「分流」页设置。') : $t('Mainland names use the domestic upstream; the rest use the foreign one. Name-based routing lives on the Routing page.','国内域名用国内上游解析，其余走国外上游；按域名的分流在「分流」页设置。')}</p></div>
    <div class="toolbar"><span class="subtle">{busy ? $t('Working…','处理中…') : dirty ? $t('Unsaved changes','未保存') : message}</span>
      <button class="icon-button" title={$t('Discard changes','放弃修改')} aria-label={$t('Discard changes','放弃修改')} disabled={!dirty || busy} on:click={reset}><RotateCcw size={16}/></button>
      <button class="primary-button action" disabled={!dirty || busy || loading} on:click={save}><Save size={16}/>{$t('Save','保存')}</button></div>
  </div>
  {#if error}<div class="error-line" role="alert">{error}</div>{/if}
  {#if needsReconnect && connected}<div class="notice warn" role="note">
    <span>{$t('Saved. The current connection still uses the previous DNS settings.','已保存。当前连接仍在使用旧的 DNS 设置。')}</span>
    <button class="primary-button" disabled={busy} on:click={reconnect}>{$t('Reconnect now','立即重连生效')}</button>
  </div>{/if}

  {#if loading}<div class="empty">{$t('Loading…','加载中…')}</div>
  {:else if policyMode}
    <section class="card">
      <div class="card-head"><h2>{$t('Resolution mode','解析模式')}</h2></div>
      <div class="card-body stack">
        <div class="choice-grid" role="radiogroup" aria-label={$t('Resolution mode','解析模式')}>{#each modes as [value,en,zh,enHint,zhHint]}<button class="choice" role="radio" aria-checked={pget('dns/mode','auto') === value} disabled={proxyMode && value === 'fake-ip'} title={proxyMode && value === 'fake-ip' ? $t('Proxy mode cannot use Fake-IP','代理模式不能使用 Fake-IP') : ''} on:click={() => pset('dns/mode',value)}><strong>{$t(en,zh)}</strong><small>{$t(enHint,zhHint)}</small></button>{/each}</div>
        {#if proxyMode}<p class="subtle small">{pget('dns/mode','auto') === 'fake-ip' ? $t('Fake-IP needs adapter mode: switch to Auto or Real IP, or the connection check will fail.','Fake-IP 需要网卡模式：请改为「自动」或「真实 IP」，否则连接前检查会失败。') : $t('In proxy mode, Auto resolves real addresses; Fake-IP is for adapter mode only.','代理模式下「自动」等同于真实解析；Fake-IP 仅用于网卡模式。')}</p>{/if}
        {#if pget('dns/mode','auto') !== 'real'}<div class="inline-field">
          <label class="field"><span class="label">{$t('Fake-IP pool','Fake-IP 地址池')}</span><input class="text-input mono" value={pget('dns/fake-ip/range','198.18.0.0/16')} on:change={(e) => pset('dns/fake-ip/range',e.currentTarget.value.trim())}/></label>
          <button class="secondary-button action" disabled={busy || !!state.connection.pid} title={state.connection.pid ? $t('Disconnect first','请先断开连接') : ''} on:click={resetFakeIp}><Trash2 size={15}/>{$t('Reset Fake-IP','重置 Fake-IP')}</button>
        </div>
        <p class="subtle small">{$t('Changing the pool needs a reconnect and clearing DNS caches.','修改地址池后需重新连接并清理 DNS 缓存。')}</p>{/if}
      </div>
    </section>
    <section class="card">
      <div class="card-head"><h2>{$t('Resolvers','解析器')}</h2><span class="subtle">{$t('Direct traffic uses','直连流量使用')} <code>{bindings.direct || '—'}</code> · {$t('proxied traffic uses','代理流量使用')} <code>{bindings.proxy || '—'}</code></span></div>
      <div class="card-body stack">
        {#each resolvers as [name,resolver] (name)}<div class="resolver">
          <div class="resolver-head"><strong class="mono">{name}</strong>
            <div class="segmented compact" role="radiogroup" aria-label={`${name}: ${$t('egress','出口')}`}>{#each [['direct','Direct','直连'],['proxy','Tunnel','隧道']] as [via,en,zh]}<button role="radio" aria-checked={resolver.via === via} class:active={resolver.via === via} on:click={() => pset(`dns/resolvers/${name}/via`,via)}>{$t(en,zh)}</button>{/each}</div></div>
          <div class="servers">{#each resolver.servers || [] as server, index}<span class="server mono">{label(server)}<button class="chip-x" aria-label={`${$t('Remove','移除')} ${label(server)}`} on:click={() => removeServer(name,index)}><X size={13}/></button></span>{/each}</div>
          <form class="add-server" on:submit|preventDefault={() => addServer(name)}>
            <input class="text-input mono" list={`providers-${name}`} placeholder={$t('Provider name or DoH/DoT/UDP address','服务商名称或 DoH/DoT/UDP 地址')} aria-label={`${name}: ${$t('add server','添加服务器')}`} bind:value={newServer[name]}/>
            <datalist id={`providers-${name}`}>{#each ENCRYPTED_DNS as provider}<option value={provider}>{label(provider)}</option>{/each}</datalist>
            <button class="secondary-button action"><Plus size={15}/>{$t('Add','添加')}</button>
          </form>
        </div>{:else}<p class="subtle">{$t('The policy defines no resolvers.','策略中没有定义解析器。')}</p>{/each}
      </div>
    </section>
  {:else}
    {#if info.policy}<div class="notice" role="note">{$t('A routing policy exists but is off. Turn it on from the Routing page to use policy DNS.','已有分流策略但未启用。在「分流」页启用后改用策略 DNS。')}</div>{/if}
    <section class="upstreams" aria-label={$t('Upstream servers','上游服务器')}>
      {#each upstreams as [path,en,zh,enHint,zhHint,providers,fallback]}
        {@const current=get(path,fallback)}
        <div class="card"><div class="card-body stack">
          <div><h2 class="tight">{$t(en,zh)}</h2><small class="subtle">{$t(enHint,zhHint)}</small></div>
          <div class="chips" role="radiogroup" aria-label={$t(en,zh)}>{#each providers as provider}<button class="chip" role="radio" aria-checked={current === provider} class:active={current === provider} on:click={() => set(path,provider)}>{label(provider)}</button>{/each}</div>
          <label class="field"><span class="label">{$t('Or a custom address','或自定义地址')}</span><input class="text-input mono" placeholder="https://… / tls://… / udp://…" value={providers.includes(current) ? '' : current} on:change={(e) => set(path,e.currentTarget.value.trim() || fallback)}/></label>
        </div></div>
      {/each}
    </section>
    <section class="card" aria-label={$t('Resolution options','解析选项')}>
      {#each legacyOptions as [path,en,zh,enHint,zhHint,fallback,extra]}
        {@const on=!!get(path,fallback)}
        <div class="option">
          <label class="switch-line"><span><strong>{$t(en,zh)}</strong><small class="subtle">{$t(enHint,zhHint)}</small></span><input type="checkbox" role="switch" checked={on} on:change={(e) => set(path,e.currentTarget.checked)}/></label>
          {#if extra && on}<label class="field extra"><span class="label">{$t(extra[1],extra[2])}</span><input class="text-input mono" type={extra[3] === 'number' ? 'number' : 'text'} value={get(extra[0],extra[4])} on:change={(e) => set(extra[0],extra[3] === 'number' ? Number(e.currentTarget.value) : e.currentTarget.value.trim())}/></label>{/if}
        </div>
      {/each}
    </section>
  {/if}
</div>

<style>
  .page { gap:16px; }
  .stack { display:grid; gap:14px; } .tight { margin:0 0 2px; } .label { font-size:12px; color:var(--text-2); } .small { font-size:12px; margin:0; }
  .upstreams { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; }
  .chips, .servers { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { min-height:36px; padding:0 14px; border-radius:8px; border:1px solid var(--border-strong); background:var(--surface); color:var(--text); cursor:pointer; }
  .chip.active { border-color:var(--accent); background:var(--accent-soft); color:var(--accent); }
  .option { padding:4px 18px; border-bottom:1px solid var(--border); } .option:last-child { border-bottom:0; }
  .switch-line { display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:60px; cursor:pointer; } .switch-line > span { display:grid; gap:3px; }
  .extra { max-width:320px; padding-bottom:14px; }
  .inline-field { display:flex; flex-wrap:wrap; gap:12px; align-items:end; } .inline-field .field { flex:0 1 280px; }
  .resolver { display:grid; gap:10px; padding:14px; border:1px solid var(--border); border-radius:10px; background:var(--surface); }
  .resolver-head { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .segmented.compact { min-height:32px; } .segmented.compact button { padding:5px 12px; }
  .server { display:inline-flex; align-items:center; gap:4px; min-height:30px; padding:0 4px 0 10px; border-radius:7px; background:var(--surface-hover); font-size:12px; }
  .chip-x { display:inline-grid; place-items:center; width:24px; height:24px; border:0; border-radius:5px; background:transparent; color:var(--text-2); cursor:pointer; } .chip-x:hover { color:var(--text); background:var(--surface-raised); }
  .add-server { display:flex; gap:8px; } .add-server input { flex:1; min-width:0; }
  code { font-family:var(--mono); }
</style>
