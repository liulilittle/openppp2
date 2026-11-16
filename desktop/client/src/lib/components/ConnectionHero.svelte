<script>
  import { onDestroy, onMount } from 'svelte'
  import { parseRules, listRules } from '../policyRules.js'
  import { Power, ChevronRight, ShieldAlert } from 'lucide-svelte'
  import { connectionStates } from '../runtime/model.js'
  import { formatDuration } from '../format.js'
  import { t } from '../i18n.js'
  export let state
  export let runtime
  let now=Date.now(), error='', routing=null, routingBusy=false
  const tick=setInterval(() => now=Date.now(),1000)
  onDestroy(() => clearInterval(tick))
  $: connection=state.connection
  $: status=connectionStates[connection.status] || connectionStates.disconnected
  $: busy=!!connection.pid || ['starting','connecting','connected','reconnecting','stopping'].includes(connection.status)
  $: selected=connection.currentNodeId || state.subscription.nodes[0]?.id || ''
  $: tunMode=state.settings.connectionMode !== 'proxy'
  $: needsElevation=tunMode && runtime.kind !== 'demo' && !state.administrator
  const labels={connected:'Connected',connecting:'Connecting',starting:'Starting',reconnecting:'Reconnecting',stopping:'Stopping',disconnected:'Disconnected',recovery_pending:'Network recovery pending',error:'Connection failed'}
  const actions={connected:'Disconnect',connecting:'Cancel',starting:'Cancel',reconnecting:'Cancel',stopping:'Stopping',disconnected:'Connect',recovery_pending:'Restore network',error:'Retry'}
  const phases={preparing_host:['Preparing adapter','准备网卡'],handshaking:['Authenticating','认证中'],applying_policy:['Applying policy','应用网络策略'],connecting:['Connecting to server','连接服务器']}
  const modes=[['proxy','Proxy mode','代理模式','Sets the system proxy; no administrator rights','设置系统代理，无需管理员'],['client','Adapter mode','网卡模式','A virtual adapter carries all traffic; administrator required','虚拟网卡接管全部流量，需管理员']]
  async function act() { try { error=''; if(connection.status === 'recovery_pending') await runtime.retryRecovery(); else if(busy) await runtime.disconnect(); else await runtime.connect(selected) } catch(cause) { error=String(cause) } }
  async function mode(value) { try { error=''; await runtime.updateSetting('connectionMode',value) } catch(cause) { error=String(cause) } }
  onMount(async () => {
    try { const info=await runtime.policyLoad(); routing={ enabled:!!info.enabled, exists:!!info.policy, rules:info.rules || '' } } catch { routing=null }
  })
  async function toggleRouting(event) {
    const checkbox=event.currentTarget
    const wanted=checkbox.checked
    routingBusy=true; error=''
    try { routing={ ...routing, enabled:await runtime.policySetEnabled(wanted) } } catch(cause) { error=String(cause) } finally { routingBusy=false }
    checkbox.checked=!!routing?.enabled
  }
  const actionWords={ direct:['direct','直连'], proxy:['through the tunnel','走代理'], reject:['refused','拒绝'] }
  // One line that says what the policy does, e.g. "Direct all" or "6 rules · rest through the tunnel".
  function routingSummary(value) {
    if(!value?.exists) return $t('No policy yet — everything except the bypass list uses the tunnel','未创建策略 · 除直连列表外全部走代理')
    if(!value.enabled) return $t('Policy off — legacy bypass list in use','策略未启用 · 使用传统直连列表')
    const model=parseRules(value.rules), active=listRules(model).filter((rule) => rule.enabled)
    const rest=$t(...(actionWords[model.defaultAction] || [model.defaultAction,model.defaultAction]))
    if(!active.length) return $t(`Everything ${rest}`,`全部${rest}`)
    return $t(`${active.length} rules · everything else ${rest}`,`${active.length} 条规则 · 其余${rest}`)
  }
  async function elevate() { if(confirm($t('Restart as administrator?','以管理员身份重启？'))) { try { await runtime.elevate() } catch(cause) { error=String(cause) } } }
</script>

<div class="page-heading"><h1>{$t('Connection','连接')}</h1></div>
<section class="hero" aria-label={$t('Connection control','连接控制')}>
  <div class="card power-card">
    <button class={`power ${status.tone}`} disabled={connection.status === 'stopping' || (!busy && connection.status !== 'recovery_pending' && !selected)} on:click={act} aria-label={$t(actions[connection.status] || 'Connect',status.action)}>
      <Power size={38} strokeWidth={2}/>
      <span>{$t(actions[connection.status] || 'Connect',status.action)}</span>
    </button>
    <h2 class={`state ${status.tone}`}><i></i>{$t(labels[connection.status] || 'Disconnected',status.label)}</h2>
    <div class="meta">
      {#if connection.status === 'connected'}<span>{$t('Online','在线')} {formatDuration(connection.connectedAt,now)}</span>{/if}
      {#if phases[connection.phase]}<span>{$t(...phases[connection.phase])}</span>{/if}
      {#if busy && !connection.statsAvailable}<span>{$t('Waiting for kernel statistics','等待内核统计')}</span>{/if}
      {#if connection.statsStale}<span class="warning">{$t('Statistics stale','统计已过期')}</span>{/if}
      {#if connection.status === 'recovery_pending'}<span class="warning">{$t('Network changes require recovery before reconnecting','网络状态仍待恢复，完成前不能重新连接')}</span>{:else if !busy && connection.status !== 'error'}<span>{$t('Choose a node and access mode, then connect','选择节点和接入方式后连接')}</span>{/if}
    </div>
  </div>

  <div class="card setup-card">
    <label class="field"><span class="label">{$t('Node','节点')}</span>
      <select class="select-input" value={selected} disabled={busy} on:change={(event) => runtime.selectNode(event.currentTarget.value)}>
        {#if !state.subscription.nodes.length}<option value="">{$t('No nodes','暂无节点')}</option>{/if}
        {#each state.subscription.nodes as node}<option value={node.id}>{node.name}</option>{/each}
      </select>
    </label>
    <div class="field">
      <span class="label" id="access-mode">{$t('Access mode','接入方式')}</span>
      <div class="choice-grid modes" role="radiogroup" aria-labelledby="access-mode">
        {#each modes as [value,en,zh,enHint,zhHint]}
          {@const active=(state.settings.connectionMode === 'proxy') === (value === 'proxy')}
          <button class="choice" role="radio" aria-checked={active} disabled={busy} on:click={() => mode(value)}><strong>{$t(en,zh)}</strong><small>{$t(enHint,zhHint)}</small></button>
        {/each}
      </div>
      {#if needsElevation}<div class="elevate"><ShieldAlert size={15}/><span>{$t('Adapter mode needs administrator rights.','网卡模式需要管理员权限。')}</span><button class="inline-link accent" disabled={busy} on:click={elevate}>{$t('Restart as administrator','以管理员身份重启')}</button></div>{/if}
    </div>
    <div class="routing-link">
      <button class="routing-open" on:click={() => runtime.navigate('routing')}>
        <span><small>{$t('Routing','分流')}</small><span>{routing ? routingSummary(routing) : (state.policyEnabled ? $t('Routing policy in use','使用分流策略') : $t('Legacy routing (bypass list)','传统分流（直连列表）'))}</span></span>
        <span class="edit">{$t('Edit','编辑')}<ChevronRight size={15}/></span>
      </button>
      {#if routing?.exists}<input type="checkbox" role="switch" checked={routing.enabled} disabled={routingBusy} aria-label={$t('Use the routing policy','启用分流策略')} title={busy ? $t('Takes effect after reconnecting','重连后生效') : ''} on:change={toggleRouting}/>{/if}
    </div>
    {#if busy && routing?.exists}<small class="subtle hint">{$t('Routing changes take effect after reconnecting.','分流修改在重连后生效。')}</small>{/if}
  </div>
</section>
{#if error || connection.lastError}<div role="alert" class="error-line">{error || connection.lastError}</div>{/if}

<style>
  .hero { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }
  .power-card { padding:26px 20px; display:grid; justify-items:center; align-content:center; gap:14px; text-align:center; }
  .power { width:140px; height:140px; border-radius:50%; border:2px solid var(--text-3); background:var(--surface); color:var(--text-2); display:grid; place-items:center; align-content:center; gap:6px; cursor:pointer; font-weight:600; font-size:14px; }
  .power:hover:not(:disabled) { border-color:var(--accent); color:var(--accent); }
  .power.success { border-color:var(--accent); color:var(--accent); background:var(--accent-soft); }
  .power.warning { border-color:var(--yellow); color:var(--yellow); }
  .power.danger { border-color:var(--red); color:var(--red); }
  .state { margin:0; font-size:18px; display:flex; gap:10px; align-items:center; } .state i { width:9px; height:9px; border-radius:50%; background:var(--gray); }
  .state.success i { background:var(--green); } .state.warning i { background:var(--yellow); } .state.danger i { background:var(--red); }
  .meta { display:flex; flex-wrap:wrap; justify-content:center; gap:6px 14px; font-size:12px; color:var(--text-2); min-height:18px; }
  .setup-card { padding:20px; display:grid; gap:18px; align-content:start; }
  .label { font-size:12px; color:var(--text-2); }
  .modes { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .choice strong { font-size:14px; }
  .elevate { display:flex; flex-wrap:wrap; align-items:center; gap:8px; font-size:12px; color:var(--yellow); margin-top:4px; }
  .accent { color:var(--accent); } .accent:hover { color:var(--text); }
  .routing-link { display:flex; align-items:center; gap:12px; min-height:52px; padding:0 14px 0 0; border-radius:10px; border:1px solid var(--border-strong); background:var(--surface); color:var(--text); }
  .routing-open { flex:1; min-width:0; display:flex; align-items:center; justify-content:space-between; gap:12px; padding:8px 0 8px 14px; border:0; background:none; color:inherit; font:inherit; cursor:pointer; text-align:left; }
  .routing-open > span:first-child { display:grid; gap:2px; min-width:0; } .routing-link small { color:var(--text-2); font-size:12px; }
  .hint { margin-top:-10px; font-size:12px; }
  .routing-link .edit { display:inline-flex; align-items:center; gap:2px; color:var(--accent); font-size:13px; flex:none; }
  .routing-link:hover, .routing-link:focus-within { border-color:var(--accent); }
  @media(max-width:520px) { .modes { grid-template-columns:1fr; } }
</style>
