<script>
  import { onMount } from 'svelte'
  import { Save, RotateCcw, CheckCircle2, Plus, Trash2, Play, RefreshCw, Search, X } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  import {
    ACTIONS, RULE_TYPES, parseRules, serializeRules, listRules, addRule, removeRule,
    setRuleEnabled, setRuleAction, setDefaultAction, validateRule, summarize,
  } from '../lib/policyRules.js'
  import { PRESETS, applyOptions, readOptions, optionErrors } from '../lib/routingPresets.js'
  import QuickRouting from '../lib/components/QuickRouting.svelte'
  export let state
  export let runtime

  const actionNames={ direct:['Direct','直连'], proxy:['Proxy','代理'], reject:['Reject','拒绝'] }
  const typeNames={ suffix:['Domain suffix','域名后缀'], exact:['Exact domain','完整域名'], subdomain:['Subdomains','子域名'], keyword:['Keyword','关键词'], regexp:['Regex','正则'], cidr:['IPv4 range','IPv4 网段'], set:['Rule set','规则集'] }
  const typeHints={ suffix:['example.com — the domain and its subdomains','example.com — 该域名及其子域名'], exact:['api.example.com — this name only','api.example.com — 仅此域名'], subdomain:['example.com — subdomains only','example.com — 仅匹配子域名'], keyword:['google — name contains the text','google — 域名包含该文字'], regexp:['^cdn[0-9]+\\.example\\.com$','^cdn[0-9]+\\.example\\.com$'], cidr:['203.0.113.0/24','203.0.113.0/24'], set:['Name of a rule set below','下方规则集的名称'] }
  const errors={ empty:['Enter a value','请填写'], whitespace:['No spaces','不能包含空格'], 'domain-only':['Domain only — no scheme, port or path','只填域名，不要协议、端口或路径'], domain:['Not a valid domain','不是有效域名'], keyword:['Keyword cannot contain #','关键词不能包含 #'], regexp:['Invalid regular expression','正则表达式无效'], cidr:['Use a.b.c.d/n with n ≤ 32','格式应为 a.b.c.d/n，n 不超过 32'], set:['Use letters, digits, . _ -','只能用字母、数字和 . _ -'], 'set-unknown':['No rule set with this name','没有这个名称的规则集'] }
  const ruleSetFormats=['geoip-dat','geosite-dat','geoip-text','geosite-text']

  let loading=true, busy='', error='', message=''
  let info={ enabled:false, policyDir:'', kernelSupported:null, kernelError:'' }
  let saved={ policy:null, rules:'' }
  let policy=null, model=parseRules(''), view='list', textDraft='', rawPolicy=''
  let filter='all', query='', adding=false, draft={ type:'suffix', value:'', action:'direct' }
  // Quick options: a draft is kept only while it cannot be applied yet (a geo list without a source).
  let quickDraft=null, onboard={ ...PRESETS['proxy-all'], geositeSource:'', geoipSource:'' }
  let target='', network='tcp', port='', explanation=null
  let diagnostics=[], checkResult=null, migration=null, status=null, statusError=''
  let needsReconnect=false

  onMount(load)

  async function load() {
    loading=true; error=''
    try { info=await runtime.policyLoad(); saved={ policy:info.policy, rules:info.rules || '' }; setDraft(info.policy,info.rules || '') }
    catch(cause) { error=String(cause) }
    finally { loading=false }
  }
  function setDraft(nextPolicy,nextRules) {
    quickDraft=null
    policy=nextPolicy ? structuredClone(nextPolicy) : null
    model=parseRules(nextRules); textDraft=nextRules; view='list'
    rawPolicy=policy ? JSON.stringify(policy,null,2) : ''
    clearResults()
  }
  function clearResults() { message=''; diagnostics=[]; checkResult=null; explanation=null }
  function read(source,path,fallback) { return path.split('/').reduce((value,key) => value?.[key],source) ?? fallback }
  function setPath(path,value) {
    const next=structuredClone(policy || { version:2 }), keys=path.split('/')
    let node=next
    for(const key of keys.slice(0,-1)) { if(!node[key] || typeof node[key] !== 'object') node[key]={}; node=node[key] }
    if(value === undefined) delete node[keys.at(-1)]; else node[keys.at(-1)]=value
    policy=next; rawPolicy=JSON.stringify(policy,null,2); clearResults()
  }
  function applyRaw() {
    try { const value=JSON.parse(rawPolicy); if(!value || Array.isArray(value) || typeof value !== 'object') throw new Error($t('client.policy must be a JSON object','client.policy 必须是 JSON 对象')); policy=value; error=''; clearResults() }
    catch(cause) { error=String(cause) }
  }
  function updateModel(next) { model=next; clearResults() }
  function switchView(next) {
    if(next === view) return
    if(next === 'text') textDraft=serializeRules(model)
    else model=parseRules(textDraft)
    view=next
  }

  async function run(label,task) { busy=label; error=''; message=''; try { return await task() } catch(cause) { error=String(cause) } finally { busy='' } }
  function showReport(result) { checkResult=result; diagnostics=result?.report?.diagnostics || [] }
  async function check() { await run('check',async () => { const result=await runtime.policyCheck(policy,rulesText); showReport(result); if(result.exitCode === 0) message=$t('Check passed','检查通过') }) }
  async function save() {
    await run('save',async () => {
      const result=await runtime.policySave(policy,rulesText)
      showReport(result.result)
      if(result.result.exitCode !== 0) return
      const first=!saved.policy
      saved={ policy:structuredClone(policy), rules:rulesText }; model=parseRules(rulesText); textDraft=rulesText
      // The first saved policy is what the user just built; turn it on instead of
      // leaving connections silently on the legacy routing.
      if(first && !info.enabled) info={ ...info, enabled:await runtime.policySetEnabled(true) }
      needsReconnect=connected && info.enabled
      message=info.enabled ? $t('Saved; applies on next connection','已保存，下次连接生效') : $t('Saved, but the policy is off','已保存，但策略未启用')
    })
  }
  async function reconnect() {
    await run('reconnect',async () => { needsReconnect=false; await runtime.switchNode(state.connection.currentNodeId) })
  }
  async function saveAndReconnect() { await save(); if(needsReconnect && !error) await reconnect() }
  // Adds a rule for the tested target: a domain suffix (without a leading www.) or a /32.
  function ruleForTarget(action) {
    const value=target.trim().toLowerCase().replace(/\.$/,'')
    const ipv4=/^\d{1,3}(\.\d{1,3}){3}$/.test(value)
    const rule=ipv4 ? { type:'cidr', value:`${value}/32` } : { type:'suffix', value:value.replace(/^www\./,'') }
    const existing=rules.find((item) => item.type === rule.type && item.value === rule.value)
    updateModel(existing ? setRuleAction(model,existing.id,action) : addRule(model,{ action, ...rule }))
    message=$t(`Rule set: ${rule.value} → ${actionNames[action][0]}. Save to apply.`,`已设置 ${rule.value} → ${actionNames[action][1]}，保存后生效`)
  }
  function discard() { setDraft(saved.policy,saved.rules) }
  async function toggleEnabled(event) {
    const checkbox=event.currentTarget
    const wanted=checkbox.checked
    await run('enable',async () => { info={ ...info, enabled:await runtime.policySetEnabled(wanted) } })
    checkbox.checked=info.enabled
  }
  function changeQuick(next) {
    if(Object.keys(optionErrors(next)).length) { quickDraft=next; return }
    if(view === 'text') switchView('list')
    const result=applyOptions(model,policy,next)
    quickDraft=null; model=result.model; policy=result.policy; rawPolicy=JSON.stringify(policy,null,2); clearResults()
  }
  // Creates the policy from the base kernel template, then applies the chosen options.
  async function create() {
    if(Object.keys(optionErrors(onboard)).length) return
    await run('init',async () => {
      const result=await runtime.policyInit(onboard.defaultAction === 'direct' ? 'direct-all' : 'proxy-all','','')
      if(!result.policy) { showReport(result.result); return }
      const applied=applyOptions(parseRules(result.rules),result.policy,onboard)
      setDraft(applied.policy,serializeRules(applied.model)); message=$t('Policy drafted; review the rules and save','策略已生成，检查规则后保存')
    })
  }
  async function migrate() { await run('migrate',async () => { migration=await runtime.policyMigrate(); diagnostics=migration.result.report.diagnostics || [] }) }
  function adoptMigration() {
    if(policy && dirty && !confirm($t('Replace the current draft?','替换当前草稿？'))) return
    setDraft(migration.policy,migration.rules); migration=null; message=$t('Draft loaded; review the differences before saving','草稿已载入，保存前请核对差异')
  }
  async function explain() {
    await run('explain',async () => { explanation=await runtime.policyExplain(policy,rulesText,target.trim(),network,Number(port) || null); diagnostics=explanation.report.diagnostics || [] })
  }
  async function refreshStatus() { statusError=''; await run('status',async () => { try { status=(await runtime.policyStatus()).report } catch(cause) { status=null; statusError=String(cause) } }) }
  async function updateNow() { await run('update',async () => { const result=await runtime.policyUpdate(); diagnostics=result.report.diagnostics || []; await refreshStatus() }) }

  function openAdd() { adding=true; draft={ type:'suffix', value:'', action:filter === 'all' ? 'direct' : filter } }
  function commitAdd() {
    if(draftError) return
    updateModel(addRule(model,{ action:draft.action, type:draft.type, value:draft.value.trim() }))
    draft={ ...draft, value:'' }
  }
  function cycle(rule) { updateModel(setRuleAction(model,rule.id,ACTIONS[(ACTIONS.indexOf(rule.action)+1) % ACTIONS.length])) }

  function addRuleSet() { const sets=read(policy,'rule-sets',{}) || {}; let n=Object.keys(sets).length + 1; while(sets[`set${n}`]) n+=1; setPath(`rule-sets/set${n}`,{ format:'geoip-dat', tag:'cn', source:{ path:'' } }) }
  function renameRuleSet(from,to) {
    to=to.trim(); if(!to || to === from) return
    const sets=read(policy,'rule-sets',{}) || {}; if(sets[to]) return
    setPath('rule-sets',Object.fromEntries(Object.entries(sets).map(([key,value]) => [key === from ? to : key,value])))
  }
  function time(ms) { return ms > 0 ? new Date(ms).toLocaleString() : '—' }

  $: rulesText=view === 'text' ? textDraft : serializeRules(model)
  $: dirty=JSON.stringify(policy) !== JSON.stringify(saved.policy) || rulesText !== saved.rules
  $: unsupported=info.kernelSupported === false || (info.kernelSupported === null && !!info.kernelError)
  $: ruleSets=Object.entries(read(policy,'rule-sets',{}) || {})
  $: ruleSetNames=ruleSets.map(([name]) => name)
  // Stable display order: changing a rule's action moves it to another section in
  // the file, but the row keeps its place on screen (ids grow in creation order).
  $: rules=listRules(model).slice().sort((a,b) => Number(a.id.slice(1)) - Number(b.id.slice(1)))
  $: counts=summarize(model)
  $: shown=rules.filter((rule) => (filter === 'all' || rule.action === filter) && (!query.trim() || rule.value.toLowerCase().includes(query.trim().toLowerCase())))
  $: draftError=validateRule(draft.type,draft.value,ruleSetNames)
  $: draftMessage=draft.value.trim() && draftError ? $t(...(errors[draftError] || ['Invalid','无效'])) : ''
  $: route=explanation?.report?.route
  $: dns=explanation?.report?.dns
  $: connected=state.connection.status === 'connected'
  $: quick=quickDraft || readOptions(view === 'text' ? parseRules(textDraft) : model,policy)
</script>

<div class="page">
  <div class="page-heading">
    <div><h1>{$t('Routing','分流')}</h1><p class="page-lead">{$t('Decides which traffic goes direct, through the tunnel, or is refused. Changes apply on the next connection.','决定哪些流量直连、经隧道或被拒绝。修改在下次连接时生效。')}</p></div>
    {#if policy}<div class="toolbar">
      <span class="subtle">{busy ? $t('Working…','处理中…') : dirty ? $t('Unsaved changes','未保存') : message}</span>
      <button class="icon-button" title={$t('Discard changes','放弃修改')} aria-label={$t('Discard changes','放弃修改')} disabled={!dirty || !!busy} on:click={discard}><RotateCcw size={16}/></button>
      <button class="secondary-button action" disabled={!!busy || unsupported} on:click={check}><CheckCircle2 size={16}/>{$t('Check','检查')}</button>
      <button class="primary-button action" disabled={!dirty || !!busy || unsupported} on:click={save}><Save size={16}/>{$t('Save','保存')}</button>
    </div>{/if}
  </div>

  {#if unsupported}<div class="notice" role="alert">{info.kernelError || $t('The selected kernel does not support routing policies (requires 2.1.7 or later).','所选内核不支持分流策略（需要 2.1.7 或更高版本）。')}</div>{/if}
  {#if error}<div class="error-line" role="alert">{error}</div>{/if}

  {#if loading}
    <div class="empty">{$t('Loading…','加载中…')}</div>
  {:else if !policy}
    <section class="card">
      <div class="card-head"><h2>{$t('Create a routing policy','创建分流策略')}</h2></div>
      <div class="card-body stack">
        <p class="subtle">{$t('Choose a preset or set each option. Until a policy is enabled, connections use the legacy bypass list in Settings › Advanced.','选一个预设，或逐项设置。启用策略之前，连接使用 设置 › 高级 中的传统直连列表。')}</p>
        <QuickRouting options={onboard} disabled={!!busy || unsupported} on:change={(e) => onboard=e.detail}/>
        <div><button class="primary-button action" disabled={!!busy || unsupported || !!Object.keys(optionErrors(onboard)).length} on:click={create}>{$t('Create policy','创建策略')}</button></div>
      </div>
    </section>
    <section class="card">
      <div class="card-head"><h2>{$t('Or migrate the legacy settings','或迁移传统分流设置')}</h2><button class="secondary-button action" disabled={!!busy || unsupported} on:click={migrate}><RefreshCw size={15}/>{$t('Create draft','生成草稿')}</button></div>
      <div class="card-body stack">
        <p class="subtle">{$t('Converts the bypass list, DNS rules and base configuration into a policy draft. Nothing changes until you save.','把直连列表、DNS 规则与基础配置转换为策略草稿，保存前不会生效。')}</p>
        {#if migration}
          {@const report=migration.result.report.migration || {}}
          <div class={migration.result.exitCode === 0 ? 'notice ok' : 'notice'}>{migration.result.exitCode === 0 ? $t('Routing is equivalent to the current settings.','分流结果与当前设置等价。') : migration.result.exitCode === 5 ? $t('The draft differs from the current settings; review each item before adopting it.','草稿与当前设置存在差异，采用前请逐项核对。') : $t('Migration failed.','迁移失败。')}</div>
          {#if report.diagnostics?.length}<ul class="diagnostics">{#each report.diagnostics as item}<li><code>{item.code}</code> {item.message}</li>{/each}</ul>{/if}
          {#if migration.policy}<button class="primary-button action start" on:click={adoptMigration}>{$t('Open draft in editor','在编辑器中打开草稿')}</button>{/if}
        {/if}
      </div>
    </section>
  {:else}
    <label class="card switch-row">
      <span><strong>{$t('Use this policy for all connections','对所有连接生效')}</strong><small class="subtle">{$t('Replaces node-provided policies and the legacy bypass list.','替代节点自带的策略和传统直连列表。')}</small></span>
      <input type="checkbox" role="switch" checked={info.enabled} disabled={!saved.policy || !!busy} on:change={toggleEnabled}/>
    </label>

    {#if saved.policy && !info.enabled}<div class="notice warn" role="alert">
      <span>{$t('This policy is off. Connections still use the legacy routing and send everything except the bypass list through the tunnel.','此策略未启用：连接仍按传统分流，除直连列表外全部经隧道。')}</span>
      <button class="primary-button" disabled={!!busy} on:click={() => run('enable',async () => { info={ ...info, enabled:await runtime.policySetEnabled(true) } })}>{$t('Turn on','启用')}</button>
    </div>{:else if info.enabled && connected && dirty}<div class="notice warn" role="note">
      <span>{$t('Connected: changes apply after saving and reconnecting.','当前已连接：修改需保存并重连后生效。')}</span>
      <button class="primary-button" disabled={!!busy || unsupported} on:click={saveAndReconnect}>{$t('Save and reconnect','保存并重连')}</button>
    </div>{:else if needsReconnect && connected}<div class="notice warn" role="note">
      <span>{$t('Saved. The current connection still uses the previous rules.','已保存。当前连接仍在使用旧规则。')}</span>
      <button class="primary-button" disabled={!!busy} on:click={reconnect}>{$t('Reconnect now','立即重连生效')}</button>
    </div>{/if}

    <section class="card" aria-label={$t('Quick settings','快速设置')}>
      <div class="card-head"><h2>{$t('Quick settings','快速设置')}</h2><span class="subtle">{$t('Each option is a rule in the list below','每个选项都对应下方列表中的规则')}</span></div>
      <div class="card-body"><QuickRouting options={quick} disabled={!!busy || unsupported} on:change={(e) => changeQuick(e.detail)}/></div>
    </section>

    <section class="card" aria-label={$t('Rules','规则')}>
      <div class="card-head">
        <h2>{$t('Rules','规则')} <span class="subtle count">{rules.length}</span></h2>
        <div class="toolbar">
          <div class="segmented compact" role="tablist" aria-label={$t('View','视图')}>
            <button role="tab" aria-selected={view === 'list'} class:active={view === 'list'} on:click={() => switchView('list')}>{$t('List','列表')}</button>
            <button role="tab" aria-selected={view === 'text'} class:active={view === 'text'} on:click={() => switchView('text')}>{$t('Text','文本')}</button>
          </div>
          {#if view === 'list'}<button class="secondary-button action" on:click={openAdd}><Plus size={15}/>{$t('Add rule','添加规则')}</button>{/if}
        </div>
      </div>

      {#if view === 'list'}
        <div class="filters">
          <div class="segmented compact" role="radiogroup" aria-label={$t('Filter by action','按动作筛选')}>
            <button role="radio" aria-checked={filter === 'all'} class:active={filter === 'all'} on:click={() => filter='all'}>{$t('All','全部')}</button>
            {#each ACTIONS as action}<button role="radio" aria-checked={filter === action} class:active={filter === action} on:click={() => filter=action}>{$t(...actionNames[action])} · {counts[action]}</button>{/each}
          </div>
          <label class="search"><Search size={15}/><input class="text-input" placeholder={$t('Search rules','搜索规则')} aria-label={$t('Search rules','搜索规则')} bind:value={query}/></label>
        </div>
        <p class="priority subtle">{$t('Matching follows precision, not list order: explicit rules before rule sets; exact domain › suffix › keyword › regex; the longest suffix or IPv4 prefix wins.','匹配看精确程度而不是列表顺序：明确写的规则优先于规则集；完整域名 › 后缀 › 关键词 › 正则；后缀和 IPv4 前缀越长越优先。')}</p>

        {#if adding}<form class="add-form" on:submit|preventDefault={commitAdd}>
          <label class="field"><span class="label">{$t('Match','匹配类型')}</span><select class="select-input" bind:value={draft.type}>{#each RULE_TYPES as type}<option value={type}>{$t(...typeNames[type])}</option>{/each}</select></label>
          <label class="field grow"><span class="label">{$t('Value','内容')}</span>
            {#if draft.type === 'set' && ruleSetNames.length}<select class="select-input mono" bind:value={draft.value}><option value="">{$t('Choose a rule set','选择规则集')}</option>{#each ruleSetNames as name}<option value={name}>{name}</option>{/each}</select>
            {:else}<input class="text-input mono" class:invalid={!!draftMessage} placeholder={$t(...typeHints[draft.type])} bind:value={draft.value} aria-invalid={!!draftMessage}/>{/if}
          </label>
          <div class="field"><span class="label" id="draft-action">{$t('Action','动作')}</span><div class="segmented compact" role="radiogroup" aria-labelledby="draft-action">{#each ACTIONS as action}<button type="button" role="radio" aria-checked={draft.action === action} class:active={draft.action === action} on:click={() => draft={ ...draft, action }}>{$t(...actionNames[action])}</button>{/each}</div></div>
          <div class="form-actions"><button class="primary-button action" disabled={!!draftError}>{$t('Add','添加')}</button><button type="button" class="icon-button" aria-label={$t('Close','关闭')} title={$t('Close','关闭')} on:click={() => adding=false}><X size={15}/></button></div>
          {#if draftMessage}<div class="error-line full" role="alert">{draftMessage}</div>{/if}
        </form>{/if}

        <div class="table-scroll">
          {#each shown as rule (rule.id)}
            <div class="rule-row" class:off={!rule.enabled}>
              <span class="badge">{$t(...typeNames[rule.type])}</span>
              <span class="value mono" title={rule.value}>{rule.value}{#if rule.note}<small class="subtle"> · {rule.note}</small>{/if}</span>
              <button class={`pill ${rule.action}`} title={$t('Click to change the action','点击切换动作')} aria-label={`${$t('Action','动作')}: ${$t(...actionNames[rule.action])}. ${$t('Click to change','点击切换')}`} on:click={() => cycle(rule)}>{$t(...actionNames[rule.action])}</button>
              <input type="checkbox" role="switch" checked={rule.enabled} aria-label={`${$t('Enabled','启用')}: ${rule.value}`} on:change={(event) => updateModel(setRuleEnabled(model,rule.id,event.currentTarget.checked))}/>
              <button class="icon-button" title={$t('Delete','删除')} aria-label={`${$t('Delete','删除')} ${rule.value}`} on:click={() => updateModel(removeRule(model,rule.id))}><Trash2 size={15}/></button>
            </div>
          {:else}
            <div class="empty small">{rules.length ? $t('No rules match the filter','没有符合筛选条件的规则') : $t('No rules yet: all traffic follows the default below.','还没有规则：全部流量按下面的「其余流量」处理。')}</div>
          {/each}
        </div>

        <div class="default-row">
          <span><strong>{$t('Everything else','其余流量')}</strong><small class="subtle">{$t('When no rule matches','没有命中任何规则时')}</small></span>
          <div class="segmented compact" role="radiogroup" aria-label={$t('Default action','其余流量动作')}>{#each ACTIONS as action}<button role="radio" aria-checked={model.defaultAction === action} class:active={model.defaultAction === action} on:click={() => updateModel(setDefaultAction(model,action))}>{$t(...actionNames[action])}</button>{/each}</div>
        </div>
      {:else}
        <div class="card-body stack">
          <textarea class="text-area mono rules-text" bind:value={textDraft} on:input={clearResults} spellcheck="false" aria-label={$t('Rules file','规则文件')}></textarea>
          <details><summary>{$t('Syntax','语法')}</summary><pre class="syntax">{`default proxy            # direct | proxy | reject
dns direct local          # resolver for direct names
dns proxy remote          # resolver for proxied names
[direct]
=exact.example            # exact host
example.com               # domain and subdomains
*.example.org             # subdomains only
keyword:ads               # host contains "ads"
regexp:^cdn[0-9]+\\.       # regular expression
10.0.0.0/8                # IPv4 CIDR
set:geoip-cn              # rule set declared below
# off: example.net        # rule switched off in the list view
[reject]
[dns:local]               # names resolved by a specific resolver`}</pre></details>
        </div>
      {/if}
    </section>

    <section class="card" aria-label={$t('Test an address','测试地址')}>
      <div class="card-head"><h2>{$t('Test an address','测试地址')}</h2><span class="subtle">{$t('Evaluates the unsaved draft offline with the kernel; no lookup or connection.','用内核离线评估当前草稿，不查询 DNS，也不建立连接。')}</span></div>
      <form class="card-body test-row" on:submit|preventDefault={explain}>
        <input class="text-input mono" placeholder={$t('Domain or IPv4, e.g. www.example.com','域名或 IPv4，如 www.example.com')} bind:value={target} aria-label={$t('Target','目标')}/>
        <select class="select-input" bind:value={network} aria-label={$t('Protocol','协议')}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
        <input class="text-input" type="number" min="1" max="65535" placeholder={$t('Port','端口')} bind:value={port} aria-label={$t('Port','端口')}/>
        <button class="primary-button action" disabled={!target.trim() || !!busy || unsupported}><Play size={15}/>{$t('Test','测试')}</button>
      </form>
      {#if route}<div class="card-body verdict" aria-live="polite">
        <div><span class="subtle">{$t('Route','路由')}</span><span class={`pill ${route.action}`}>{$t(...(actionNames[route.action] || [route.action,route.action]))}</span><small>{route.matched ? `${route.rule_id} · ${route.file}:${route.line}` : $t('No rule matched; default action','未命中规则，使用其余流量动作')}{route.needs_ip ? ` · ${$t('may change after IP resolution','解析 IP 后可能变化')}` : ''}</small></div>
        {#if !unsupported}<div class="quick-rule"><span class="subtle">{$t('Send this target','让它')}</span>{#each ACTIONS.filter((action) => action !== route.action) as action}<button class={`pill ${action}`} disabled={!!busy} on:click={() => ruleForTarget(action)}>{$t(...{ direct:['go direct','直连'], proxy:['use the tunnel','走代理'], reject:['be refused','拒绝'] }[action])}</button>{/each}</div>{/if}
        {#if dns?.applicable}<div><span class="subtle">DNS</span><strong>{dns.rejected ? $t('Refused','拒绝解析') : dns.resolver}</strong><small>{$t('via','经')} {({direct:$t('direct','直连'),proxy:$t('tunnel','隧道')})[dns.via] || dns.via} · {dns.rule_id}{dns.line ? ` · ${dns.file}:${dns.line}` : ''}</small></div>{/if}
      </div>{/if}
    </section>

    <section class="card" aria-label={$t('Rule sets','规则集')}>
      <div class="card-head"><h2>{$t('Rule sets','规则集')}</h2><button class="secondary-button action" on:click={addRuleSet}><Plus size={15}/>{$t('Add','添加')}</button></div>
      <div class="card-body stack">
        {#if !ruleSets.length}<p class="subtle">{$t('GeoIP / GeoSite lists. Add one, then use it in a rule of type "Rule set".','GeoIP / GeoSite 列表。添加后，在规则里选择「规则集」类型引用。')}</p>{/if}
        {#each ruleSets as [name,set] (name)}<div class="rule-set">
          <input class="text-input mono" aria-label={$t('Name','名称')} value={name} on:change={(e) => renameRuleSet(name,e.currentTarget.value)}/>
          <select class="select-input" aria-label={$t('Format','格式')} value={set.format} on:change={(e) => setPath(`rule-sets/${name}/format`,e.currentTarget.value)}>{#each ruleSetFormats as format}<option>{format}</option>{/each}</select>
          <input class="text-input mono" aria-label="Tag" placeholder="tag" value={set.tag || ''} on:change={(e) => setPath(`rule-sets/${name}/tag`,e.currentTarget.value.trim() || undefined)}/>
          <input class="text-input mono" aria-label={$t('Path or URL','路径或 URL')} placeholder={$t('Path relative to the policy folder, or https:// URL','相对策略目录的路径，或 https:// 地址')} value={set.source?.url || set.source?.path || ''} on:change={(e) => { const value=e.currentTarget.value.trim(); setPath(`rule-sets/${name}/source`,{ [/^https?:\/\//i.test(value) ? 'url' : 'path']:value }) }}/>
          <button class="icon-button" title={$t('Remove','删除')} aria-label={`${$t('Remove','删除')} ${name}`} on:click={() => setPath(`rule-sets/${name}`,undefined)}><Trash2 size={15}/></button>
        </div>{/each}
        {#if info.policyDir}<p class="subtle">{$t('Relative paths resolve under','相对路径按此目录解析：')} <code>{info.policyDir}</code></p>{/if}
      </div>
    </section>

    <details class="card">
      <summary class="card-head"><h2>{$t('Advanced','高级')}</h2></summary>
      <div class="card-body stack">
        <label class="switch-line"><span>{$t('Block IPv6','阻断 IPv6')}<small class="subtle">{$t('Prevents IPv6 leaks around the tunnel','防止 IPv6 绕过隧道泄漏')}</small></span><input type="checkbox" role="switch" checked={read(policy,'ipv6','') === 'block'} on:change={(e) => setPath('ipv6',e.currentTarget.checked ? 'block' : undefined)}/></label>
        <label class="switch-line"><span>{$t('TCP domain sniffing','TCP 域名嗅探')}<small class="subtle">{$t('Adapter mode only: match HTTPS/HTTP by SNI/Host','仅网卡模式：按 SNI/Host 匹配域名')}</small></span><input type="checkbox" role="switch" checked={!!read(policy,'tcp-domain-sniff',false)} on:change={(e) => setPath('tcp-domain-sniff',e.currentTarget.checked)}/></label>
        <label class="switch-line"><span>{$t('Update remote rule sets while connected','连接期间自动更新远程规则集')}</span><input type="checkbox" role="switch" checked={!!read(policy,'updates/enabled',false)} on:change={(e) => setPath('updates/enabled',e.currentTarget.checked)}/></label>
        <div class="form-grid two">
          <label class="field"><span class="label">{$t('Update interval','更新间隔')}</span><input class="text-input mono" value={read(policy,'updates/interval','24h')} on:change={(e) => setPath('updates/interval',e.currentTarget.value.trim())}/></label>
          <label class="field"><span class="label">{$t('Download through','下载经由')}</span><select class="select-input" value={read(policy,'updates/via','proxy')} on:change={(e) => setPath('updates/via',e.currentTarget.value)}><option value="proxy">{$t('Tunnel','隧道')}</option><option value="direct">{$t('Direct','直连')}</option></select></label>
        </div>
        <details><summary>{$t('client.policy JSON','client.policy JSON')}</summary><textarea class="text-area mono spaced" bind:value={rawPolicy} on:change={applyRaw} spellcheck="false" aria-label="client.policy JSON"></textarea></details>
      </div>
    </details>

    <details class="card" on:toggle={(e) => { if(e.currentTarget.open && !status && !statusError) refreshStatus() }}>
      <summary class="card-head"><h2>{$t('Runtime status','运行状态')}</h2></summary>
      <div class="card-body stack">
        <div class="toolbar"><button class="secondary-button action" disabled={!!busy || unsupported} on:click={refreshStatus}><RefreshCw size={15}/>{$t('Refresh','刷新')}</button><button class="secondary-button action" disabled={!!busy || unsupported || !connected} title={connected ? '' : $t('Connect first','请先连接')} on:click={updateNow}>{$t('Update rule sets now','立即更新规则集')}</button></div>
        {#if statusError}<p class="subtle">{statusError}</p>{/if}
        {#if status}<dl class="status-grid">
          <dt>{$t('State','状态')}</dt><dd>{status.runtime_state}{status.reason ? ` · ${status.reason}` : ''}</dd>
          <dt>{$t('Active version','生效版本')}</dt><dd class="mono">{status.active_version ?? '—'}</dd>
          <dt>{$t('Prepared version','待生效版本')}</dt><dd class="mono">{status.prepared_version || '—'}{status.prepared_pending_commit ? ` · ${$t('applies on next connection','下次连接生效')}` : ''}</dd>
          <dt>{$t('Last update','上次更新')}</dt><dd>{time(status.last_attempt_ms)} · {status.last_result || '—'}</dd>
          <dt>{$t('Next attempt','下次尝试')}</dt><dd>{time(status.next_attempt_ms)}</dd>
          {#if status.last_diagnostic}<dt>{$t('Last error','最近错误')}</dt><dd class="warning">{status.last_diagnostic}</dd>{/if}
        </dl>{/if}
      </div>
    </details>
  {/if}

  {#if diagnostics.length}<section class="card" aria-live="polite"><div class="card-head"><h2>{$t('Diagnostics','诊断')}</h2></div><ul class="card-body diagnostics">{#each diagnostics as item}<li class:warning={item.severity === 'warning'}><code>{item.code}</code> {item.message}{#if item.source}<span class="subtle"> — {item.source}{item.line ? `:${item.line}` : ''}</span>{/if}</li>{/each}</ul></section>
  {:else if checkResult?.exitCode === 0}<p class="ok-line">{$t('Check passed','检查通过')} · {$t('rules','规则')} {checkResult.report.rule_count ?? '—'}</p>{/if}
</div>

<style>
  .page { gap:16px; }
  .stack { display:grid; gap:14px; } .stack > p { margin:0; }
  .label { font-size:12px; color:var(--text-2); }
  .count { font-weight:400; margin-left:4px; }
  .spaced { margin-top:12px; }
  .start { justify-self:start; }
  .switch-row { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:14px 18px; cursor:pointer; }
  .switch-row > span, .switch-line > span, .default-row > span { display:grid; gap:3px; }
  .switch-line { display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:48px; border-bottom:1px solid var(--border); }
  .segmented.compact { min-height:34px; } .segmented.compact button { padding:6px 12px; white-space:nowrap; }
  .filters { display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:space-between; padding:12px 18px 0; }
  .search { position:relative; display:flex; align-items:center; flex:0 1 240px; color:var(--text-3); } .search :global(svg) { position:absolute; left:10px; } .search input { padding-left:32px; }
  .priority { margin:10px 18px 4px; font-size:12px; line-height:1.5; }
  .add-form { display:flex; flex-wrap:wrap; gap:12px; align-items:end; margin:10px 18px; padding:14px; border-radius:10px; background:var(--surface); border:1px solid var(--border); }
  .add-form .field { flex:0 1 150px; } .add-form .grow { flex:1 1 240px; } .form-actions { display:flex; gap:6px; align-items:center; } .full { flex-basis:100%; padding:0; }
  .invalid { border-color:var(--reject); }
  .rule-row { display:grid; grid-template-columns:110px minmax(140px,1fr) 72px 40px 32px; gap:12px; align-items:center; min-width:460px; padding:8px 18px; border-bottom:1px solid var(--border); }
  .rule-row.off .value, .rule-row.off .badge { opacity:.5; }
  .rule-row .badge { justify-self:start; }
  .value { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .empty.small { min-height:72px; font-size:13px; }
  .default-row { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:12px; padding:14px 18px; background:var(--surface); border-radius:0 0 12px 12px; }
  .rules-text { min-height:320px; }
  .syntax { font-size:12px; color:var(--text-2); overflow:auto; }
  details > summary { cursor:pointer; color:var(--text-2); list-style-position:inside; }
  details.card > summary { color:var(--text); border-bottom:0; } details.card[open] > summary { border-bottom:1px solid var(--border); }
  details.card > summary h2 { display:inline; }
  .test-row { display:grid; grid-template-columns:minmax(0,1fr) 90px 110px auto; gap:8px; }
  .verdict { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:18px; padding-top:0; } .verdict div { display:grid; gap:6px; justify-items:start; } .verdict strong { font-size:18px; }
  .rule-set { display:grid; grid-template-columns:minmax(90px,1fr) 130px 80px minmax(160px,3fr) auto; gap:8px; }
  .diagnostics { margin:0; padding-left:34px; display:grid; gap:6px; font-size:13px; } code { overflow-wrap:anywhere; }
  .ok-line { color:var(--green); font-size:13px; margin:0; }
  .notice.ok { border-color:rgba(63,185,80,.35); background:rgba(63,185,80,.08); color:var(--text); }
  .verdict .quick-rule { display:flex; align-items:center; flex-wrap:wrap; gap:8px; grid-column:1 / -1; }
  .quick-rule .pill { cursor:pointer; }
  .status-grid { display:grid; grid-template-columns:max-content minmax(0,1fr); gap:8px 18px; margin:0; } .status-grid dt { color:var(--text-3); } .status-grid dd { margin:0; overflow-wrap:anywhere; }
  @media(max-width:760px) { .test-row, .rule-set { grid-template-columns:1fr; } .search { flex-basis:100%; } }
</style>
