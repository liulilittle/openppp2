<script>
  import { Download, Search, Trash2, Pause, Play, Copy } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  import { downloadText, redactText } from '../lib/security.js'
  export let state
  export let runtime
  let query='', severity='all', session='all', paused=false, frozen=[], error='', container
  $: events=(paused ? frozen : state.events).filter((event) => (severity === 'all' || event.severity === severity) && (session === 'all' || String(event.sessionId) === session) && event.message.toLowerCase().includes(query.toLowerCase()))
  $: sessions=[...new Set(state.events.map((event) => event.sessionId).filter((id) => id != null))]
  $: text=redactText(events.map((event) => `${event.time}\t${event.severity}\t${event.message}`).join('\n'),state.subscription.sources?.map((s) => s.url))
  $: if(!paused && container && events.length) requestAnimationFrame(() => { if(container) container.scrollTop=container.scrollHeight })
  function toggle() { if(!paused) frozen=structuredClone(state.events); paused=!paused }
  async function copy() { try { await navigator.clipboard.writeText(text) } catch(cause) { error=String(cause) } }
</script>
<div class="page"><div class="page-heading"><h1>{$t('Logs','日志')}</h1><div class="toolbar"><button class="icon-button" title={$t(paused ? 'Resume' : 'Pause',paused ? '继续' : '暂停')} aria-label={$t(paused ? 'Resume' : 'Pause',paused ? '继续' : '暂停')} on:click={toggle}>{#if paused}<Play size={16}/>{:else}<Pause size={16}/>{/if}</button><button class="icon-button" title={$t('Copy','复制')} aria-label={$t('Copy','复制')} on:click={copy}><Copy size={16}/></button><button class="icon-button" title={$t('Export','导出')} aria-label={$t('Export','导出')} on:click={() => downloadText('openppp2-client.log',text)}><Download size={16}/></button><button class="icon-button" title={$t('Clear','清空')} aria-label={$t('Clear','清空')} on:click={() => { runtime.clearEvents(); frozen=[] }}><Trash2 size={16}/></button></div></div>
  <div class="toolbar filters"><label class="search"><Search size={15}/><input class="text-input" bind:value={query} placeholder={$t('Search logs','搜索日志')} aria-label={$t('Search logs','搜索日志')}/></label><select class="select-input" bind:value={severity} aria-label={$t('Severity','级别')}><option value="all">{$t('All levels','全部级别')}</option><option value="info">{$t('Info','信息')}</option><option value="success">{$t('Success','成功')}</option><option value="error">{$t('Error','错误')}</option></select><select class="select-input" bind:value={session} aria-label={$t('Session','会话')}><option value="all">{$t('All sessions','全部会话')}</option>{#each sessions as id}<option value={String(id)}>#{id}</option>{/each}</select></div>
  {#if error}<div role="alert" class="error-line">{error}</div>{/if}<div class="log-list mono" bind:this={container}>{#each events as event (event.id)}<div class="log-row"><time>{event.time}</time><span>{event.severity}</span><code class:error-line={event.severity === 'error'}>{event.message}</code></div>{:else}<div class="empty">{$t('No matching logs','没有匹配的日志')}</div>{/each}</div>
</div>
<style>.filters .select-input { width:140px; } .search { display:flex; align-items:center; gap:8px; flex:1; min-width:180px; } .log-list { height:calc(100vh - 230px); min-height:260px; overflow:auto; padding:16px 0; border-top:1px solid var(--border); } .log-row { display:grid; grid-template-columns:72px 65px minmax(0,1fr); gap:12px; padding:7px 0; font-size:12px; } time, .log-row > span { color:var(--text-3); } code { overflow-wrap:anywhere; }</style>
