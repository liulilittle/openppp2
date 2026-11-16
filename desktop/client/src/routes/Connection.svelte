<script>
  import ConnectionHero from '../lib/components/ConnectionHero.svelte'
  import StatsPanel from '../lib/components/StatsPanel.svelte'
  import NodeTable from '../lib/components/NodeTable.svelte'
  import { t } from '../lib/i18n.js'
  export let state
  export let runtime
  $: favorites=state.subscription.nodes.filter((node) => node.favorite).slice(0,4)
  $: maximum=Math.max(1,...(state.history || []).flatMap((point) => [point.rx,point.tx]))
  $: historyStart=(state.history?.at(-1)?.time || Date.now())-60_000
  $: line=(key) => (state.history || []).map((point) => `${Math.max(0,point.time-historyStart)*600/60_000},${95-point[key]*85/maximum}`).join(' ')
</script>
<div class="page"><ConnectionHero {state} {runtime}/>{#if state.connection.statsAvailable}<StatsPanel stats={state.stats} stale={state.connection.statsStale}/>{/if}
  <section class="band"><div class="section-heading"><h2>{$t('Traffic','流量')}</h2><span>{$t('Last 60 seconds','最近 60 秒')}</span></div><svg viewBox="0 0 600 100" preserveAspectRatio="none" role="img" aria-label={$t('Download and upload traffic','下载及上传流量')}><line x1="0" x2="600" y1="95" y2="95" stroke="var(--border)"/><polyline points={line('rx')} fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke"/><polyline points={line('tx')} fill="none" stroke="var(--green)" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>{#if !state.history?.length}<span class="subtle">{$t('No traffic samples','暂无流量样本')}</span>{/if}</section>
  <section class="band"><div class="section-heading"><h2>{$t('Recent events','最近事件')}</h2><button class="inline-link" on:click={() => runtime.navigate('logs')}>{$t('All logs','全部日志')}</button></div>{#each state.events.slice(-3).reverse() as event}<div class="event-row"><time>{event.time}</time><span class:error-line={event.severity === 'error'}>{event.message}</span></div>{:else}<div class="empty">{$t('No events','暂无事件')}</div>{/each}</section>
  <section class="band"><div class="section-heading"><h2>{$t('Favorites','收藏节点')}</h2><button class="inline-link" on:click={() => runtime.navigate('nodes')}>{$t('All nodes','全部节点')}</button></div><NodeTable nodes={favorites} currentNodeId={state.connection.currentNodeId} {runtime}/></section>
</div>
<style>svg { display:block; width:100%; height:110px; margin:12px 0; } .event-row { display:grid; grid-template-columns:72px minmax(0,1fr); gap:14px; padding:8px 0; font-size:12px; } time { color:var(--text-3); } .event-row span { overflow-wrap:anywhere; }</style>
