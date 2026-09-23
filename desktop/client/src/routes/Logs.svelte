<script>
  import { Download, Search, Trash2 } from 'lucide-svelte'
  export let state
  export let runtime
  let query = ''
  let severity = 'all'
  $: events = state.events.filter((event) =>
    (severity === 'all' || event.severity === severity) && event.message.toLowerCase().includes(query.trim().toLowerCase()),
  )

  function exportLogs() {
    const text = events.map((event) => `${event.time}\t${event.severity}\t${event.message}`).join('\n')
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'openppp2-client.log'
    anchor.click()
    URL.revokeObjectURL(url)
  }
</script>

<div class="page">
  <section class="panel log-panel">
    <div class="panel-head"><h1 class="panel-title">日志</h1><div class="toolbar"><button class="icon-button" on:click={exportLogs} title="导出日志"><Download size={15} /></button><button class="icon-button" on:click={() => runtime.clearEvents()} title="清空日志"><Trash2 size={15} /></button></div></div>
    <div class="filters"><label><Search size={14} /><input bind:value={query} placeholder="搜索日志" /></label><select class="select-input" bind:value={severity}><option value="all">全部级别</option><option value="info">信息</option><option value="success">成功</option><option value="error">错误</option></select></div>
    <div class="log-list mono">
      {#if events.length}{#each events as event (event.id)}<div class="log-row {event.severity}"><time>{event.time}</time><span>{event.severity}</span><code>{event.message}</code></div>{/each}{:else}<div class="empty">没有匹配的日志</div>{/if}
    </div>
  </section>
</div>

<style>
  .log-panel { min-height: 520px; }
  .filters { display: flex; gap: 8px; padding: 10px 16px; border-bottom: 1px solid var(--border); }
  .filters label { max-width: 420px; flex: 1; display: flex; align-items: center; gap: 8px; padding: 0 10px; border: 1px solid var(--border-strong); border-radius: 7px; color: var(--text-3); background: #0d1014; }
  .filters input { width: 100%; height: 32px; border: 0; outline: 0; color: var(--text); background: transparent; }
  .filters select { width: 112px; padding-top: 0; padding-bottom: 0; }
  .log-list { padding: 8px 16px; font-size: 11px; }
  .log-row { min-height: 27px; display: grid; grid-template-columns: 72px 62px 1fr; align-items: center; gap: 10px; }
  .log-row time { color: #607994; }.log-row span { color: var(--text-3); }.log-row code { color: #cfd8e3; overflow-wrap: anywhere; }
  .log-row.error code { color: #f38f8a; }.log-row.success code { color: #fff; }
</style>
