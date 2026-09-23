<script>
  export let events = []
  export let onAll
</script>

<section class="panel">
  <div class="panel-head"><h2 class="panel-title">会话事件</h2><button class="inline-link" on:click={onAll}>全部日志 →</button></div>
  <div class="event-list">
    {#if events.length}
      {#each events.slice(-4) as event (event.id)}
        <div class="event {event.severity}"><time class="mono">{event.time}</time><span class="message mono">{event.message}</span></div>
      {/each}
    {:else}<div class="empty">暂无事件</div>{/if}
  </div>
</section>

<style>
  .event-list { padding: 5px 18px 6px; min-height: 74px; }
  .event { min-height: 23px; display: grid; grid-template-columns: 70px 1fr; align-items: center; gap: 0; font-size: 11px; animation: enter 160ms ease-out; }
  time { color: #607994; } .message { color: #cfd8e3; overflow-wrap: anywhere; } .event.success .message { color: #fff; font-weight: 650; } .event.error .message { color: var(--red); }
  @keyframes enter { from { opacity: 0; transform: translateY(-2px); } }
</style>
