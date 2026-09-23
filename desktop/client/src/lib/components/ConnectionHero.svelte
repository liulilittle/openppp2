<script>
  import { connectionStates } from '../runtime/model.js'
  import { formatDuration } from '../format.js'

  export let state
  export let runtime
  let now = Date.now()
  const tick = setInterval(() => (now = Date.now()), 1000)

  $: connection = state.connection
  $: status = connectionStates[connection.status]
  $: node = state.subscription.nodes.find((item) => item.id === connection.currentNodeId) || state.subscription.nodes[0]

  function act() {
    if (connection.status === 'connected') runtime.disconnect()
    else if (connection.status === 'connecting') runtime.cancel()
    else runtime.connect(node?.id)
  }

  import { onDestroy } from 'svelte'
  onDestroy(() => clearInterval(tick))
</script>

<section class="panel hero {status.tone}">
  <div class="details">
    <div class="status"><i></i><strong>{status.label}</strong>{#if connection.status === 'error'}<span>· 退出码 {connection.exitCode}</span>{/if}</div>
    <div class="node"><b>{node?.name || '未选择节点'}</b>{#if node}<span class="mono">{node.address}</span>{/if}</div>
    {#if connection.status === 'connected'}
      <div class="meta">{#if Number.isFinite(node?.latencyMs)}延迟 <span class="number">{node.latencyMs} ms</span>（直连参考）<span>·</span>{/if}已连接 <span class="number">{formatDuration(connection.connectedAt, now)}</span></div>
    {:else if connection.status === 'connecting'}
      <div class="meta">{node.name}<span>·</span>正在等待真实握手事件</div>
    {:else if connection.status === 'error'}
      <div class="meta error-copy">{connection.lastError || 'ppp 进程已异常退出'}</div>
    {:else}
      <div class="meta">{#if Number.isFinite(node?.latencyMs)}延迟 <span class="number">{node.latencyMs} ms</span>（直连参考）{:else}延迟未测试{/if}</div>
    {/if}
  </div>
  <button class="primary-button" on:click={act}>{status.action}</button>
</section>

<style>
  .hero { min-height: 114px; padding: 20px 22px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }
  .details { min-width: 0; }
  .status { display: flex; align-items: center; gap: 8px; }
  .status i { width: 9px; height: 9px; border-radius: 50%; background: var(--gray); transition: background-color 150ms ease; }
  .status strong { font-size: 18px; }
  .status span { color: var(--text-2); }
  .success .status i { background: var(--green); } .success .status strong { color: #f4fff7; }
  .warning .status i { background: var(--yellow); } .warning .status strong { color: #efd08a; }
  .danger .status i { background: var(--red); } .danger .status strong { color: #ff9894; }
  .node { margin-top: 10px; display: flex; gap: 9px; align-items: baseline; min-width: 0; }
  .node b { font-size: 13px; } .node span { color: #9fc9ef; font-size: 12px; overflow: hidden; text-overflow: ellipsis; }
  .meta { margin-top: 5px; color: #91b4d5; font-size: 12px; display: flex; gap: 7px; flex-wrap: wrap; }
  .error-copy { color: #ef8f8b; font-family: var(--mono); }
  @media (max-width: 560px) { .hero { align-items: stretch; flex-direction: column; } .primary-button { width: 100%; } }
</style>
