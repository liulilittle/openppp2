<script>
  import { Pencil, Star, Trash2 } from 'lucide-svelte'
  import { latencyTone } from '../runtime/model.js'
  export let nodes = []
  export let currentNodeId = null
  export let runtime
  export let showFavorite = false
  export let onEdit = () => {}
  export let onDelete = () => {}
</script>

<div class="table-scroll">
  <table>
    <thead><tr>{#if showFavorite}<th class="fav"></th>{/if}<th>名称</th><th>副标题</th><th class="address">地址</th><th class="latency">延迟</th><th class="action"></th></tr></thead>
    <tbody>
      {#each nodes as node (node.id)}
        <tr class:current={node.id === currentNodeId}>
          {#if showFavorite}<td class="fav"><button class:active={node.favorite} class="favorite" on:click={() => runtime.toggleFavorite(node.id)} aria-label={node.favorite ? '取消收藏' : '收藏'}><Star size={14} fill={node.favorite ? 'currentColor' : 'none'} /></button></td>{/if}
          <td class="name-cell"><div class="node-name"><strong>{node.name}</strong>{#if node.source === 'manual'}<span class="source-badge">本地</span>{/if}</div></td><td class="muted">{node.subtitle}</td><td class="address mono">{node.address}</td><td class="latency number {latencyTone(node.latencyMs)}">{Number.isFinite(node.latencyMs) ? `${node.latencyMs} ms` : '未测试'}</td>
          <td class="action"><div class="row-actions">{#if node.source === 'manual'}<button class="mini-icon" title="编辑节点" aria-label="编辑节点" on:click={() => onEdit(node)}><Pencil size={13} /></button><button class="mini-icon danger-action" title="删除节点" aria-label="删除节点" on:click={() => onDelete(node)}><Trash2 size={13} /></button>{/if}{#if node.id === currentNodeId && currentNodeId}<span class="current-label">当前</span>{:else}<button class="row-button" on:click={() => runtime.switchNode(node.id)}>连接</button>{/if}</div></td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  th:nth-child(1), td:nth-child(1) { width: 18%; }
  .name-cell { width: 21%; }
  .address { width: 30%; color: #9fc9ef; }
  .latency { width: 12%; } .action { width: 146px; text-align: right; }
  tr.current { background: rgba(255,255,255,.025); box-shadow: inset 2px 0 var(--green); }
  .current-label { color: var(--text-2); font-size: 11px; }
  .good { color: #45d45b; } .warning { color: #e8a714; } .danger { color: #ff514b; } .muted { color: var(--text-3); }
  .fav { width: 38px !important; padding-right: 0; }
  .favorite { width: 24px; height: 24px; display: grid; place-items: center; border: 0; background: none; color: var(--text-3); padding: 0; cursor: pointer; }
  .favorite.active { color: #d9b14a; }
  .node-name { min-width: 0; display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
  .node-name strong { min-width: 0; overflow-wrap: anywhere; }
  .source-badge { flex: none; padding: 1px 5px; border: 1px solid rgba(63,185,80,.3); border-radius: 4px; color: #69d27a; font-size: 9px; font-weight: 600; }
  .row-actions { display: flex; align-items: center; justify-content: flex-end; gap: 5px; }
  .mini-icon { width: 26px; height: 26px; display: grid; place-items: center; padding: 0; border: 1px solid transparent; border-radius: 5px; background: transparent; color: var(--text-3); cursor: pointer; }
  .mini-icon:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface-hover); }
  .mini-icon.danger-action:hover { color: #ff7770; }
</style>
