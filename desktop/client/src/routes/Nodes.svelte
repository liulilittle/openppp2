<script>
  import { Plus, Search } from 'lucide-svelte'
  import ManualNodeDialog from '../lib/components/ManualNodeDialog.svelte'
  import NodeTable from '../lib/components/NodeTable.svelte'
  export let state
  export let runtime
  let query = ''
  let sort = 'latency'
  let editorOpen = false
  let editorNode = null
  let message = ''
  $: filtered = state.subscription.nodes
    .filter((node) => `${node.name} ${node.subtitle} ${node.address}`.toLowerCase().includes(query.trim().toLowerCase()))
    .toSorted((a, b) => sort === 'name' ? a.name.localeCompare(b.name, 'zh-CN') : (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity))

  function openEditor(node = null) { editorNode = node; editorOpen = true; message = '' }
  async function saveNode(node) { await runtime.saveManualNode(node); editorOpen = false; message = '节点已保存' }
  async function deleteNode(node) {
    if (!window.confirm(`删除手动节点“${node.name}”？`)) return
    try { await runtime.deleteManualNode(node.id); message = '节点已删除' } catch (error) { message = String(error) }
  }
</script>

<div class="page">
  <section class="panel">
    <div class="panel-head"><h1 class="panel-title">节点</h1><div class="head-actions"><span class="subtle">{filtered.length} 个节点</span><button class="primary-button add-button" on:click={() => openEditor()}><Plus size={14} />添加节点</button></div></div>
    <div class="toolbar-area">
      <label class="search"><Search size={14} /><input bind:value={query} placeholder="搜索名称、副标题或地址" aria-label="搜索节点" /></label>
      <select class="select-input" bind:value={sort} aria-label="节点排序"><option value="latency">按延迟</option><option value="name">按名称</option></select>
    </div>
    {#if message}<div class="status-line">{message}</div>{/if}
    <NodeTable nodes={filtered} currentNodeId={state.connection.currentNodeId} {runtime} showFavorite onEdit={openEditor} onDelete={deleteNode} />
  </section>
</div>

{#if editorOpen}<ManualNodeDialog node={editorNode} onClose={() => (editorOpen = false)} onSave={saveNode} />{/if}

<style>
  .toolbar-area { padding: 11px 16px; display: flex; gap: 8px; border-bottom: 1px solid var(--border); }
  .search { min-width: 220px; max-width: 420px; flex: 1; height: 34px; display: flex; align-items: center; gap: 8px; border: 1px solid var(--border-strong); border-radius: 7px; padding: 0 10px; background: #0d1014; color: var(--text-3); }
  .search input { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; color: var(--text); }
  .select-input { width: 112px; padding-top: 0; padding-bottom: 0; }
  .head-actions, .add-button { display: flex; align-items: center; gap: 9px; }
  .add-button { min-height: 30px; padding: 0 12px; font-size: 11px; }
  .status-line { padding: 8px 16px; border-bottom: 1px solid var(--border); color: #91b4d5; font-size: 11px; }
  @media (max-width: 560px) { .head-actions .subtle { display: none; } .toolbar-area { flex-wrap: wrap; } .search { min-width: 100%; } }
</style>
