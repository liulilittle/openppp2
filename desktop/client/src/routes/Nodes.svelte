<script>
  import { Plus, Search, RefreshCw, Upload, Download, Star } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  import { downloadText } from '../lib/security.js'
  import ManualNodeDialog from '../lib/components/ManualNodeDialog.svelte'
  import NodeTable from '../lib/components/NodeTable.svelte'
  export let state
  export let runtime
  let query = ''
  let sort = 'latency'
  let editorOpen = false
  let editorNode = null
  let message = ''
  let source='all', favoritesOnly=false, busy=false
  $: filtered = state.subscription.nodes
    .filter((node) => `${node.name} ${node.subtitle} ${node.address}`.toLowerCase().includes(query.trim().toLowerCase()))
    .filter((node) => (source === 'all' || (node.sourceId || node.source) === source) && (!favoritesOnly || node.favorite))
    .toSorted((a, b) => sort === 'name' ? a.name.localeCompare(b.name, 'zh-CN') : (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity))

  function openEditor(node = null) { editorNode = node; editorOpen = true; message = '' }
  async function saveNode(node) { await runtime.saveManualNode(node); editorOpen = false; message = '节点已保存' }
  async function deleteNode(node) {
    if (!window.confirm(`${$t('Delete node','删除节点')} ${node.name}?`)) return
    try { await runtime.deleteManualNode(node.id); message = '节点已删除' } catch (error) { message = String(error) }
  }
  function duplicate(node) { if(!node.config) { message=$t('This compact subscription node has no full profile to duplicate','该精简订阅节点尚无完整配置可复制'); return } openEditor({...node,id:null,name:`${node.name} copy`,source:'manual'}) }
  async function probe() { busy=true; try { await runtime.probeNodes(filtered.map((node) => node.id)) } catch(cause) { message=String(cause) } finally { busy=false } }
  async function importNodes(event) { try { const file=event.currentTarget.files[0]; if(!file) return; if(file.size > 2*1024*1024) throw new Error('File exceeds 2 MiB'); const values=JSON.parse(await file.text()); if(!Array.isArray(values)) throw new Error('Expected a node array'); for(const node of values) await runtime.saveManualNode({...node,id:null}); message=$t('Imported','导入完成') } catch(cause) { message=String(cause) } finally { event.currentTarget.value='' } }
  function exportNodes() { if(!confirm($t('Export includes private keys. Continue?','导出包含私钥，继续？'))) return; downloadText('openppp2-nodes.json',JSON.stringify(state.subscription.nodes.filter((node) => node.source === 'manual').map(({name,subtitle,config,options}) => ({name,subtitle,config,options})),null,2),'application/json') }
</script>

<div class="page">
  <section class="panel">
    <div class="page-heading"><h1>{$t('Nodes','节点')}</h1><div class="head-actions"><span class="subtle">{filtered.length}</span><button class="primary-button add-button" on:click={() => openEditor()}><Plus size={14} />{$t('Add node','添加节点')}</button></div></div>
    <div class="toolbar-area">
      <label class="search"><Search size={14} /><input bind:value={query} placeholder={$t('Search nodes','搜索节点')} aria-label={$t('Search nodes','搜索节点')} /></label>
      <select class="select-input" bind:value={sort} aria-label={$t('Sort','排序')}><option value="latency">{$t('Latency','延迟')}</option><option value="name">{$t('Name','名称')}</option></select>
      <select class="select-input" bind:value={source} aria-label={$t('Source','来源')}><option value="all">{$t('All sources','全部来源')}</option><option value="manual">{$t('Local','本地')}</option>{#each state.subscription.sources || [] as item}<option value={item.id}>{item.name}</option>{/each}</select>
      <button class="icon-button" class:active={favoritesOnly} aria-pressed={favoritesOnly} title={$t('Favorites','收藏')} aria-label={$t('Favorites','收藏')} on:click={() => favoritesOnly=!favoritesOnly}><Star size={15}/></button>
      <button class="icon-button" disabled={busy} title={$t('Probe TCP latency','测 TCP 延迟')} aria-label={$t('Probe TCP latency','测 TCP 延迟')} on:click={probe}><RefreshCw size={15}/></button>
      <label class="icon-button file-button" title={$t('Import nodes','导入节点')}><Upload size={15}/><input type="file" accept=".json,application/json" on:change={importNodes} aria-label={$t('Import nodes','导入节点')}/></label><button class="icon-button" title={$t('Export local nodes','导出本地节点')} aria-label={$t('Export local nodes','导出本地节点')} on:click={exportNodes}><Download size={15}/></button>
    </div>
    {#if message}<div class="status-line">{message}</div>{/if}
    <NodeTable nodes={filtered} currentNodeId={state.connection.currentNodeId} {runtime} showFavorite onEdit={openEditor} onDelete={deleteNode} onCopy={duplicate} />
  </section>
</div>

{#if editorOpen}<ManualNodeDialog node={editorNode} onClose={() => (editorOpen = false)} onSave={saveNode} />{/if}

<style>
  .toolbar-area { padding: 11px 0; display: flex; flex-wrap:wrap; gap: 8px; border-bottom: 1px solid var(--border); }
  .search { min-width: 180px; max-width: 420px; flex: 1; height: 34px; display: flex; align-items: center; gap: 8px; border: 1px solid var(--border-strong); border-radius: 7px; padding: 0 10px; background: var(--surface); color: var(--text-3); }
  .file-button { position:relative; cursor:pointer; } .file-button input { position:absolute; inset:0; width:100%; opacity:0; cursor:pointer; } .active { color:var(--accent); }
  .search input { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; color: var(--text); }
  .select-input { width: 112px; padding-top: 0; padding-bottom: 0; }
  .head-actions, .add-button { display: flex; align-items: center; gap: 9px; }
  .add-button { min-height: 30px; padding: 0 12px; font-size: 11px; }
  .status-line { padding: 8px 16px; border-bottom: 1px solid var(--border); color: #91b4d5; font-size: 11px; }
  @media (max-width: 560px) { .head-actions .subtle { display: none; } .toolbar-area { flex-wrap: wrap; } .search { min-width: 100%; } }
</style>
