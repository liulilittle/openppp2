<script>
  import { Check, Copy, RefreshCw } from 'lucide-svelte'
  import { formatDateTime } from '../lib/format.js'
  import { subscriptionNotice } from '../lib/runtime/model.js'
  export let state
  export let runtime
  let copied = false
  let refreshing = false
  let urlDraft = state.subscription.url
  let editing = false
  $: subscription = state.subscription
  $: notice = subscriptionNotice(subscription)

  async function copyUrl() {
    await navigator.clipboard?.writeText(subscription.url)
    copied = true
    setTimeout(() => (copied = false), 1200)
  }

  async function refresh() {
    refreshing = true
    await runtime.refreshSubscription(urlDraft.trim())
    setTimeout(() => (refreshing = false), 350)
  }
  $: if (!editing && urlDraft !== subscription.url) urlDraft = subscription.url
</script>

<div class="page">
  {#if notice}<div class="notice">{notice}，节点仍可正常使用。</div>{/if}
  <section class="panel">
    <div class="panel-head"><h1 class="panel-title">订阅</h1><button class="secondary-button refresh" on:click={refresh} disabled={refreshing}><span class:spin={refreshing}><RefreshCw size={14} /></span>刷新</button></div>
    <div class="panel-body subscription-body">
      <div class="field full"><label for="subscription-url">订阅地址</label><div class="url-row"><input id="subscription-url" class="text-input mono" bind:value={urlDraft} on:focus={() => editing = true} on:blur={() => editing = false} placeholder="https://example.com/sub/token" /><button class="icon-button" on:click={copyUrl} title="复制订阅地址">{#if copied}<Check size={15} />{:else}<Copy size={15} />{/if}</button></div></div>
      <div class="fact"><span>名称</span><strong>{subscription.name}</strong></div>
      <div class="fact"><span>节点数量</span><strong class="number">{subscription.nodes.length}</strong></div>
      <div class="fact"><span>上次成功同步</span><strong class="number">{formatDateTime(subscription.lastSyncedAt)}</strong></div>
      <div class="fact"><span>文档更新时间</span><strong class="number">{formatDateTime(subscription.updatedAt)}</strong></div>
    </div>
  </section>
  <section class="panel panel-body token-note"><b>Token 轮换</b><p>服务端轮换订阅 Token 后，需要在这里替换新的订阅地址。旧地址失效不会删除本地缓存。</p></section>
</div>

<style>
  .refresh { display: inline-flex; align-items: center; gap: 7px; }
  .subscription-body { display: grid; grid-template-columns: 1fr 1fr; gap: 18px 28px; }
  .full { grid-column: 1 / -1; }
  .url-row { display: grid; grid-template-columns: 1fr 32px; gap: 7px; }
  .fact { display: grid; gap: 4px; }.fact span { color: var(--text-3); font-size: 11px; }.fact strong { font-size: 12px; }
  .token-note p { margin: 6px 0 0; color: var(--text-2); }
  .refresh span { display: inline-flex; } .spin { animation: spin .8s linear infinite; } @keyframes spin { to { transform: rotate(360deg); } }
  @media (max-width: 640px) { .subscription-body { grid-template-columns: 1fr; } .full { grid-column: auto; } }
</style>
