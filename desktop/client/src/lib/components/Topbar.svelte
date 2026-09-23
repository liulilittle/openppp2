<script>
  import { connectionStates, subscriptionNotice } from '../runtime/model.js'
  import { formatDateTime } from '../format.js'

  export let state
  export let runtime

  $: notice = subscriptionNotice(state.subscription)
  const previewStates = ['connected', 'connecting', 'disconnected', 'error']
</script>

<header>
  <div class="sync-line">
    {#if notice}<span class="cache">{notice}</span>{:else}订阅已同步 · updatedAt {formatDateTime(state.subscription.updatedAt)}{/if}
  </div>
  {#if import.meta.env.DEV && runtime.kind === 'demo'}
    <div class="state-preview" aria-label="状态预览">
      {#each previewStates as item}
        <button class:active={state.connection.status === item} on:click={() => runtime.simulate(item)}>{connectionStates[item].label}</button>
      {/each}
    </div>
  {/if}
</header>

<style>
  header { min-height: 54px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .sync-line { color: #7fa5c9; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .cache { color: #e3bd68; }
  .state-preview { display: flex; border: 1px solid var(--border); border-radius: 7px; overflow: hidden; flex: none; }
  .state-preview button { height: 26px; padding: 0 12px; border: 0; border-right: 1px solid var(--border); background: transparent; color: var(--text-2); font-size: 11px; cursor: pointer; }
  .state-preview button:last-child { border-right: 0; }
  .state-preview button.active { background: rgba(255,255,255,.07); color: #fff; }
  @media (max-width: 760px) { .state-preview { display: none; } }
</style>
