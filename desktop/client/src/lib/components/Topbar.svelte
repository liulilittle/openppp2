<script>
  import { Sun, Moon, Monitor } from 'lucide-svelte'
  import { t } from '../i18n.js'
  export let state
  export let runtime
  let error = ''
  $: sources = state.subscription.sources || []
  async function theme(value) { try { await runtime.updateSetting('appearance',value) } catch(cause) { error=String(cause) } }
</script>
<header><span>{#if runtime.kind === 'demo'}{$t('Preview','预览')} · {/if}{sources.filter((source) => source.enabled).length} {$t('subscriptions','个订阅')} · {state.subscription.nodes.length} {$t('nodes','个节点')}</span>
  <div class="toolbar">{#if error}<span role="alert">{error}</span>{/if}
    {#each [['light',Sun,'Light','浅色'],['dark',Moon,'Dark','深色'],['system',Monitor,'System','跟随系统']] as [value,icon,en,zh]}<button class="icon-button" class:active={state.settings.appearance === value} title={$t(en,zh)} aria-label={$t(en,zh)} aria-pressed={state.settings.appearance === value} on:click={() => theme(value)}><svelte:component this={icon} size={16}/></button>{/each}
  </div>
</header>
<style>header { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:12px; color:var(--text-3); font-size:12px; } .active { color:var(--accent); background:var(--accent-soft); }</style>
