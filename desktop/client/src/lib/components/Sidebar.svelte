<script>
  import { ArrowRightLeft, RadioTower, Settings, Waypoints, Globe, Logs, Route } from 'lucide-svelte'
  import { t } from '../i18n.js'
  export let current = 'connection'
  export let navigate
  export let version = ''
  const items = [['connection','Connection','连接',ArrowRightLeft], ['nodes','Nodes','节点',Waypoints], ['subscription','Subscriptions','订阅',RadioTower], ['routing','Routing','分流',Route], ['dns','DNS','DNS',Globe], ['logs','Logs','日志',Logs], ['settings','Settings','设置',Settings]]
</script>
<aside class="sidebar">
  <div class="brand"><img src="/icon.ico" alt="" width="24" height="24"/><strong>OpenPPP2</strong></div>
  <nav aria-label={$t('Navigation','导航')}>
    {#each items as [id,en,zh,icon]}<button class:active={current === id} on:click={() => navigate(id)} aria-current={current === id ? 'page' : undefined} title={$t(en,zh)}><svelte:component this={icon} size={18}/><span>{$t(en,zh)}</span></button>{/each}
  </nav>
  <div class="version">Windows · {version || $t('Kernel unknown','内核未知')}</div>
</aside>
<style>
  .sidebar { position:sticky; top:0; height:100vh; padding:26px 12px; background:var(--surface); border-right:1px solid var(--border); display:flex; flex-direction:column; }
  .brand { display:flex; gap:10px; align-items:center; padding:0 12px 28px; color:var(--text); } .brand strong { font-size:17px; }
  nav { display:grid; gap:6px; } nav button { display:flex; gap:12px; align-items:center; width:100%; min-height:40px; border:0; background:transparent; color:var(--text-2); text-align:left; border-radius:6px; padding:0 12px; cursor:pointer; }
  nav button:hover { background:var(--surface-hover); } nav button.active { color:var(--accent); background:var(--accent-soft); }
  .version { margin-top:auto; font-size:11px; color:var(--text-3); overflow-wrap:anywhere; padding:12px; }
  @media(max-width:900px) { .sidebar { padding:24px 6px; } .brand { padding:0 0 28px; justify-content:center; } .brand strong, nav span, .version { display:none; } nav button { justify-content:center; padding:0; } }
</style>
