<script>
  import { ArrowRightLeft, FileJson, Logs, RadioTower, Settings, Waypoints } from 'lucide-svelte'

  export let current = 'connection'
  export let navigate

  const primary = [
    { id: 'connection', label: '连接', icon: ArrowRightLeft },
    { id: 'nodes', label: '节点', icon: Waypoints },
    { id: 'subscription', label: '订阅', icon: RadioTower },
    { id: 'logs', label: '日志', icon: Logs },
  ]
  const advanced = [
    { id: 'config', label: '配置', icon: FileJson },
    { id: 'settings', label: '设置', icon: Settings },
  ]
</script>

<aside class="sidebar">
  <div class="brand"><i></i><strong>OpenPPP2</strong></div>
  <nav aria-label="主要导航">
    {#each primary as item}
      <button class:active={current === item.id} on:click={() => navigate(item.id)} aria-current={current === item.id ? 'page' : undefined} title={item.label}>
        <svelte:component this={item.icon} size={15} strokeWidth={1.7} /><span>{item.label}</span>
      </button>
    {/each}
    <div class="section-label">高级</div>
    {#each advanced as item}
      <button class:active={current === item.id} on:click={() => navigate(item.id)} aria-current={current === item.id ? 'page' : undefined} title={item.label}>
        <svelte:component this={item.icon} size={15} strokeWidth={1.7} /><span>{item.label}</span>
      </button>
    {/each}
  </nav>
  <div class="version mono">ppp 2.1.0 · windows</div>
</aside>

<style>
  .sidebar { position: sticky; top: 0; height: 100vh; border-right: 1px solid var(--border); padding: 18px 10px; display: flex; flex-direction: column; background: #0b0d10; }
  .brand { display: flex; align-items: center; gap: 9px; height: 25px; padding: 0 10px; margin-bottom: 13px; }
  .brand i { width: 8px; height: 8px; border-radius: 50%; background: var(--green); }
  .brand strong { font-size: 14px; }
  nav { display: grid; gap: 3px; }
  nav button { width: 100%; height: 32px; display: flex; align-items: center; gap: 11px; border: 0; border-radius: 7px; padding: 0 11px; background: transparent; color: var(--text-2); cursor: pointer; text-align: left; }
  nav button:hover { background: rgba(255,255,255,.045); color: var(--text); }
  nav button.active { background: rgba(255,255,255,.075); color: #fff; }
  .section-label { padding: 16px 10px 5px; color: var(--text-3); font-size: 11px; }
  .version { margin-top: auto; padding: 0 10px; color: #526172; font-size: 10px; }
  @media (max-width: 900px) {
    .sidebar { width: 58px; padding-left: 8px; padding-right: 8px; }
    .brand { justify-content: center; padding: 0; }
    .brand strong, nav button span, .section-label, .version { display: none; }
    nav button { justify-content: center; padding: 0; }
  }
  @media (max-width: 560px) {
    .sidebar { position: fixed; inset: auto 0 0 0; z-index: 30; width: auto; height: 54px; border-right: 0; border-top: 1px solid var(--border); flex-direction: row; padding: 5px 8px; }
    .brand, .section-label, .version { display: none; }
    nav { width: 100%; display: flex; justify-content: space-around; }
    nav button { width: 42px; height: 42px; }
  }
</style>
