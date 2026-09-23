<script>
  import { formatBytes } from '../format.js'
  export let stats
</script>

<section class="panel panel-body">
  <div class="heading"><b>本机</b><span>stats 导出 · 1s 刷新</span></div>
  <div class="metrics number">
    <div><span class="label">↓</span><strong>{stats.rxRateMbps.toFixed(1)} Mbps</strong></div>
    <div><span class="label">↑</span><strong>{stats.txRateMbps.toFixed(1)} Mbps</strong></div>
    <div><span class="label">链路质量</span><strong>{stats.qualityPercent.toFixed(1)}% {stats.qualityGrade}</strong></div>
    <div><span class="label">累计 ↓</span><strong>{formatBytes(stats.rxBytes)}</strong></div>
    <div><span class="label">累计 ↑</span><strong>{formatBytes(stats.txBytes)}</strong></div>
    <div><span class="label">活动链路</span><strong>{stats.activeLinks}{#if stats.effectivePath} · {stats.effectivePath}{/if}</strong></div>
  </div>
  {#if stats.tunIp || stats.gateway || stats.httpProxy || stats.socksProxy}<div class="network mono">{#if stats.tunIp}<span><i>TUN</i>{stats.tunIp}</span>{/if}{#if stats.gateway}<span><i>gw</i>{stats.gateway}</span>{/if}{#if stats.httpProxy}<span><i>http</i>{stats.httpProxy}</span>{/if}{#if stats.socksProxy}<span><i>socks</i>{stats.socksProxy}</span>{/if}</div>{/if}
</section>

<style>
  .heading { display: flex; align-items: baseline; gap: 7px; }
  .heading span { color: var(--text-3); font-size: 10px; }
  .metrics { margin-top: 9px; display: grid; grid-template-columns: 1fr 1fr 1.5fr; gap: 7px 24px; }
  .metrics div { min-width: 0; display: flex; gap: 7px; }
  .label { color: var(--text-3); font-family: inherit; }
  strong { overflow: hidden; text-overflow: ellipsis; }
  .network { margin-top: 9px; display: flex; flex-wrap: wrap; gap: 9px 24px; color: #b9d5ed; font-size: 11px; }
  .network i { font-style: normal; color: var(--text-3); margin-right: 6px; }
  @media (max-width: 720px) { .metrics { grid-template-columns: 1fr 1fr; } }
  @media (max-width: 600px) { .metrics { grid-template-columns: 1fr; } }
</style>
