<script>
  import { Copy } from 'lucide-svelte'
  import { formatBytes } from '../format.js'
  import { t } from '../i18n.js'
  export let stats
  export let stale=false
  let error=''
  $: qualityLabel=({Unknown:$t('Unknown','未知'),Excellent:$t('Excellent','极好'),Outstanding:$t('Outstanding','优秀'),Good:$t('Good','良好'),Average:$t('Average','一般'),Poor:$t('Poor','很差'),Terrible:$t('Terrible','极差'),Unusable:$t('Unusable','不可用')})[stats.qualityGrade] || stats.qualityGrade || $t('Unknown','未知')
  // effective_path is the P2P data path, not a routing decision; keep it apart from split-routing "direct".
  $: pathLabel=({relay:$t('Via server','经服务器中转'),direct:$t('P2P direct','P2P 直连')})[stats.effectivePath] || stats.effectivePath || '—'
  $: p2pLabel=({disabled:$t('Disabled','已关闭'),unavailable:$t('Unavailable','不可用'),relay:$t('Relay','中转'),eligible:$t('Eligible','待协商'),probing:$t('Probing','探测中'),direct:$t('Direct','直连'),suspect:$t('Suspect','链路可疑'),falling_back:$t('Falling back','回退中'),failed:$t('Failed','失败')})[stats.p2pState] || stats.p2pState
  $: peers=Array.isArray(stats.peers) ? stats.peers : []
  async function copy(value) { try { await navigator.clipboard.writeText(value) } catch(cause) { error=String(cause) } }
</script>
<section class="stats-band"><div class="metrics">
  <div><span>{$t('Download','下载')}</span><strong>{stale ? '—' : stats.rxRateMbps.toFixed(1)} <small>Mbps</small></strong><small>{formatBytes(stats.rxBytes)}</small></div>
  <div><span>{$t('Upload','上传')}</span><strong>{stale ? '—' : stats.txRateMbps.toFixed(1)} <small>Mbps</small></strong><small>{formatBytes(stats.txBytes)}</small></div>
  <div><span>{$t('Active links','活动链路')}</span><strong>{stale ? '—' : stats.activeLinks}</strong><small>{stats.muxActiveLinks > 0 ? `MUX ${stats.muxActiveLinks}` : $t('Primary link','主链路')} · {pathLabel}{stats.tcpStack ? ` · TCP ${stats.tcpStack}` : ''}</small></div>
  <div><span>{$t('Link quality','链路质量')}</span><strong>{stale || !stats.qualityGrade || stats.qualityGrade === 'Unknown' ? '—' : `${stats.qualityPercent.toFixed(1)}%`}</strong><small>{qualityLabel}</small></div>
</div>{#if stats.p2pState}<div class="p2p"><span><b>P2P</b>{p2pLabel}</span>{#if stats.p2pState === 'unavailable'}<small>{$t('Socket protection or authenticated session unavailable; traffic stays on the server relay','套接字保护或认证会话不可用，流量继续经服务器中转')}</small>{/if}{#each peers as peer (peer.virtualIp)}<span><code>{peer.virtualIp}</code>{peer.effectivePath === 'direct' ? $t('P2P direct','P2P 直连') : $t('Via server','经服务器中转')}</span>{/each}</div>{/if}<div class="addresses">{#each [['HTTP',stats.httpProxy],['SOCKS',stats.socksProxy],['TUN',stats.tunIp]] as [label,value]}{#if value}<span><b>{label}</b><code>{value}</code><button class="icon-button" title={$t('Copy','复制')} aria-label={$t('Copy','复制')} on:click={() => copy(value)}><Copy size={13}/></button></span>{/if}{/each}</div>{#if error}<p class="error-line">{error}</p>{/if}</section>
<style>.stats-band { padding:24px 0; border-bottom:1px solid var(--border); } .metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:18px; } .metrics div { display:grid; gap:10px; } .metrics span, small { font-size:12px; color:var(--text-3); } strong { font-size:23px; font-variant-numeric:tabular-nums; } .p2p { display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-top:18px; font-size:13px; } .p2p span { display:flex; gap:8px; align-items:center; } .addresses { display:flex; flex-wrap:wrap; gap:16px; margin-top:20px; } .addresses span { display:flex; gap:8px; align-items:center; } b { font-size:11px; color:var(--text-3); } code { font-size:12px; } @media(max-width:760px) { .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); } }</style>
