<script>
  import { createEventDispatcher } from 'svelte'
  import { t } from '../i18n.js'
  import { PRESETS, matchPreset, presetOptions, optionErrors } from '../routingPresets.js'
  export let options
  export let disabled=false

  const dispatch=createEventDispatcher()
  const presets=[['split-cn','Split CN','国内直连','Mainland sites direct, the rest through the tunnel','国内网站直连，其余走代理'],['proxy-all','Proxy all','全部代理','Only the local network goes direct','仅局域网直连，其余走代理'],['direct-all','Direct all','全部直连','Nothing uses the tunnel','全部不走隧道']]
  const actions=[['direct','Direct','直连'],['proxy','Proxy','代理'],['reject','Reject','拒绝']]
  const geo=[['geosite','Mainland China sites','中国大陆网站直连','GeoSite list: matches domain names','GeoSite 列表：按域名匹配','geosite.dat / geosite-cn.txt / https://…'],['geoip','Mainland China IPs','中国大陆 IP 直连','GeoIP list: matches addresses after resolution','GeoIP 列表：按解析后的 IP 匹配','geoip.dat / geoip-cn.txt / https://…']]

  function change(patch) { dispatch('change',{ ...options, ...patch }) }
  $: preset=matchPreset(options)
  $: errors=optionErrors(options)
</script>

<div class="quick">
  <div class="field">
    <span class="label" id="quick-presets">{$t('Presets fill the options below','预设：一键填好下面的选项')}</span>
    <div class="choice-grid" role="radiogroup" aria-labelledby="quick-presets">
      {#each presets as [name,en,zh,enHint,zhHint]}<button class="choice" role="radio" aria-checked={preset === name} {disabled} on:click={() => dispatch('change',presetOptions(name,options))}><strong>{$t(en,zh)}</strong><small>{$t(enHint,zhHint)}</small></button>{/each}
    </div>
    {#if !preset}<small class="subtle">{$t('Custom combination','自定义组合')}</small>{/if}
  </div>

  <div class="option">
    <span><strong>{$t('Everything else','其余流量')}</strong><small class="subtle">{$t('Traffic no rule matches','没有命中任何规则的流量')}</small></span>
    <div class="segmented compact" role="radiogroup" aria-label={$t('Everything else','其余流量')}>{#each actions as [value,en,zh]}<button role="radio" aria-checked={options.defaultAction === value} class:active={options.defaultAction === value} {disabled} on:click={() => change({ defaultAction:value })}>{$t(en,zh)}</button>{/each}</div>
  </div>

  <label class="option">
    <span><strong>{$t('Local network direct','局域网直连')}</strong><small class="subtle mono">10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16</small></span>
    <input type="checkbox" role="switch" checked={options.lan} {disabled} on:change={(e) => change({ lan:e.currentTarget.checked })}/>
  </label>

  {#each geo as [kind,en,zh,enHint,zhHint,placeholder]}
    <div class="option-group">
      <label class="option">
        <span><strong>{$t(en,zh)}</strong><small class="subtle">{$t(enHint,zhHint)}</small></span>
        <input type="checkbox" role="switch" checked={options[kind]} {disabled} on:change={(e) => change({ [kind]:e.currentTarget.checked })}/>
      </label>
      {#if options[kind]}<label class="field source">
        <span class="label">{$t('List file or URL','列表文件或 URL')}</span>
        <input class="text-input mono" class:invalid={!!errors[kind]} {placeholder} value={options[`${kind}Source`] || ''} {disabled} aria-invalid={!!errors[kind]} on:change={(e) => change({ [`${kind}Source`]:e.currentTarget.value.trim() })}/>
        {#if errors[kind]}<small class="error-text" role="alert">{$t('Enter a file path or https:// URL to turn this on','填写文件路径或 https:// 地址后才会生效')}</small>{:else}<small class="subtle">{$t('Relative paths resolve under the policy folder; .dat files are read as v2ray format','相对路径按策略目录解析；.dat 文件按 v2ray 格式读取')}</small>{/if}
      </label>{/if}
    </div>
  {/each}
</div>

<style>
  .quick { display:grid; gap:14px; }
  .option { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:10px 0; border-top:1px solid var(--border); cursor:pointer; }
  div.option { cursor:default; }
  .option > span { display:grid; gap:3px; min-width:0; }
  .option-group { display:grid; gap:8px; }
  .source { padding-left:2px; }
  .label { font-size:12px; color:var(--text-2); }
  .error-text { color:var(--red); font-size:12px; }
  .invalid { border-color:var(--red); }
  @media(max-width:560px) { .option { flex-wrap:wrap; } }
</style>
