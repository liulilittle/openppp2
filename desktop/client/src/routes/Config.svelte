<script>
  import { Save, Check, RotateCcw } from 'lucide-svelte'
  import { t } from '../lib/i18n.js'
  export let state
  export let runtime
  export let section='all'
  // Only edited keys are kept locally, so options changed elsewhere (e.g. Settings switches) are never overwritten.
  let draft=state.config, edits={}, message='', error='', saving=false
  function reset() { draft=state.config; edits={}; message=''; error='' }
  function validate() { const value=JSON.parse(draft); if(!value || Array.isArray(value) || typeof value !== 'object') throw new Error($t('Expected JSON object','必须是 JSON 对象')); return value }
  async function save() { saving=true; error=''; try { const value=validate(); await runtime.updateClientConfig(JSON.stringify(value,null,2),options); edits={}; message=$t('Saved; applies on next connection','已保存，下次连接生效') } catch(cause) { error=String(cause) } finally { saving=false } }
  function check() { try { validate(); message=$t('Valid JSON','JSON 格式有效'); error='' } catch(cause) { error=String(cause) } }
  $: options={...state.launchOptions,...edits}
  $: dirty=draft !== state.config || Object.keys(edits).some((key) => edits[key] !== state.launchOptions?.[key])
</script>
<section><div class="section-heading"><h2>{$t(section === 'adapter' ? 'Virtual adapter' : 'Launch options',section === 'adapter' ? '虚拟网卡' : '启动参数')}</h2><div class="toolbar"><span class="subtle">{dirty ? $t('Unsaved changes','未保存') : message}</span><button class="icon-button" title={$t('Validate','校验')} aria-label={$t('Validate','校验')} on:click={check}><Check size={15}/></button><button class="icon-button" title={$t('Reset','恢复')} aria-label={$t('Reset','恢复')} on:click={reset}><RotateCcw size={15}/></button><button class="primary-button action" disabled={saving || !dirty} on:click={save}><Save size={15}/>{$t('Save','保存')}</button></div></div>
  {#if section !== 'advanced'}<div class="form-grid two spaced">{#each [['tunIp','TUN IP','TUN IP'],['tunMask','Mask','子网掩码'],['gateway','Gateway','网关']] as [key,en,zh]}<label class="field"><span>{$t(en,zh)}</span><input class="text-input mono" value={options[key] || ''} on:input={(event) => edits={...edits,[key]:event.currentTarget.value}}/></label>{/each}
    {#if state.kernel?.tcpStackSupported !== false}<label class="field"><span>{$t('TCP stack','TCP 协议栈')}</span><select class="select-input" value={options.tcpStack || ''} on:change={(event) => edits={...edits,tcpStack:event.currentTarget.value}}><option value="">{$t('Kernel default','内核默认')}</option><option value="native">native</option><option value="lwip">lwIP</option><option value="xtcp">{$t('xtcp (experimental, must be built in)','xtcp（实验，需内核编译支持）')}</option></select></label>{/if}
    {#if state.kernel?.tunIpv6Supported !== false}<label class="field"><span>{$t('Requested IPv6 (optional)','请求的 IPv6（可选）')}</span><input class="text-input mono" placeholder={$t('Server assigns when empty','留空由服务器分配')} value={options.tunIpv6 || ''} on:input={(event) => edits={...edits,tunIpv6:event.currentTarget.value}}/></label>{/if}</div>{/if}
  {#if section !== 'adapter'}<div class="form-grid two spaced"><label class="field"><span>{$t('MUX links','MUX 数量')}</span><input class="text-input" type="number" min="0" max="65535" value={options.mux || 0} on:input={(event) => edits={...edits,mux:Number(event.currentTarget.value)}}/></label><label class="field"><span>{$t('MUX mode','MUX 模式')}</span><select class="select-input" value={options.muxMode || 'compat'} on:change={(event) => edits={...edits,muxMode:event.currentTarget.value}}><option>compat</option><option>flow</option><option>balance</option><option value="stripe">{$t('stripe (experimental)','stripe（实验）')}</option></select></label></div>
    {#each [['muxTurbo','Flow Turbo'],['vnet','VNet'],['blockQuic','Block QUIC'],['staticMode','Static UDP']] as [key,label]}<label class="option-row"><span>{label}</span><input type="checkbox" role="switch" checked={!!options[key]} disabled={key === 'muxTurbo' && options.muxMode !== 'flow'} on:change={(event) => edits={...edits,[key]:event.currentTarget.checked}}/></label>{/each}
    <details class="spaced"><summary>{$t('Advanced appsettings JSON','高级 appsettings JSON')}</summary><textarea class="text-area spaced" bind:value={draft} spellcheck="false" aria-label="appsettings JSON"></textarea></details>{/if}
  {#if error}<div class="error-line" role="alert">{error}</div>{/if}
</section>
<style>.spaced { margin:20px 0; } summary { cursor:pointer; color:var(--text-2); } .option-row { min-height:46px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--border); }</style>
