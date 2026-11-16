<script>
  import { onMount } from 'svelte'
  import { discoverBinaries, getBinaries, registerBinary, removeBinary } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import Empty from '../lib/components/Empty.svelte'
  import ConfirmDialog from '../lib/components/ConfirmDialog.svelte'

  export let notify

  let binaries = []
  let path = ''
  let deleting = null
  let discoverOpen = false
  let discoverDir = '.'
  let discovered = []
  let discovering = false
  let registeringPath = ''

  function formatSize(bytes) {
    if (!bytes) return '0 B'
    const units = ['B', 'KB', 'MB', 'GB']
    let size = bytes
    let unit = 0
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024
      unit += 1
    }
    return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`
  }

  async function load() {
    try {
      binaries = await getBinaries() || []
    } catch (error) {
      notify('error', t('failedToLoadBinaries'), error.message)
    }
  }

  async function addBinary() {
    if (!path.trim()) return
    try {
      await registerBinary(path.trim())
      path = ''
      notify('success', t('binaryRegistered'), t('binarySubmitted'))
      await load()
    } catch (error) {
      notify('error', t('registerFailed'), error.message)
    }
  }

  async function runDiscovery() {
      discovering = true
    try {
      discovered = await discoverBinaries(discoverDir.trim() || '.') || []
      if (discovered.length === 0) {
        notify('success', t('discoveryComplete'), t('noBinariesFoundInDir'))
      }
    } catch (error) {
      notify('error', t('discoveryFailed'), error.message)
    } finally {
      discovering = false
    }
  }

  async function registerDiscovered(binary) {
    registeringPath = binary.path
    try {
      await registerBinary(binary.path)
      notify('success', t('binaryRegistered'), binary.path)
      await load()
    } catch (error) {
      notify('error', t('registerFailed'), error.message)
    } finally {
      registeringPath = ''
    }
  }

  function openDiscover() {
    discoverOpen = true
    discovered = []
    discoverDir = '.'
  }

  function closeDiscover() {
    discoverOpen = false
    discovering = false
    registeringPath = ''
  }

  async function confirmRemove() {
    try {
      await removeBinary(deleting.id)
      notify('success', t('binaryRemoved'), `${deleting.version || deleting.id}`)
      deleting = null
      await load()
    } catch (error) {
      notify('error', t('removeFailed'), error.message)
    }
  }

  onMount(load)
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('binariesTitle')}</h1>
      <p>{t('binariesManageDesc')}</p>
    </div>
    <div class="header-actions">
      <button class="ghost" on:click={openDiscover}>{t('binariesDiscoverBtn')}</button>
      <div class="register-box">
        <input bind:value={path} placeholder={t('binaryPathPlaceholder')} />
        <button on:click={addBinary}>{t('binariesRegisterBtn')}</button>
      </div>
    </div>
  </div>

  <div class="card">
    {#if binaries.length === 0}
      <Empty message={t('dashboardNoBinary')} />
    {:else}
      <table>
        <thead>
          <tr>
            <th>{t('version')}</th>
            <th>{t('arch')}</th>
            <th>{t('sha256')}</th>
            <th>{t('size')}</th>
            <th>{t('added')}</th>
            <th>{t('active')}</th>
            <th>{t('path')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each binaries as binary}
            <tr>
              <td>{binary.version || '—'}</td>
              <td>{binary.arch || '—'}</td>
              <td class="mono">{binary.sha256?.slice(0, 12)}…</td>
              <td>{formatSize(binary.size)}</td>
              <td>{new Date(binary.addedAt).toLocaleString()}</td>
              <td><span class:active={binary.active} class="badge">{binary.active ? t('active') : t('inactive')}</span></td>
              <td class="path">{binary.path}</td>
              <td><button class="danger" on:click={() => (deleting = binary)}>{t('remove')}</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card muted">
    <h3>{t('futureFeature')}</h3>
    <p>{t('futureFeatureDesc')}</p>
  </div>

  <ConfirmDialog
    open={!!deleting}
    title={t('removeBinaryTitle')}
    message={`${deleting?.path || ''}${deleting?.path ? ' · ' : ''}${t('removeBinaryMessage')}`}
    confirmText={t('remove')}
    on:cancel={() => (deleting = null)}
    on:confirm={confirmRemove}
  />

  {#if discoverOpen}
    <div class="overlay" role="presentation" on:click|self={closeDiscover}>
      <div class="dialog" role="dialog" aria-modal="true">
        <div class="dialog-head">
          <div>
            <h3>{t('discoverTitle')}</h3>
            <p>{t('discoverDesc')}</p>
          </div>
          <button class="icon-button" on:click={closeDiscover}>×</button>
        </div>

        <div class="discover-form">
          <input bind:value={discoverDir} placeholder={t('currentDir')} />
          <button class="accent" disabled={discovering} on:click={runDiscovery}>{discovering ? t('scanning') : t('scanBtn')}</button>
        </div>

        <div class="discover-results">
          {#if discovered.length === 0}
            <Empty message={t('noDiscoveredBinariesYet')} />
          {:else}
            {#each discovered as item}
              <div class="discover-item">
                <div class="discover-meta">
                  <strong>{item.name}</strong>
                  <span class="path">{item.path}</span>
                  <span class="subtle">{item.arch || '—'} · {formatSize(item.size)} · {item.sha256?.slice(0, 12)}…</span>
                </div>
                <button disabled={registeringPath === item.path} on:click={() => registerDiscovered(item)}>
                  {registeringPath === item.path ? t('registering') : t('binariesRegisterBtn')}
                </button>
              </div>
            {/each}
          {/if}
        </div>
      </div>
    </div>
  {/if}
</section>

<style>
  .page { display: grid; gap: 1rem; }
  .header, .register-box, .header-actions, .discover-form, .dialog-head, .discover-item { display: flex; gap: 0.75rem; }
  .header { justify-content: space-between; align-items: flex-start; }
  .header-actions { align-items: center; flex-wrap: wrap; justify-content: flex-end; }
  h1, h3 { margin: 0; }
  p { margin: 0.35rem 0 0; color: #8b949e; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 14px; padding: 1rem; overflow: auto; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.9rem 0.7rem; border-bottom: 1px solid #21262d; text-align: left; vertical-align: top; }
  th { color: #8b949e; font-weight: 500; }
  .mono, .path { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }
  .path { max-width: 260px; word-break: break-all; }
  .badge { padding: 0.25rem 0.6rem; border-radius: 999px; border: 1px solid #30363d; }
  .badge.active { color: #3fb950; border-color: rgba(63, 185, 80, 0.35); }
  input, button {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.8rem;
  }
  input { min-width: 300px; }
  .danger { background: rgba(248, 81, 73, 0.12); border-color: rgba(248, 81, 73, 0.45); }
  .ghost { background: transparent; }
  .accent { background: #0d419d; border-color: #0d419d; }
  .muted { color: #8b949e; }
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(1, 4, 9, 0.7);
    display: grid;
    place-items: center;
    z-index: 40;
  }
  .dialog {
    width: min(760px, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    overflow: auto;
    padding: 1.25rem;
    border-radius: 14px;
    border: 1px solid #30363d;
    background: #161b22;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
    display: grid;
    gap: 1rem;
  }
  .dialog-head { justify-content: space-between; align-items: flex-start; }
  .icon-button {
    min-width: auto;
    width: 2.5rem;
    height: 2.5rem;
    padding: 0;
    font-size: 1.2rem;
    line-height: 1;
  }
  .discover-form { align-items: center; }
  .discover-results { display: grid; gap: 0.75rem; }
  .discover-item {
    justify-content: space-between;
    align-items: center;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 0.9rem;
    background: #0d1117;
  }
  .discover-meta { display: grid; gap: 0.35rem; min-width: 0; }
  .subtle { color: #8b949e; font-size: 0.9rem; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
</style>
