<script>
  import { onMount } from 'svelte'
  import { instances, selectedInstance } from '../lib/stores'
  import { createInstance, updateInstance, getInstances, getStatus, startInstance, stopInstance, restartInstance, getBinaries, getProfiles, getProfile } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import StatusBadge from '../lib/components/StatusBadge.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Empty from '../lib/components/Empty.svelte'

  export let navigate
  export let notify

  let status = null
  let loading = true
  let timer
  let busy = ''
  let showInstanceModal = false
  let editingName = ''
  let savingInstance = false
  let showTunSection = false
  let showAdvancedSection = false
  let form = emptyForm()
  let binaryList = []
  let profileList = []
  let profileWarnings = []

  function emptyForm() {
    return {
      name: '',
      binaryId: '',
      configName: '',
      mode: 'client',
      args: '',
      workDir: '.',
      tunName: '',
      tunIp: '',
      tunGw: '',
      tunMask: '',
      tunVnet: true,
      tunHost: true,
      tunProtect: true,
      tunMux: 0,
      lwip: false,
      vbgp: true,
      bypass: '',
      dnsRules: '',
      virr: '',
      tuiEnabled: false,
    }
  }

  function isEditing() {
    return editingName !== ''
  }

  function tokenizeArgs(value) {
    return value.split(/\s+/).map((item) => item.trim()).filter(Boolean)
  }

  function buildArgs(currentForm, profilePath) {
    const args = [`--mode=${currentForm.mode}`]
    if (profilePath) {
      args.push(`--config=${profilePath}`)
    }
    if (currentForm.tunName.trim()) {
      args.push(`--tun=${currentForm.tunName.trim()}`)
    }
    if (currentForm.tunIp.trim()) {
      args.push(`--tun-ip=${currentForm.tunIp.trim()}`)
    }
    if (currentForm.tunGw.trim()) {
      args.push(`--tun-gw=${currentForm.tunGw.trim()}`)
    }
    if (currentForm.tunMask.trim()) {
      args.push(`--tun-mask=${currentForm.tunMask.trim()}`)
    }
    if (!currentForm.tunVnet) {
      args.push('--tun-vnet=no')
    }
    if (!currentForm.tunHost) {
      args.push('--tun-host=no')
    }
    if (!currentForm.tunProtect) {
      args.push('--tun-protect=no')
    }
    if (Number(currentForm.tunMux)) {
      args.push(`--tun-mux=${Number(currentForm.tunMux)}`)
    }
    if (currentForm.lwip) {
      args.push('--lwip=yes')
    }
    if (!currentForm.vbgp) {
      args.push('--vbgp=no')
    }
    if (currentForm.bypass.trim()) {
      args.push(`--bypass=${currentForm.bypass.trim()}`)
    }
    if (currentForm.dnsRules.trim()) {
      args.push(`--dns-rules=${currentForm.dnsRules.trim()}`)
    }
    if (currentForm.virr.trim()) {
      args.push(`--virr=${currentForm.virr.trim()}`)
    }
    return [...args, ...tokenizeArgs(currentForm.args)]
  }

  function parseInstanceArgs(instance) {
    const parsed = {
      mode: 'client',
      tunName: '',
      tunIp: '',
      tunGw: '',
      tunMask: '',
      tunVnet: true,
      tunHost: true,
      tunProtect: true,
      tunMux: 0,
      lwip: false,
      vbgp: true,
      bypass: '',
      dnsRules: '',
      virr: '',
      extraArgs: [],
    }
    for (const arg of instance.args || []) {
      if (arg.startsWith('--mode=')) {
        parsed.mode = arg.slice('--mode='.length) || 'client'
        continue
      }
      if (arg.startsWith('--config=')) {
        continue
      }
      if (arg.startsWith('--tun=')) {
        parsed.tunName = arg.slice('--tun='.length)
        continue
      }
      if (arg.startsWith('--tun-ip=')) {
        parsed.tunIp = arg.slice('--tun-ip='.length)
        continue
      }
      if (arg.startsWith('--tun-gw=')) {
        parsed.tunGw = arg.slice('--tun-gw='.length)
        continue
      }
      if (arg.startsWith('--tun-mask=')) {
        parsed.tunMask = arg.slice('--tun-mask='.length)
        continue
      }
      if (arg === '--tun-vnet=no') {
        parsed.tunVnet = false
        continue
      }
      if (arg === '--tun-host=no') {
        parsed.tunHost = false
        continue
      }
      if (arg === '--tun-protect=no') {
        parsed.tunProtect = false
        continue
      }
      if (arg.startsWith('--tun-mux=')) {
        parsed.tunMux = Number(arg.slice('--tun-mux='.length)) || 0
        continue
      }
      if (arg === '--lwip=yes') {
        parsed.lwip = true
        continue
      }
      if (arg === '--vbgp=no') {
        parsed.vbgp = false
        continue
      }
      if (arg.startsWith('--bypass=')) {
        parsed.bypass = arg.slice('--bypass='.length)
        continue
      }
      if (arg.startsWith('--dns-rules=')) {
        parsed.dnsRules = arg.slice('--dns-rules='.length)
        continue
      }
      if (arg.startsWith('--virr=')) {
        parsed.virr = arg.slice('--virr='.length)
        continue
      }
      parsed.extraArgs.push(arg)
    }
    return parsed
  }

  async function loadModalOptions() {
    const [bl, pl] = await Promise.all([getBinaries(), getProfiles()])
    binaryList = Array.isArray(bl) ? bl : []
    profileList = Array.isArray(pl) ? pl : []
  }

  function formatDate(value) {
    return value ? new Date(value).toLocaleString() : '—'
  }

  function formatUptime(instance) {
    const source = instance.running ? instance.startedAt : instance.stoppedAt
    if (!source) return '—'
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(source).getTime()) / 1000))
    const hrs = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    const secs = seconds % 60
    return `${hrs}${t('hourShort')} ${mins}${t('minuteShort')} ${secs}${t('secondShort')}`
  }

  async function refresh() {
    try {
      const [statusData, instanceData] = await Promise.all([getStatus(), getInstances()])
      status = statusData
      instances.set(Array.isArray(instanceData) ? instanceData : [])
    } catch (error) {
      notify('error', t('dashboardRefreshFailed'), error.message)
    } finally {
      loading = false
    }
  }

  async function runAction(action, name) {
    busy = `${action}:${name}`
    try {
      if (action === 'start') await startInstance(name)
      if (action === 'stop') await stopInstance(name)
      if (action === 'restart') await restartInstance(name)
      notify('success', t('actionSuccess'), `${t(`instance${action[0].toUpperCase()}${action.slice(1)}`)} ${name}`)
      await refresh()
    } catch (error) {
      notify('error', t('instanceActionFailed'), error.message)
    } finally {
      busy = ''
    }
  }

  function closeInstanceModal() {
    showInstanceModal = false
    editingName = ''
    savingInstance = false
    showTunSection = false
    showAdvancedSection = false
    form = emptyForm()
    profileWarnings = []
  }

  async function loadProfileWarnings(profileName) {
    profileWarnings = []
    if (!profileName) return
    try {
      const profile = await getProfile(profileName)
      const content = profile?.content || ''
      const json = JSON.parse(content)
      const telemetry = json?.telemetry || {}
      if (!telemetry.enabled) {
        profileWarnings = [t('profileTelemetryDisabledHint')]
        return
      }
      const warnings = []
      if (!telemetry['console-log']) warnings.push(t('profileTelemetryConsoleLogDisabledHint'))
      if (warnings.length > 0) {
        profileWarnings = warnings
      }
    } catch {
      profileWarnings = []
    }
  }

  async function openAddModal() {
    try {
      await loadModalOptions()
      editingName = ''
      form = emptyForm()
      showTunSection = false
      showAdvancedSection = false
      profileWarnings = []
      showInstanceModal = true
    } catch {
      binaryList = []
      profileList = []
      showInstanceModal = true
    }
  }

  async function openEditModal(instance) {
    try {
      await loadModalOptions()
    } catch {
      binaryList = []
      profileList = []
    }

    const parsedArgs = parseInstanceArgs(instance)
    const matchedBinary = binaryList.find((item) => item.path === instance.binary)
    const matchedProfile = profileList.find((item) => item.path === instance.configPath)
    editingName = instance.name
    form = {
      name: instance.name,
      binaryId: matchedBinary?.id || '',
      configName: matchedProfile?.name || '',
      mode: parsedArgs.mode || 'client',
      args: parsedArgs.extraArgs.join(' '),
      workDir: instance.workDir || '.',
      tunName: parsedArgs.tunName,
      tunIp: parsedArgs.tunIp,
      tunGw: parsedArgs.tunGw,
      tunMask: parsedArgs.tunMask,
      tunVnet: parsedArgs.tunVnet,
      tunHost: parsedArgs.tunHost,
      tunProtect: parsedArgs.tunProtect,
      tunMux: parsedArgs.tunMux,
      lwip: parsedArgs.lwip,
      vbgp: parsedArgs.vbgp,
      bypass: parsedArgs.bypass,
      dnsRules: parsedArgs.dnsRules,
      virr: parsedArgs.virr,
    }
    showTunSection = Boolean(form.tunName || form.tunIp || form.tunGw || form.tunMask || Number(form.tunMux) || !form.tunVnet || !form.tunHost || !form.tunProtect)
    showAdvancedSection = Boolean(form.lwip || !form.vbgp || form.bypass || form.dnsRules || form.virr)
    await loadProfileWarnings(form.configName)
    showInstanceModal = true
  }

  async function handleProfileChange(event) {
    form.configName = event.currentTarget.value
    await loadProfileWarnings(form.configName)
  }

  async function submitInstance() {
    const name = form.name.trim()
    if (!name) return
    const bin = binaryList.find(b => b.id === form.binaryId)
    const prof = profileList.find(p => p.name === form.configName)
    const payload = {
      name,
      binary: bin ? bin.path : '',
      configPath: prof ? prof.path : '',
      args: buildArgs(form, prof ? prof.path : ''),
      workDir: form.workDir.trim() || '.',
      tuiEnabled: !!form.tuiEnabled,
    }
    savingInstance = true
    try {
      if (isEditing()) {
        await updateInstance(editingName, payload)
        notify('success', t('instanceUpdated'), name)
      } else {
        await createInstance(payload)
        notify('success', t('addInstanceSuccess'), name)
      }
      closeInstanceModal()
      await refresh()
    } catch (error) {
      notify('error', isEditing() ? t('instanceActionFailed') : t('addInstanceFailed'), error.message)
    } finally {
      savingInstance = false
    }
  }

  function openInstance(name) {
    selectedInstance.set(name)
    navigate('instances')
  }

  function handleOverlayKeydown(event) {
    if (event.key === 'Escape' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      closeInstanceModal()
    }
  }

  onMount(() => {
    refresh()
    timer = setInterval(refresh, 3000)
    return () => clearInterval(timer)
  })
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('dashboardTitle')}</h1>
      <p>{t('dashboardDesc')}</p>
    </div>
    <button class="ghost" on:click={openAddModal}>{t('addInstance')}</button>
  </div>

  {#if loading}
    <Loading />
  {:else}
    <div class="status-card card">
      <div>
        <span class="label">{t('dashboardVersion')}</span>
        <strong>{status?.version || '—'}</strong>
      </div>
      <div>
        <span class="label">{t('dashboardUptime')}</span>
        <strong>{status?.uptime || '—'}</strong>
      </div>
      <div>
        <span class="label">{t('dashboardInstances')}</span>
        <strong>{status?.instanceCount ?? $instances.length}</strong>
      </div>
      <div>
        <span class="label">{t('dashboardBinaries')}</span>
        <strong>{status?.binariesCount ?? 0}</strong>
      </div>
    </div>

    {#if (status?.binariesCount ?? 0) === 0}
      <div class="card hint-card">
        <strong>{t('dashboardNoBinary')}</strong>
        <span>{t('dashboardNoBinaryHint')}</span>
      </div>
    {/if}

    {#if $instances.length === 0}
      <Empty message={t('dashboardNoInstances')} />
    {:else}
      <div class="grid">
        {#each $instances as instance}
          <div class="card instance-card" role="button" tabindex="0" on:click={() => openInstance(instance.name)} on:keydown={(event) => (event.key === 'Enter' || event.key === ' ') && openInstance(instance.name)}>
            <div class="card-head">
              <div>
                <h3>{instance.name}</h3>
                <small>{instance.binary}</small>
              </div>
              <StatusBadge running={instance.running} crashed={!instance.running && !!instance.lastExit && !instance.lastExit.success} />
            </div>

            <div class="meta">
              <span>{t('instancePID')}: {instance.pid || '—'}</span>
              <span>{t('since')}: {formatDate(instance.running ? instance.startedAt : instance.stoppedAt)}</span>
              <span>{t('elapsed')}: {formatUptime(instance)}</span>
              <span>{t('instanceRestartCount')}: {instance.restartCount ?? 0}</span>
            </div>

            {#if instance.runtimeStats && Object.keys(instance.runtimeStats).length > 0}
              <div class="stats-row">
                {#if instance.runtimeStats['hosting environment']}<span class="chip">{instance.runtimeStats['hosting environment']}</span>{/if}
                {#if instance.runtimeStats['vpn server']}<span class="chip">{instance.runtimeStats['vpn server']}</span>{/if}
                {#if instance.runtimeStats['managed server']}<span class="chip">{instance.runtimeStats['managed server']}</span>{/if}
                {#if instance.runtimeStats.duration}<span class="chip">{t('duration')}: {instance.runtimeStats.duration}</span>{/if}
                {#if instance.runtimeStats.sessions}<span class="chip">{t('sessions')}: {instance.runtimeStats.sessions}</span>{/if}
                {#if instance.runtimeStats.tx}<span class="chip">{t('tx')}: {instance.runtimeStats.tx}</span>{/if}
                {#if instance.runtimeStats.rx}<span class="chip">{t('rx')}: {instance.runtimeStats.rx}</span>{/if}
                {#if instance.runtimeStats['in']}<span class="chip">IN: {instance.runtimeStats['in']}</span>{/if}
                {#if instance.runtimeStats.out}<span class="chip">OUT: {instance.runtimeStats.out}</span>{/if}
              </div>
            {/if}

            <div class="actions">
              <button disabled={busy !== '' || savingInstance} on:click|stopPropagation={() => openEditModal(instance)}>{t('edit')}</button>
              <button disabled={busy !== '' && busy !== `start:${instance.name}`} on:click|stopPropagation={() => runAction('start', instance.name)}>{t('instanceStart')}</button>
              <button disabled={busy !== '' && busy !== `stop:${instance.name}`} on:click|stopPropagation={() => runAction('stop', instance.name)}>{t('instanceStop')}</button>
              <button class="accent" disabled={busy !== '' && busy !== `restart:${instance.name}`} on:click|stopPropagation={() => runAction('restart', instance.name)}>{t('instanceRestart')}</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  {/if}

  {#if showInstanceModal}
    <div class="overlay" role="button" tabindex="0" aria-label={t('cancel')} on:click|self={closeInstanceModal} on:keydown={handleOverlayKeydown}>
      <div class="dialog" role="dialog" aria-modal="true" tabindex="-1">
        <h3>{isEditing() ? t('editInstance') : t('newInstanceTitle')}</h3>
        <div class="form-grid">
          <label>
            <span>{t('newInstanceName')}</span>
            <input bind:value={form.name} type="text" disabled={isEditing()} />
          </label>
          <label>
            <span>{t('newInstanceBinary')}</span>
            <select bind:value={form.binaryId}>
              <option value="">-- {t('selectBinary')} --</option>
              {#each binaryList as bin}
                <option value={bin.id}>{bin.path} ({bin.arch}, {bin.sha256.slice(0, 8)})</option>
              {/each}
            </select>
            {#if binaryList.length === 0}
              <small class="hint">{t('noBinaryHint')}</small>
            {/if}
          </label>
          <label>
            <span>{t('newInstanceConfig')}</span>
            <select bind:value={form.configName} on:change={handleProfileChange}>
              <option value="">-- {t('selectProfile')} --</option>
              {#each profileList as prof}
                <option value={prof.name}>{prof.name}</option>
              {/each}
            </select>
            {#if profileList.length === 0}
              <small class="hint">{t('noProfileHint')}</small>
            {/if}
            {#if profileWarnings.length > 0}
              {#each profileWarnings as warning}
                <small class="hint">{warning}</small>
              {/each}
            {/if}
          </label>
          <label>
            <span>{t('mode')}</span>
            <select bind:value={form.mode}>
              <option value="client">{t('modeClient')}</option>
              <option value="server">{t('modeServer')}</option>
            </select>
          </label>
          <label>
            <span>{t('instanceWorkDir')}</span>
            <input bind:value={form.workDir} type="text" />
          </label>
          <label>
            <span>{t('newInstanceArgs')}</span>
            <input bind:value={form.args} type="text" placeholder={t('argsPlaceholder')} />
          </label>
        </div>
        <div class="section-card">
          <button class="section-toggle" on:click={() => (showTunSection = !showTunSection)}>
            <span>{showTunSection ? '▼' : '▶'}</span>
            <span>{t('sectionTunSettings')}</span>
          </button>
          {#if showTunSection}
            <div class="section-body form-grid section-grid">
              <label>
                <span>{t('tunName')}</span>
                <input bind:value={form.tunName} type="text" />
              </label>
              <label>
                <span>{t('tunIp')}</span>
                <input bind:value={form.tunIp} type="text" placeholder={t('tunIpPlaceholder')} />
              </label>
              <label>
                <span>{t('tunGw')}</span>
                <input bind:value={form.tunGw} type="text" placeholder={t('tunGwPlaceholder')} />
              </label>
              <label>
                <span>{t('tunMask')}</span>
                <input bind:value={form.tunMask} type="text" placeholder="e.g. /30 or 255.255.255.252" />
              </label>
              <label>
                <span>{t('tunMux')}</span>
                <input bind:value={form.tunMux} min="0" type="number" />
              </label>
              <div class="checkbox-grid full-span">
                <label class="checkbox-field"><input bind:checked={form.tunVnet} type="checkbox" /> <span>{t('tunVnet')}</span></label>
                <label class="checkbox-field"><input bind:checked={form.tunHost} type="checkbox" /> <span>{t('tunHost')}</span></label>
                <label class="checkbox-field"><input bind:checked={form.tunProtect} type="checkbox" /> <span>{t('tunProtect')}</span></label>
              </div>
            </div>
          {/if}
        </div>
        <div class="section-card">
          <button class="section-toggle" on:click={() => (showAdvancedSection = !showAdvancedSection)}>
            <span>{showAdvancedSection ? '▼' : '▶'}</span>
            <span>{t('sectionAdvanced')}</span>
          </button>
          {#if showAdvancedSection}
            <div class="section-body form-grid section-grid">
              <div class="checkbox-grid full-span">
                <label class="checkbox-field"><input bind:checked={form.lwip} type="checkbox" /> <span>{t('lwip')}</span></label>
                <label class="checkbox-field"><input bind:checked={form.vbgp} type="checkbox" /> <span>{t('vbgp')}</span></label>
                <label class="checkbox-field"><input bind:checked={form.tuiEnabled} type="checkbox" /> <span>{t('tuiEnabled')}</span></label>
              </div>
              <label>
                <span>{t('bypass')}</span>
                <input bind:value={form.bypass} type="text" />
              </label>
              <label>
                <span>{t('dnsRules')}</span>
                <input bind:value={form.dnsRules} type="text" />
              </label>
              <label class="full-span">
                <span>{t('virr')}</span>
                <input bind:value={form.virr} type="text" />
              </label>
            </div>
          {/if}
        </div>
        <div class="dialog-actions">
          <button on:click={closeInstanceModal}>{t('cancel')}</button>
          <button class="accent" disabled={savingInstance} on:click={submitInstance}>{isEditing() ? t('update') : t('create')}</button>
        </div>
      </div>
    </div>
  {/if}
</section>

<style>
  .page { display: grid; gap: 1rem; }
  .header, .card-head, .actions, .meta, .status-card { display: flex; }
  .header { justify-content: space-between; align-items: flex-start; gap: 1rem; }
  h1 { margin: 0 0 0.35rem; font-size: 1.7rem; }
  p, small { color: #8b949e; }
  p { margin: 0; }
  .card, .ghost, button { border: 1px solid #30363d; border-radius: 14px; }
  .card { background: #161b22; padding: 1rem; }
  .status-card { gap: 2rem; justify-content: space-between; }
  .status-card > div { display: grid; gap: 0.4rem; }
  .hint-card { display: grid; gap: 0.35rem; color: #8b949e; }
  .label { color: #8b949e; font-size: 0.85rem; }
  strong { font-size: 1.1rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }
  .instance-card { cursor: pointer; display: grid; gap: 1rem; }
  .instance-card:hover { border-color: #58a6ff; }
  .card-head { justify-content: space-between; gap: 1rem; align-items: flex-start; }
  h3 { margin: 0 0 0.3rem; }
  .meta { flex-direction: column; gap: 0.35rem; color: #c9d1d9; font-size: 0.9rem; }
  .stats-row { display: flex; flex-wrap: wrap; gap: 0.45rem; }
  .chip { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 0.25rem 0.6rem; font-size: 0.78rem; color: #c9d1d9; font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }
  .actions { gap: 0.65rem; }
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(1, 4, 9, 0.7);
    display: grid;
    place-items: center;
    z-index: 40;
  }
  .dialog {
    width: min(720px, calc(100vw - 2rem));
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
  .form-grid {
    display: grid;
    gap: 0.85rem;
  }
  .section-card {
    border: 1px solid #30363d;
    border-radius: 12px;
    overflow: hidden;
    background: #11161d;
  }
  .section-toggle {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    justify-content: flex-start;
    padding: 0.95rem 1rem;
    border: 0;
    border-bottom: 1px solid #30363d;
    border-radius: 0;
    background: #11161d;
    font-weight: 600;
  }
  .section-body {
    padding: 1rem;
  }
  .section-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  label {
    display: grid;
    gap: 0.35rem;
  }
  .checkbox-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 0.75rem;
  }
  .checkbox-field {
    display: flex;
    align-items: center;
    gap: 0.55rem;
  }
  .checkbox-field span {
    color: #c9d1d9;
  }
  .full-span {
    grid-column: 1 / -1;
  }
  label span {
    color: #8b949e;
    font-size: 0.9rem;
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.65rem;
  }
  input, select {
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.8rem;
  }
  select { cursor: pointer; }
  small.hint { color: #d29922; font-size: 0.8rem; }
  button, .ghost {
    background: #21262d;
    color: #c9d1d9;
    padding: 0.65rem 0.95rem;
    cursor: pointer;
  }
  .accent { background: #0d419d; border-color: #0d419d; }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  @media (max-width: 680px) {
    .section-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
