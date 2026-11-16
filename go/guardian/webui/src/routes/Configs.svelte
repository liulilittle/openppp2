<script>
  import { onMount } from 'svelte'
  import { deleteProfile, getProfile, getProfileBackups, getProfiles, restoreProfile, saveProfile, validateProfile } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import Empty from '../lib/components/Empty.svelte'
  import ConfirmDialog from '../lib/components/ConfirmDialog.svelte'

  export let notify

  let profiles = []
  let selected = ''
  let rawContent = ''
  let generatedContent = ''
  let backups = []
  let validation = ''
  let newProfileName = ''
  let showDelete = false
  let activeEditor = 'form'
  let form = getDefaultForm()
  let editorLines
  let editorRaw
  let sections = {
    basic: true,
    server: false,
    client: false,
    encryption: false,
    network: false,
    telemetry: false,
  }

  $: generatedContent = formToJson(form)
  $: lineNumbers = Array.from({ length: Math.max(1, (activeEditor === 'raw' ? rawContent : generatedContent).split('\n').length) }, (_, index) => index + 1).join('\n')

  function getDefaultForm() {
    return {
      threads: 0,
      serverTcpPort: 0, serverWsPort: 0, serverBackend: '',
      clientServerUri: '', clientGuid: '',
      kf: 154, kx: 128, kl: 10, kh: 12, sb: 1000,
      protocol: 'aes-128-cfb', protocolKey: '',
      transport: 'aes-256-cfb', transportKey: '',
      masked: true, plaintext: false, deltaEncode: false, shuffleData: false,
      tcpTurbo: false, tcpFastOpen: false,
      muxKeepalive: 0, muxConnectTimeout: 0,
      wsHost: '', wsPath: '',
      telemetryEnabled: false, telemetryLevel: 0,
      telemetryCount: false, telemetrySpan: false,
      telemetryConsoleLog: true, telemetryConsoleMetric: true, telemetryConsoleSpan: true,
    }
  }

  function formToJson(form) {
    const json = {}

    if (form.threads) {
      json.concurrent = { threads: form.threads }
    }

    const server = {}
    if (form.serverTcpPort) server.listen = { ...server.listen, tcp: form.serverTcpPort }
    if (form.serverWsPort) server.listen = { ...server.listen, ws: form.serverWsPort }
    if (form.serverBackend) server.backend = form.serverBackend
    if (Object.keys(server).length > 0) json.server = server

    const client = {}
    if (form.clientServerUri) client.server = form.clientServerUri
    if (form.clientGuid) client.guid = form.clientGuid
    if (Object.keys(client).length > 0) json.client = client

    const key = {}
    if (form.kf !== undefined && form.kf !== '') key.kf = Number(form.kf)
    if (form.kx !== undefined && form.kx !== '') key.kx = Number(form.kx)
    if (form.kl !== undefined && form.kl !== '') key.kl = Number(form.kl)
    if (form.kh !== undefined && form.kh !== '') key.kh = Number(form.kh)
    if (form.sb !== undefined && form.sb !== '') key.sb = Number(form.sb)
    if (form.protocol) key.protocol = form.protocol
    if (form.protocolKey) key['protocol-key'] = form.protocolKey
    if (form.transport) key.transport = form.transport
    if (form.transportKey) key['transport-key'] = form.transportKey
    if (form.masked !== undefined) key.masked = form.masked
    if (form.plaintext !== undefined) key.plaintext = form.plaintext
    if (form.deltaEncode !== undefined) key['delta-encode'] = form.deltaEncode
    if (form.shuffleData !== undefined) key['shuffle-data'] = form.shuffleData
    if (Object.keys(key).length > 0) json.key = key

    const tcp = {}
    if (form.tcpTurbo !== undefined) tcp.turbo = form.tcpTurbo
    if (form.tcpFastOpen !== undefined) tcp['fast-open'] = form.tcpFastOpen
    if (Object.keys(tcp).length > 0) json.tcp = tcp

    const mux = {}
    if (form.muxKeepalive) mux.keepalive = form.muxKeepalive
    if (form.muxConnectTimeout) mux['connect-timeout'] = form.muxConnectTimeout
    if (Object.keys(mux).length > 0) json.mux = mux

    const ws = {}
    if (form.wsHost) ws.host = form.wsHost
    if (form.wsPath) ws.path = form.wsPath
    if (Object.keys(ws).length > 0) json.websocket = ws

    const telemetry = {}
    if (form.telemetryEnabled !== undefined) telemetry.enabled = form.telemetryEnabled
    if (form.telemetryLevel !== undefined && form.telemetryLevel !== null && form.telemetryLevel !== '') telemetry.level = Number(form.telemetryLevel)
    if (form.telemetryCount !== undefined) telemetry.count = form.telemetryCount
    if (form.telemetrySpan !== undefined) telemetry.span = form.telemetrySpan
    if (form.telemetryConsoleLog !== undefined) telemetry['console-log'] = form.telemetryConsoleLog
    if (form.telemetryConsoleMetric !== undefined) telemetry['console-metric'] = form.telemetryConsoleMetric
    if (form.telemetryConsoleSpan !== undefined) telemetry['console-span'] = form.telemetryConsoleSpan
    if (Object.keys(telemetry).length > 0) json.telemetry = telemetry

    return JSON.stringify(json, null, 2)
  }

  function jsonToForm(jsonStr) {
    const next = getDefaultForm()
    try {
      const json = JSON.parse(jsonStr)
      next.threads = json.concurrent?.threads || 0
      next.serverTcpPort = json.server?.listen?.tcp || 0
      next.serverWsPort = json.server?.listen?.ws || 0
      next.serverBackend = json.server?.backend || ''

      next.clientServerUri = json.client?.server || ''
      next.clientGuid = json.client?.guid || ''

      next.kf = json.key?.kf ?? 154
      next.kx = json.key?.kx ?? 128
      next.kl = json.key?.kl ?? 10
      next.kh = json.key?.kh ?? 12
      next.sb = json.key?.sb ?? 1000
      next.protocol = json.key?.protocol || 'aes-128-cfb'
      next.protocolKey = json.key?.['protocol-key'] || ''
      next.transport = json.key?.transport || 'aes-256-cfb'
      next.transportKey = json.key?.['transport-key'] || ''
      next.masked = json.key?.masked ?? true
      next.plaintext = json.key?.plaintext ?? false
      next.deltaEncode = json.key?.['delta-encode'] ?? false
      next.shuffleData = json.key?.['shuffle-data'] ?? false

      next.tcpTurbo = json.tcp?.turbo ?? false
      next.tcpFastOpen = json.tcp?.['fast-open'] ?? false

      next.muxKeepalive = json.mux?.keepalive || 0
      next.muxConnectTimeout = json.mux?.['connect-timeout'] || 0

      next.wsHost = json.websocket?.host || ''
      next.wsPath = json.websocket?.path || ''

      next.telemetryEnabled = json.telemetry?.enabled ?? false
      next.telemetryLevel = json.telemetry?.level ?? 0
      next.telemetryCount = json.telemetry?.count ?? false
      next.telemetrySpan = json.telemetry?.span ?? false
      next.telemetryConsoleLog = json.telemetry?.['console-log'] ?? true
      next.telemetryConsoleMetric = json.telemetry?.['console-metric'] ?? true
      next.telemetryConsoleSpan = json.telemetry?.['console-span'] ?? true
    } catch {
      return null
    }
    return next
  }

  function toggleSection(key) {
    sections = { ...sections, [key]: !sections[key] }
  }

  function syncLineNumbersScroll() {
    if (editorLines && editorRaw) {
      editorLines.scrollTop = editorRaw.scrollTop
    }
  }

  function getCurrentJsonString() {
    return activeEditor === 'raw' ? rawContent : generatedContent
  }

  function switchEditor(mode) {
    if (mode === activeEditor) return

    if (mode === 'raw') {
      rawContent = generatedContent
      activeEditor = 'raw'
      return
    }

    const parsed = jsonToForm(rawContent)
    if (!parsed) {
      notify('error', t('validationFailed'), 'Invalid JSON')
      return
    }

    form = parsed
    activeEditor = 'form'
  }

  async function selectProfile(name) {
    selected = name
    validation = ''
    const profile = await getProfile(name)
    rawContent = profile?.content || '{\n\n}'
    form = jsonToForm(rawContent) || getDefaultForm()
    backups = await getProfileBackups(name) || []
  }

  async function loadProfiles() {
    profiles = await getProfiles() || []
    if (!selected && profiles[0]?.name) {
      await selectProfile(profiles[0].name)
    }
  }

  async function save() {
    if (!selected) return
    try {
      const jsonString = getCurrentJsonString()
      await saveProfile(selected, jsonString)
      notify('success', t('profileSaved'), `${selected}`)
      await loadProfiles()
      await selectProfile(selected)
    } catch (error) {
      notify('error', t('saveFailed'), error.message)
    }
  }

  async function validate() {
    try {
      const result = await validateProfile(getCurrentJsonString())
      validation = JSON.stringify(result, null, 2)
      notify('success', t('validationComplete'), t('validationFinished'))
    } catch (error) {
      validation = error.message
      notify('error', t('validationFailed'), error.message)
    }
  }

  async function createProfile() {
    const name = newProfileName.trim()
    if (!name) return
    try {
      await saveProfile(name, JSON.stringify(formToJson(getDefaultForm()), null, 2))
      newProfileName = ''
      await loadProfiles()
      await selectProfile(name)
      notify('success', t('profileCreated'), `${name}`)
    } catch (error) {
      notify('error', t('createFailed'), error.message)
    }
  }

  async function confirmDelete() {
    try {
      await deleteProfile(selected)
      notify('success', t('profileDeleted'), `${selected}`)
    selected = ''
    rawContent = ''
    form = getDefaultForm()
      showDelete = false
      await loadProfiles()
    } catch (error) {
      notify('error', t('deleteFailed'), error.message)
    }
  }

  async function restore(backupId) {
    try {
      await restoreProfile(selected, backupId)
      notify('success', t('backupRestored'), `${backupId}`)
      await selectProfile(selected)
    } catch (error) {
      notify('error', t('restoreFailed'), error.message)
    }
  }

  onMount(async () => {
    try {
      await loadProfiles()
    } catch (error) {
      notify('error', t('failedToLoadProfiles'), error.message)
    }
  })
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('configsTitle')}</h1>
      <p>{t('configsManageDesc')}</p>
    </div>
  </div>

  <div class="layout">
    <aside class="card sidebar">
      <div class="sidebar-tools">
        <input bind:value={newProfileName} placeholder={t('newProfilePlaceholder')} />
        <button on:click={createProfile}>{t('add')}</button>
      </div>
      <div class="profile-list">
        {#if profiles.length === 0}
          <Empty message={t('noProfilesAvailable')} />
        {:else}
          {#each profiles as profile}
            <button class:selected={profile.name === selected} class="profile-item" on:click={() => selectProfile(profile.name)}>
              <strong>{profile.name}</strong>
              <small>{new Date(profile.updatedAt).toLocaleString()}</small>
            </button>
          {/each}
        {/if}
      </div>
      <button class="danger" on:click={() => (showDelete = true)} disabled={!selected}>{t('deleteProfile')}</button>
    </aside>

    <div class="main">
      <div class="card editor-card">
        <div class="editor-head">
          <div class="editor-head-title">
            <h3>{selected || t('noProfileSelected')}</h3>
            {#if selected}
              <div class="editor-tabs">
                <button class:active={activeEditor === 'form'} class="tab" on:click={() => switchEditor('form')}>{t('configFormEditor')}</button>
                <button class:active={activeEditor === 'raw'} class="tab" on:click={() => switchEditor('raw')}>{t('configRawEditor')}</button>
              </div>
            {/if}
          </div>
          <div class="actions">
            <button on:click={validate} disabled={!selected}>{t('validate')}</button>
            <button class="accent" on:click={save} disabled={!selected}>{t('save')}</button>
          </div>
        </div>

        {#if selected}
          {#if activeEditor === 'form'}
            <div class="form-editor">
              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('basic')}>
                  <span>{sections.basic ? '▼' : '▶'}</span>
                  <span>{t('sectionBasic')}</span>
                </button>
                {#if sections.basic}
                  <div class="section-body fields-grid">
                    <label class="field">
                      <span>{t('threads')}</span>
                      <input bind:value={form.threads} min="0" type="number" />
                    </label>
                  </div>
                {/if}
              </section>

              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('server')}>
                  <span>{sections.server ? '▼' : '▶'}</span>
                  <span>{t('sectionServer')}</span>
                </button>
                {#if sections.server}
                  <div class="section-body fields-grid">
                    <label class="field">
                      <span>{t('serverTcpPort')}</span>
                      <input bind:value={form.serverTcpPort} min="0" type="number" />
                    </label>
                    <label class="field">
                      <span>{t('serverWsPort')}</span>
                      <input bind:value={form.serverWsPort} min="0" type="number" />
                    </label>
                    <label class="field field-full">
                      <span>{t('serverBackend')}</span>
                      <input bind:value={form.serverBackend} type="text" />
                    </label>
                  </div>
                {/if}
              </section>

              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('client')}>
                  <span>{sections.client ? '▼' : '▶'}</span>
                  <span>{t('sectionClient')}</span>
                </button>
                {#if sections.client}
                  <div class="section-body fields-grid">
                    <label class="field field-full">
                      <span>{t('clientServerUri')}</span>
                      <input bind:value={form.clientServerUri} type="text" />
                    </label>
                    <label class="field field-full">
                      <span>{t('clientGuid')}</span>
                      <input bind:value={form.clientGuid} type="text" />
                    </label>
                  </div>
                {/if}
              </section>

              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('encryption')}>
                  <span>{sections.encryption ? '▼' : '▶'}</span>
                  <span>{t('sectionEncryption')}</span>
                </button>
                {#if sections.encryption}
                  <div class="section-body fields-grid">
                    <label class="field">
                      <span>{t('keyKf')}</span>
                      <input bind:value={form.kf} type="number" />
                    </label>
                    <label class="field">
                      <span>{t('keyKx')}</span>
                      <input bind:value={form.kx} type="number" />
                    </label>
                    <label class="field">
                      <span>{t('keyKl')}</span>
                      <input bind:value={form.kl} type="number" />
                    </label>
                    <label class="field">
                      <span>{t('keyKh')}</span>
                      <input bind:value={form.kh} type="number" />
                    </label>
                    <label class="field">
                      <span>{t('keySb')}</span>
                      <input bind:value={form.sb} type="number" />
                    </label>
                    <label class="field">
                      <span>{t('keyProtocol')}</span>
                      <select bind:value={form.protocol}>
                        <option value="aes-128-cfb">aes-128-cfb</option>
                        <option value="aes-256-cfb">aes-256-cfb</option>
                        <option value="">{t('cipherNone')}</option>
                      </select>
                    </label>
                    <label class="field">
                      <span>{t('keyProtocolKey')}</span>
                      <input bind:value={form.protocolKey} type="text" />
                    </label>
                    <label class="field">
                      <span>{t('keyTransport')}</span>
                      <select bind:value={form.transport}>
                        <option value="aes-128-cfb">aes-128-cfb</option>
                        <option value="aes-256-cfb">aes-256-cfb</option>
                        <option value="">{t('cipherNone')}</option>
                      </select>
                    </label>
                    <label class="field">
                      <span>{t('keyTransportKey')}</span>
                      <input bind:value={form.transportKey} type="text" />
                    </label>
                    <div class="field field-full checkbox-grid">
                      <label class="checkbox-field"><input bind:checked={form.masked} type="checkbox" /> <span>{t('keyMasked')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.deltaEncode} type="checkbox" /> <span>{t('keyDeltaEncode')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.shuffleData} type="checkbox" /> <span>{t('keyShuffleData')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.plaintext} type="checkbox" /> <span>{t('keyPlaintext')}</span></label>
                    </div>
                  </div>
                {/if}
              </section>

              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('network')}>
                  <span>{sections.network ? '▼' : '▶'}</span>
                  <span>{t('sectionNetwork')}</span>
                </button>
                {#if sections.network}
                  <div class="section-body fields-grid">
                    <label class="field">
                      <span>{t('muxKeepalive')}</span>
                      <input bind:value={form.muxKeepalive} min="0" type="number" />
                    </label>
                    <label class="field">
                      <span>{t('muxConnectTimeout')}</span>
                      <input bind:value={form.muxConnectTimeout} min="0" type="number" />
                    </label>
                    <label class="field field-full">
                      <span>{t('wsHost')}</span>
                      <input bind:value={form.wsHost} type="text" />
                    </label>
                    <label class="field field-full">
                      <span>{t('wsPath')}</span>
                      <input bind:value={form.wsPath} type="text" />
                    </label>
                    <div class="field field-full checkbox-grid">
                      <label class="checkbox-field"><input bind:checked={form.tcpTurbo} type="checkbox" /> <span>{t('tcpTurbo')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.tcpFastOpen} type="checkbox" /> <span>{t('tcpFastOpen')}</span></label>
                    </div>
                  </div>
                {/if}
              </section>

              <section class="section-card">
                <button class="section-toggle" on:click={() => toggleSection('telemetry')}>
                  <span>{sections.telemetry ? '▼' : '▶'}</span>
                  <span>{t('sectionTelemetry')}</span>
                </button>
                {#if sections.telemetry}
                  <div class="section-body fields-grid">
                    <label class="field">
                      <span>{t('telemetryLevel')}</span>
                      <select bind:value={form.telemetryLevel}>
                        <option value="0">0 · INFO</option>
                        <option value="1">1 · VERB</option>
                        <option value="2">2 · DEBUG</option>
                        <option value="3">3 · TRACE</option>
                      </select>
                    </label>
                    <div class="field field-full checkbox-grid">
                      <label class="checkbox-field"><input bind:checked={form.telemetryEnabled} type="checkbox" /> <span>{t('verbose')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.telemetryCount} type="checkbox" /> <span>{t('telemetryCount')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.telemetrySpan} type="checkbox" /> <span>{t('telemetrySpan')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.telemetryConsoleLog} type="checkbox" /> <span>{t('telemetryConsoleLog')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.telemetryConsoleMetric} type="checkbox" /> <span>{t('telemetryConsoleMetric')}</span></label>
                      <label class="checkbox-field"><input bind:checked={form.telemetryConsoleSpan} type="checkbox" /> <span>{t('telemetryConsoleSpan')}</span></label>
                    </div>
                  </div>
                {/if}
              </section>
            </div>
          {:else}
            <div class="editor-wrap">
              <textarea bind:this={editorLines} class="lines" readonly value={lineNumbers}></textarea>
              <textarea bind:this={editorRaw} bind:value={rawContent} class="editor" on:scroll={syncLineNumbersScroll} spellcheck="false"></textarea>
            </div>
          {/if}
        {:else}
          <Empty message={t('chooseOrCreateProfile')} />
        {/if}
      </div>

      <div class="card">
        <h3>{t('validationResult')}</h3>
        <pre>{validation || t('validationHint')}</pre>
      </div>

      <div class="card">
        <h3>{t('backupsTitle')}</h3>
        {#if !selected}
          <Empty message={t('selectProfileToViewBackups')} />
        {:else if backups.length === 0}
          <Empty message={t('noBackupsFound')} />
        {:else}
          <div class="backup-list">
            {#each backups as backup}
              <div class="backup-item">
                <div>
                  <strong>{backup.id}</strong>
                  <small>{new Date(backup.createdAt).toLocaleString()} · {backup.size} {t('bytes')}</small>
                </div>
                <button on:click={() => restore(backup.id)}>{t('restore')}</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>
  </div>

  <ConfirmDialog
    open={showDelete}
    title={t('deleteProfileTitle')}
    message={`${selected ? `${selected} · ` : ''}${t('deleteProfileMessage')}`}
    confirmText={t('delete')}
    on:cancel={() => (showDelete = false)}
    on:confirm={confirmDelete}
  />
</section>

<style>
  .page, .main, .form-editor { display: grid; gap: 1rem; }
  .layout { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 1rem; }
  .card, .section-card { background: #161b22; border: 1px solid #30363d; border-radius: 14px; }
  .card { padding: 1rem; }
  h1, h3 { margin: 0; }
  p { margin: 0.35rem 0 0; color: #8b949e; }
  .sidebar { display: grid; gap: 1rem; align-content: start; }
  .sidebar-tools, .editor-head, .actions, .backup-item, .editor-head-title { display: flex; gap: 0.75rem; }
  .sidebar-tools, .editor-head, .backup-item { justify-content: space-between; align-items: center; }
  .editor-head-title { flex-direction: column; align-items: flex-start; }
  .profile-list { display: grid; gap: 0.5rem; max-height: 540px; overflow: auto; }
  .profile-item { display: grid; gap: 0.25rem; text-align: left; }
  .profile-item.selected { border-color: #58a6ff; background: rgba(88, 166, 255, 0.12); }
  .editor-tabs { display: flex; gap: 0.5rem; }
  .tab.active { color: #58a6ff; border-color: #58a6ff; background: rgba(88, 166, 255, 0.12); }
  .editor-wrap { display: grid; grid-template-columns: 56px 1fr; margin-top: 1rem; border: 1px solid #30363d; border-radius: 12px; overflow: hidden; }
  .section-card { overflow: hidden; }
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
  .section-body { padding: 1rem; }
  .fields-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
  .field { display: grid; gap: 0.45rem; }
  .field > span { color: #8b949e; font-size: 0.92rem; }
  .field-full { grid-column: 1 / -1; }
  .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; }
  .checkbox-field { display: flex; align-items: center; gap: 0.55rem; }
  .lines, .editor, pre {
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
    background: #0d1117;
    color: #c9d1d9;
  }
  .lines, .editor {
    min-height: 420px;
    padding: 1rem;
    border: 0;
    resize: vertical;
    outline: none;
  }
  .lines { color: #8b949e; border-right: 1px solid #30363d; text-align: right; overflow: hidden; }
  .editor { width: 100%; }
  pre { margin: 0.9rem 0 0; padding: 1rem; border: 1px solid #30363d; border-radius: 12px; white-space: pre-wrap; }
  .backup-list { display: grid; gap: 0.75rem; margin-top: 1rem; }
  small { color: #8b949e; }
  button, input, select, textarea {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.8rem;
  }
  input, select { width: 100%; }
  .accent { background: #0d419d; border-color: #0d419d; }
  .danger { background: rgba(248, 81, 73, 0.12); border-color: rgba(248, 81, 73, 0.45); }
  @media (max-width: 980px) {
    .layout { grid-template-columns: 1fr; }
    .fields-grid { grid-template-columns: 1fr; }
  }
</style>
