const TOKEN_KEY = 'openppp2.manager.token'
const state = { page: 'overview', status: null, users: [], servers: [], subscriptions: [] }

const content = document.querySelector('#content')
const loginDialog = document.querySelector('#loginDialog')
const editorDialog = document.querySelector('#editorDialog')
const editorForm = document.querySelector('#editorForm')
const dialogBody = document.querySelector('#dialogBody')
const dialogTitle = document.querySelector('#dialogTitle')
let submitEditor = null

function token() { return localStorage.getItem(TOKEN_KEY) || '' }
function managedMode() { return state.status?.managed === true }
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]))
}
function formatBytes(value) {
  const n = Number(value || 0)
  if (n === 0) return '不限'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let current = n, index = 0
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index++ }
  return `${current.toFixed(current >= 10 ? 1 : 2)} ${units[index]}`
}
function formatDate(seconds) {
  if (!seconds) return '不限'
  return new Date(Number(seconds) * 1000).toLocaleString()
}
function toast(message, error = false) {
  const el = document.querySelector('#toast')
  el.textContent = message
  el.className = error ? 'show error' : 'show'
  clearTimeout(toast.timer)
  toast.timer = setTimeout(() => { el.className = '' }, 2800)
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}), Authorization: `Bearer ${token()}` }
  if (options.body && typeof options.body !== 'string') {
    headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(options.body)
  }
  const response = await fetch(`/api/v1${path}`, { ...options, headers })
  const type = response.headers.get('content-type') || ''
  const payload = type.includes('json') ? await response.json() : await response.text()
  if (!response.ok) {
    if (response.status === 401) showLogin()
    throw new Error(payload?.error || payload || `${response.status} ${response.statusText}`)
  }
  return payload
}

function setConnected(connected) {
  document.querySelector('#connectionDot').classList.toggle('online', connected)
  document.querySelector('#connectionText').textContent = connected ? '已连接' : '未连接'
}
function showLogin() {
  setConnected(false)
  if (!loginDialog.open) loginDialog.showModal()
}

async function loadAll() {
  try {
    const [status, users, servers, subscriptions] = await Promise.all([
      api('/status'), api('/users'), api('/servers'), api('/subscriptions'),
    ])
    Object.assign(state, { status, users, servers, subscriptions })
    setConnected(true)
    document.querySelector('#lastUpdated').textContent = new Date().toLocaleTimeString()
    render()
    return null
  } catch (error) {
    setConnected(false)
    if (token()) toast(error.message, true)
    return error
  }
}

function render() {
  const managed = managedMode()
  document.querySelector('#usersNav').hidden = !managed
  document.querySelector('#serversNav').textContent = managed ? 'PPP 节点' : '订阅节点'
  if (!managed && state.page === 'users') state.page = 'subscriptions'
  document.querySelectorAll('nav button').forEach((button) => button.classList.toggle('active', button.dataset.page === state.page))
  const titles = { overview: '总览', users: '用户', servers: managed ? 'PPP 节点' : '订阅节点', subscriptions: '订阅' }
  document.querySelector('#pageTitle').textContent = titles[state.page]
  if (state.page === 'overview') renderOverview()
  if (state.page === 'users') renderUsers()
  if (state.page === 'servers') renderServers()
  if (state.page === 'subscriptions') renderSubscriptions()
}

function renderOverview() {
  const s = state.status || {}
  if (!managedMode()) {
    content.innerHTML = `
      <div class="metrics standalone-metrics">
        <div class="metric"><span>订阅节点</span><strong>${Number(s.servers || 0)}</strong></div>
        <div class="metric"><span>订阅</span><strong>${Number(s.subscriptions || 0)}</strong></div>
      </div>
      <div class="band">
        <div class="toolbar"><h2>订阅节点</h2></div>
        ${serverTable(state.servers.slice(0, 8), false)}
      </div>`
    return
  }
  content.innerHTML = `
    <div class="metrics">
      <div class="metric"><span>用户</span><strong>${Number(s.users || 0)}</strong></div>
      <div class="metric"><span>PPP 节点</span><strong>${Number(s.servers || 0)}</strong></div>
      <div class="metric"><span>在线节点</span><strong>${Number(s.onlineServers || 0)}</strong></div>
      <div class="metric"><span>订阅</span><strong>${Number(s.subscriptions || 0)}</strong></div>
    </div>
    <div class="band">
      <div class="toolbar"><h2>节点状态</h2></div>
      ${serverTable(state.servers.slice(0, 8), false)}
    </div>`
}

function renderUsers() {
  content.innerHTML = `
    <div class="toolbar"><h2>用户列表</h2><button data-action="new-user">新建用户</button></div>
    ${state.users.length ? `<div class="table-wrap"><table><thead><tr><th>GUID</th><th>入站余量</th><th>出站余量</th><th>到期</th><th>QoS</th><th>操作</th></tr></thead><tbody>${state.users.map((u) => `
      <tr><td><code>${escapeHtml(u.Guid)}</code></td><td>${formatBytes(u.IncomingTraffic)}</td><td>${formatBytes(u.OutgoingTraffic)}</td><td>${formatDate(u.ExpiredTime)}</td><td>${u.BandwidthQoS ? `${u.BandwidthQoS} Kbps` : '不限'}</td><td><div class="row-actions"><button class="secondary" data-action="edit-user" data-id="${escapeHtml(u.Guid)}">编辑</button><button class="danger" data-action="delete-user" data-id="${escapeHtml(u.Guid)}">删除</button></div></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">暂无用户</div>'}`
}

function serverTable(servers, actions = true) {
  const managed = managedMode()
  if (!servers.length) return `<div class="empty">暂无${managed ? ' PPP' : '订阅'}节点</div>`
  return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>节点</th><th>客户端地址</th>${managed ? '<th>状态</th>' : ''}<th>加密</th><th>QoS</th>${actions ? '<th>操作</th>' : ''}</tr></thead><tbody>${servers.map((s) => `
    <tr><td>${s.id}</td><td>${escapeHtml(s.name)}</td><td><code>${escapeHtml(s.link)}</code></td>${managed ? `<td><span class="badge ${s.online ? 'ok' : ''}">${s.online ? '在线' : '离线'}</span></td>` : ''}<td>${s.plaintext ? '明文' : `${escapeHtml(s.protocol)} / ${escapeHtml(s.transport)}`}</td><td>${s.bandwidthQoS ? `${s.bandwidthQoS} Kbps` : '不限'}</td>${actions ? `<td><div class="row-actions"><button class="secondary" data-action="edit-server" data-id="${s.id}">编辑</button><button class="danger" data-action="delete-server" data-id="${s.id}">删除</button></div></td>` : ''}</tr>`).join('')}</tbody></table></div>`
}

function renderServers() {
  const title = managedMode() ? 'PPP Managed Server 节点' : '订阅节点'
  content.innerHTML = `<div class="toolbar"><h2>${title}</h2><button data-action="new-server">新建节点</button></div>${serverTable(state.servers)}`
}

function renderSubscriptions() {
  content.innerHTML = `
    <div class="toolbar"><h2>订阅列表</h2><button data-action="new-subscription">新建订阅</button></div>
    ${state.subscriptions.length ? `<div class="table-wrap"><table><thead><tr><th>名称</th><th>用户</th><th>节点</th><th>状态</th><th>地址</th><th>操作</th></tr></thead><tbody>${state.subscriptions.map((s) => `
      <tr><td>${escapeHtml(s.name)}</td><td><code>${escapeHtml(s.userGuid)}</code></td><td>${s.serverIds.length}</td><td><span class="badge ${s.enabled ? 'ok' : 'warn'}">${s.enabled ? '启用' : '停用'}</span></td><td><code>${escapeHtml(s.url)}</code></td><td><div class="row-actions"><button data-action="copy-sub" data-url="${escapeHtml(s.url)}">复制</button><button class="secondary" data-action="preview-sub" data-id="${s.id}">预览</button><button class="secondary" data-action="edit-subscription" data-id="${s.id}">编辑</button><button class="secondary" data-action="rotate-sub" data-id="${s.id}">换 Token</button><button class="danger" data-action="delete-subscription" data-id="${s.id}">删除</button></div></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">暂无订阅</div>'}`
}

function openEditor(title, html, onSubmit) {
  dialogTitle.textContent = title
  dialogBody.innerHTML = html
  submitEditor = onSubmit
  editorDialog.showModal()
}

function userForm(user = {}) {
  const expiryDate = new Date(Number(user.ExpiredTime || 0) * 1000)
  expiryDate.setMinutes(expiryDate.getMinutes() - expiryDate.getTimezoneOffset())
  const expiry = user.ExpiredTime ? expiryDate.toISOString().slice(0, 16) : ''
  return `<div class="form-grid">
    <label><span>GUID（留空自动生成）</span><input name="guid" value="${escapeHtml(user.Guid || '')}" ${user.Guid ? 'readonly' : ''}></label>
    <label><span>到期时间</span><input name="expiry" type="datetime-local" value="${expiry}"></label>
    <label><span>入站额度 GiB（0 不限）</span><input name="incoming" type="number" min="0" step="0.1" value="${Number(user.IncomingTraffic || 0) / 1073741824}"></label>
    <label><span>出站额度 GiB（0 不限）</span><input name="outgoing" type="number" min="0" step="0.1" value="${Number(user.OutgoingTraffic || 0) / 1073741824}"></label>
    <label><span>QoS Kbps（0 不限）</span><input name="qos" type="number" min="0" value="${user.BandwidthQoS || 0}"></label>
  </div>`
}

function serverForm(server = {}) {
  return `<div class="form-grid">
    <label><span>名称</span><input name="name" required value="${escapeHtml(server.name || '')}"></label>
    <label><span>客户端连接 URI</span><input name="link" required placeholder="ppp://vpn.example.com:20000/" value="${escapeHtml(server.link || '')}"></label>
    <label><span>Protocol</span><input name="protocol" value="${escapeHtml(server.protocol || 'aes-128-cfb')}"></label>
    <label><span>Protocol Key</span><input name="protocolKey" value="${escapeHtml(server.protocolKey || '')}"></label>
    <label><span>Transport</span><input name="transport" value="${escapeHtml(server.transport || 'aes-256-cfb')}"></label>
    <label><span>Transport Key</span><input name="transportKey" value="${escapeHtml(server.transportKey || '')}"></label>
    <label><span>kf</span><input name="kf" type="number" value="${server.kf || 154543927}"></label>
    <label><span>kx</span><input name="kx" type="number" value="${server.kx || 128}"></label>
    <label><span>kl</span><input name="kl" type="number" value="${server.kl || 10}"></label>
    <label><span>kh</span><input name="kh" type="number" value="${server.kh || 12}"></label>
    <label><span>默认 QoS Kbps</span><input name="bandwidthQoS" type="number" min="0" value="${server.bandwidthQoS || 0}"></label>
  </div><fieldset><legend>传输选项</legend><div class="checks">
    ${['masked:XOR Masking', 'plaintext:Plaintext', 'deltaEncode:Delta Encode', 'shuffleData:Shuffle Data'].map((item) => { const [key, label] = item.split(':'); return `<label class="check"><input type="checkbox" name="${key}" ${server[key] ? 'checked' : ''}><span>${label}</span></label>` }).join('')}
  </div></fieldset>`
}

function subscriptionForm(sub = {}) {
  const selected = new Set(sub.serverIds || [])
  const userField = managedMode()
    ? `<label><span>用户</span><select name="userGuid" required><option value="">选择用户</option>${state.users.map((u) => `<option value="${escapeHtml(u.Guid)}" ${u.Guid === sub.userGuid ? 'selected' : ''}>${escapeHtml(u.Guid)}</option>`).join('')}</select></label>`
    : `<label><span>客户端 GUID</span><input name="userGuid" required maxlength="36" placeholder="00000000-0000-0000-0000-000000000000" value="${escapeHtml(sub.userGuid || '')}"></label>`
  return `<div class="form-grid">
    <label><span>名称</span><input name="name" required value="${escapeHtml(sub.name || '')}"></label>
    <label><span>Profile 前缀</span><input name="profilePrefix" value="${escapeHtml(sub.profilePrefix || '')}"></label>
    ${userField}
    <label class="check"><input name="enabled" type="checkbox" ${sub.enabled !== false ? 'checked' : ''}><span>启用公开订阅</span></label>
  </div><fieldset><legend>下发节点</legend><div class="checks">${state.servers.map((s) => `<label class="check"><input type="checkbox" name="serverId" value="${s.id}" ${selected.has(s.id) ? 'checked' : ''}><span>${escapeHtml(s.name)} (${s.online ? '在线' : '离线'})</span></label>`).join('')}</div></fieldset>
  <label><span>移动端 options JSON</span><textarea name="options">${escapeHtml(JSON.stringify(sub.options || { mtu: 1400, blockQuic: true, allowLan: true }, null, 2))}</textarea></label>`
}

function formObject(form) { return Object.fromEntries(new FormData(form).entries()) }
function userPayload(form) {
  const v = formObject(form)
  return { guid: v.guid, incomingTraffic: Math.round(Number(v.incoming || 0) * 1073741824), outgoingTraffic: Math.round(Number(v.outgoing || 0) * 1073741824), expiredTime: v.expiry ? Math.floor(new Date(v.expiry).getTime() / 1000) : 0, bandwidthQoS: Number(v.qos || 0) }
}
function serverPayload(form) {
  const v = formObject(form)
  return { name: v.name, link: v.link, protocol: v.protocol, protocolKey: v.protocolKey, transport: v.transport, transportKey: v.transportKey, kf: Number(v.kf), kx: Number(v.kx), kl: Number(v.kl), kh: Number(v.kh), bandwidthQoS: Number(v.bandwidthQoS || 0), masked: form.elements.masked.checked, plaintext: form.elements.plaintext.checked, deltaEncode: form.elements.deltaEncode.checked, shuffleData: form.elements.shuffleData.checked }
}
function subscriptionPayload(form) {
  const v = formObject(form)
  return { name: v.name, profilePrefix: v.profilePrefix, userGuid: v.userGuid, serverIds: [...form.querySelectorAll('[name=serverId]:checked')].map((el) => Number(el.value)), enabled: form.elements.enabled.checked, options: JSON.parse(v.options || '{}') }
}

content.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]')
  if (!button) return
  const { action, id } = button.dataset
  try {
    if (action === 'new-user') openEditor('新建用户', userForm(), async (form) => api('/users', { method: 'POST', body: userPayload(form) }))
    if (action === 'edit-user') { const item = state.users.find((u) => u.Guid === id); openEditor('编辑用户', userForm(item), async (form) => api(`/users/${encodeURIComponent(id)}`, { method: 'PUT', body: userPayload(form) })) }
    if (action === 'delete-user') { if (!confirm('删除该用户？')) return; await api(`/users/${encodeURIComponent(id)}`, { method: 'DELETE' }) }
    if (action === 'new-server') openEditor('新建 PPP 节点', serverForm(), async (form) => api('/servers', { method: 'POST', body: serverPayload(form) }))
    if (action === 'edit-server') { const item = state.servers.find((s) => s.id === Number(id)); openEditor('编辑 PPP 节点', serverForm(item), async (form) => api(`/servers/${id}`, { method: 'PUT', body: serverPayload(form) })) }
    if (action === 'delete-server') { if (!confirm('删除该 PPP 节点？')) return; await api(`/servers/${id}`, { method: 'DELETE' }) }
    if (action === 'new-subscription') openEditor('新建订阅', subscriptionForm(), async (form) => api('/subscriptions', { method: 'POST', body: subscriptionPayload(form) }))
    if (action === 'edit-subscription') { const item = state.subscriptions.find((s) => s.id === Number(id)); openEditor('编辑订阅', subscriptionForm(item), async (form) => api(`/subscriptions/${id}`, { method: 'PUT', body: subscriptionPayload(form) })) }
    if (action === 'delete-subscription') { if (!confirm('删除该订阅？')) return; await api(`/subscriptions/${id}`, { method: 'DELETE' }) }
    if (action === 'rotate-sub') { if (!confirm('旧订阅地址会立即失效，继续？')) return; await api(`/subscriptions/${id}/rotate-token`, { method: 'POST' }) }
    if (action === 'copy-sub') { await navigator.clipboard.writeText(button.dataset.url); toast('订阅地址已复制'); return }
    if (action === 'preview-sub') { const response = await fetch(`/api/v1/subscriptions/${id}/preview`, { headers: { Authorization: `Bearer ${token()}` } }); const text = await response.text(); openEditor('订阅预览', `<textarea readonly class="subscription-preview">${escapeHtml(text)}</textarea>`, null); return }
    if (!['new-user', 'edit-user', 'new-server', 'edit-server', 'new-subscription', 'edit-subscription', 'copy-sub', 'preview-sub'].includes(action)) { toast('操作完成'); await loadAll() }
  } catch (error) { toast(error.message, true) }
})

editorForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  if (!submitEditor) { editorDialog.close(); return }
  try { await submitEditor(editorForm); editorDialog.close(); toast('保存成功'); await loadAll() } catch (error) { toast(error.message, true) }
})
document.querySelectorAll('[data-dialog-close]').forEach((button) => button.addEventListener('click', () => editorDialog.close()))
editorDialog.addEventListener('close', () => { submitEditor = null })
document.querySelectorAll('nav button').forEach((button) => button.addEventListener('click', () => { state.page = button.dataset.page; render() }))
document.querySelector('#refreshButton').addEventListener('click', loadAll)
document.querySelector('#logoutButton').addEventListener('click', () => { localStorage.removeItem(TOKEN_KEY); showLogin() })
document.querySelector('#loginForm').addEventListener('submit', async (event) => {
  event.preventDefault()
  localStorage.setItem(TOKEN_KEY, document.querySelector('#tokenInput').value.trim())
  const error = await loadAll()
  if (error) document.querySelector('#loginError').textContent = error.message
  else { loginDialog.close(); document.querySelector('#loginError').textContent = '' }
})

if (!token()) showLogin(); else loadAll()
