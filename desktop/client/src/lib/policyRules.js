// Structured view of a policy v2 rules file (see docs/guides/POLICY_CLI.md §4).
//
// The file is kept as an ordered list of items so a save rewrites only what the
// user changed: comments, DNS bindings, [dns:*] sections and anything this module
// does not understand round-trip verbatim, and rule order inside each section is
// preserved (the kernel breaks equal-priority ties by declaration order).

export const ACTIONS = ['direct', 'proxy', 'reject']
export const RULE_TYPES = ['suffix', 'exact', 'subdomain', 'keyword', 'regexp', 'cidr', 'set']

// A rule the user switched off is kept in its section as a comment the kernel ignores.
const DISABLED_PREFIX = '# off: '

const CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/
const DOMAIN = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/i
const SET_NAME = /^[A-Za-z0-9_.-]+$/

let nextId = 1
const newId = () => `r${nextId++}`

/** Splits a trailing `# note` off a rule line; only whitespace-preceded `#` starts a note. */
function splitNote(text) {
  const match = /\s#\s?(.*)$/.exec(text)
  return match ? { body: text.slice(0, match.index).trim(), note: match[1].trim() } : { body: text.trim(), note: '' }
}

/** Parses one rule token (`=a.b`, `*.a.b`, `keyword:x`, `regexp:x`, `set:x`, CIDR, suffix). */
export function parseToken(token) {
  if (token.startsWith('=')) return { type: 'exact', value: token.slice(1) }
  if (token.startsWith('*.')) return { type: 'subdomain', value: token.slice(2) }
  if (token.startsWith('keyword:')) return { type: 'keyword', value: token.slice(8) }
  if (token.startsWith('regexp:')) return { type: 'regexp', value: token.slice(7) }
  if (token.startsWith('set:')) return { type: 'set', value: token.slice(4) }
  if (CIDR.test(token)) return { type: 'cidr', value: token }
  return { type: 'suffix', value: token }
}

export function toToken(type, value) {
  switch (type) {
    case 'exact': return `=${value}`
    case 'subdomain': return `*.${value}`
    case 'keyword': return `keyword:${value}`
    case 'regexp': return `regexp:${value}`
    case 'set': return `set:${value}`
    default: return value
  }
}

/** Returns an error message for an invalid rule value, or '' when it is acceptable. */
export function validateRule(type, value, ruleSetNames = []) {
  const text = String(value ?? '').trim()
  if (!text) return 'empty'
  if (/\s/.test(text) && type !== 'regexp') return 'whitespace'
  switch (type) {
    case 'exact':
    case 'suffix':
    case 'subdomain':
      if (/[/:]/.test(text)) return 'domain-only'
      return DOMAIN.test(text) ? '' : 'domain'
    case 'keyword':
      return /[#]/.test(text) ? 'keyword' : ''
    case 'regexp':
      try { new RegExp(text); return '' } catch { return 'regexp' }
    case 'cidr': {
      const match = CIDR.exec(text)
      if (!match) return 'cidr'
      const octets = match.slice(1, 5).map(Number)
      return octets.every((octet) => octet <= 255) && Number(match[5]) <= 32 ? '' : 'cidr'
    }
    case 'set':
      if (!SET_NAME.test(text)) return 'set'
      return ruleSetNames.length && !ruleSetNames.includes(text) ? 'set-unknown' : ''
    default:
      return 'type'
  }
}

function ruleLine(rule) {
  const token = toToken(rule.type, rule.value)
  const body = rule.note ? `${token}  # ${rule.note}` : token
  return rule.enabled ? body : `${DISABLED_PREFIX}${body}`
}

/**
 * Parses rules text into `{ defaultAction, items }`.
 * Items are `{ kind: 'line', text }`, `{ kind: 'section', name }` or
 * `{ kind: 'rule', id, action, type, value, enabled, note, raw }`.
 */
export function parseRules(text) {
  const items = []
  let defaultAction = null
  let section = null
  for (const raw of String(text ?? '').replace(/\r\n?/g, '\n').split('\n')) {
    const trimmed = raw.trim()
    const header = /^\[([^\]]+)\]$/.exec(trimmed)
    if (header) {
      section = header[1].trim()
      items.push({ kind: 'section', name: section, raw })
      continue
    }
    if (section === null) {
      const def = /^default\s+(direct|proxy|reject)\b/.exec(trimmed)
      if (def && defaultAction === null) {
        defaultAction = def[1]
        items.push({ kind: 'default', action: def[1], raw })
        continue
      }
    }
    if (ACTIONS.includes(section) && trimmed) {
      let enabled = true
      let body = trimmed
      if (trimmed.startsWith(DISABLED_PREFIX.trim())) {
        enabled = false
        body = trimmed.slice(DISABLED_PREFIX.trim().length).trim()
      } else if (trimmed.startsWith('#')) {
        items.push({ kind: 'line', text: raw })
        continue
      }
      const { body: token, note } = splitNote(body)
      if (token) {
        const { type, value } = parseToken(token)
        items.push({ kind: 'rule', id: newId(), action: section, type, value, enabled, note, raw })
        continue
      }
    }
    items.push({ kind: 'line', text: raw })
  }
  return { defaultAction, items }
}

/** Serialises a parsed model back to rules text; untouched rules keep their original line. */
export function serializeRules(model) {
  const lines = []
  let wroteDefault = false
  for (const item of model.items) {
    if (item.kind === 'default') {
      if (model.defaultAction) lines.push(model.defaultAction === item.action ? item.raw : `default ${model.defaultAction}`)
      wroteDefault = true
    } else if (item.kind === 'section') {
      lines.push(item.raw ?? `[${item.name}]`)
    } else if (item.kind === 'rule') {
      lines.push(item.raw ?? ruleLine(item))
    } else {
      lines.push(item.text)
    }
  }
  if (!wroteDefault && model.defaultAction) lines.unshift(`default ${model.defaultAction}`)
  let text = lines.join('\n')
  if (!text.endsWith('\n')) text += '\n'
  return text
}

export const listRules = (model) => model.items.filter((item) => item.kind === 'rule')

/** Index after the last item of the last `[action]` section, or -1 when there is none. */
function sectionEnd(items, action) {
  let start = -1
  for (let i = items.length - 1; i >= 0; i -= 1) {
    if (items[i].kind === 'section' && items[i].name === action) { start = i; break }
  }
  if (start < 0) return -1
  let end = start + 1
  while (end < items.length && items[end].kind !== 'section') end += 1
  // Keep trailing blank lines after the rules so section spacing survives.
  while (end - 1 > start && items[end - 1].kind === 'line' && !items[end - 1].text.trim()) end -= 1
  return end
}

function insertRule(items, rule) {
  const next = items.slice()
  const at = sectionEnd(next, rule.action)
  if (at >= 0) {
    next.splice(at, 0, rule)
    return next
  }
  // New action section: after the last action section, before any [dns:*] / other sections.
  let insertAt = next.length
  for (let i = 0; i < next.length; i += 1) {
    if (next[i].kind === 'section' && !ACTIONS.includes(next[i].name)) { insertAt = i; break }
  }
  const previous = next[insertAt - 1]
  const blank = () => ({ kind: 'line', text: '' })
  const block = []
  if (previous && !(previous.kind === 'line' && !previous.text.trim())) block.push(blank())
  block.push({ kind: 'section', name: rule.action }, rule)
  if (insertAt < next.length) block.push(blank())
  next.splice(insertAt, 0, ...block)
  return next
}

export function addRule(model, { action, type, value, note = '' }) {
  const rule = { kind: 'rule', id: newId(), action, type, value: String(value).trim(), enabled: true, note }
  return { ...model, items: insertRule(model.items, rule) }
}

export function removeRule(model, id) {
  return { ...model, items: model.items.filter((item) => item.id !== id) }
}

export function setRuleEnabled(model, id, enabled) {
  return { ...model, items: model.items.map((item) => item.id === id ? { ...item, enabled, raw: undefined } : item) }
}

/** Moves a rule to the end of its new action's section (or a new section). */
export function setRuleAction(model, id, action) {
  const rule = model.items.find((item) => item.id === id)
  if (!rule || rule.action === action) return model
  const moved = { ...rule, action, raw: undefined }
  return { ...model, items: insertRule(model.items.filter((item) => item.id !== id), moved) }
}

export function setDefaultAction(model, action) {
  return { ...model, defaultAction: action }
}

/** Counts enabled rules per action, for summaries. */
export function summarize(model) {
  const counts = { direct: 0, proxy: 0, reject: 0, disabled: 0 }
  for (const rule of listRules(model)) {
    if (!rule.enabled) counts.disabled += 1
    else counts[rule.action] += 1
  }
  return counts
}
