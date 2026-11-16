// Quick routing options layered over the rules model. A preset only fills these
// options; each option stays visible and editable, and maps to plain rules plus
// rule-set declarations that the rule list and text view show as well.
import { addRule, listRules, removeRule, setDefaultAction, setRuleAction, setRuleEnabled } from './policyRules.js'

export const LAN_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
export const GEO_SETS = { geosite: 'geosite-cn', geoip: 'geoip-cn' }

export const PRESETS = {
  'split-cn': { defaultAction: 'proxy', lan: true, geosite: true, geoip: true },
  'proxy-all': { defaultAction: 'proxy', lan: true, geosite: false, geoip: false },
  'direct-all': { defaultAction: 'direct', lan: false, geosite: false, geoip: false },
}

const isUrl = (value) => /^https?:\/\//i.test(value)

// geoip-dat / geosite-dat for v2ray .dat files, the text formats otherwise.
export function geoFormat(kind, source) {
  return /\.dat(\?|#|$)/i.test(String(source || '').trim()) ? `${kind}-dat` : `${kind}-text`
}

const directRule = (model, type, value) =>
  listRules(model).find((rule) => rule.type === type && rule.value === value)

export function readOptions(model, policy) {
  const on = (type, value) => {
    const rule = directRule(model, type, value)
    return !!rule && rule.enabled && rule.action === 'direct'
  }
  const source = (name) => {
    const set = policy?.['rule-sets']?.[name]
    return set?.source?.url || set?.source?.path || ''
  }
  return {
    defaultAction: model.defaultAction || 'proxy',
    lan: LAN_RANGES.every((range) => on('cidr', range)),
    geosite: on('set', GEO_SETS.geosite),
    geoip: on('set', GEO_SETS.geoip),
    geositeSource: source(GEO_SETS.geosite),
    geoipSource: source(GEO_SETS.geoip),
  }
}

// Makes one direct rule present and enabled, or removes it.
function ensureDirect(model, type, value, wanted) {
  const rule = directRule(model, type, value)
  if (!wanted) return rule ? removeRule(model, rule.id) : model
  if (!rule) return addRule(model, { action: 'direct', type, value })
  let next = model
  if (rule.action !== 'direct') next = setRuleAction(next, rule.id, 'direct')
  if (!rule.enabled) next = setRuleEnabled(next, rule.id, true)
  return next
}

function withRuleSet(policy, name, kind, source, wanted) {
  const next = structuredClone(policy || { version: 2 })
  const sets = { ...(next['rule-sets'] || {}) }
  const value = String(source || '').trim()
  if (wanted && value) {
    sets[name] = { ...(sets[name] || {}), format: geoFormat(kind, value), tag: sets[name]?.tag || 'cn', source: { [isUrl(value) ? 'url' : 'path']: value } }
  } else if (!wanted) {
    delete sets[name]
  }
  if (Object.keys(sets).length) next['rule-sets'] = sets
  else delete next['rule-sets']
  return next
}

export function applyOptions(model, policy, options) {
  let nextModel = setDefaultAction(model, options.defaultAction)
  for (const range of LAN_RANGES) nextModel = ensureDirect(nextModel, 'cidr', range, options.lan)
  let nextPolicy = policy
  for (const kind of ['geosite', 'geoip']) {
    const name = GEO_SETS[kind]
    nextModel = ensureDirect(nextModel, 'set', name, options[kind])
    nextPolicy = withRuleSet(nextPolicy, name, kind, options[`${kind}Source`], options[kind])
  }
  return { model: nextModel, policy: nextPolicy }
}

// Name of the preset the options equal, or '' for a custom combination.
export function matchPreset(options) {
  const keys = ['defaultAction', 'lan', 'geosite', 'geoip']
  return Object.keys(PRESETS).find((name) => keys.every((key) => PRESETS[name][key] === options[key])) || ''
}

// Options to fill when a preset is chosen, keeping the sources already typed.
export function presetOptions(name, current) {
  return { ...current, ...PRESETS[name] }
}

// Problems that block applying the options: a geo list switched on without a source.
export function optionErrors(options) {
  const errors = {}
  if (options.geosite && !String(options.geositeSource || '').trim()) errors.geosite = 'source'
  if (options.geoip && !String(options.geoipSource || '').trim()) errors.geoip = 'source'
  return errors
}
