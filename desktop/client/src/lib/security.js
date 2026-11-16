export function redactText(text, urls = []) {
  let result = String(text ?? '')
  for (const url of urls.filter(Boolean)) result = result.split(url).join('[subscription URL]')
  return result.replace(/((?:protocol-key|transport-key|backend-key|password|token)["']?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;]+)/gi, (_, prefix, value) => {
    const quote = ['"', "'"].includes(value[0]) ? value[0] : ''
    return `${prefix}${quote}[redacted]${quote}`
  })
    .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => {
      try { const parsed = new URL(url); return `${parsed.origin}/[redacted]` } catch { return '[URL]' }
    })
}

export function downloadText(name, text, type = 'text/plain;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const anchor = document.createElement('a')
  anchor.href = url; anchor.download = name; anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
