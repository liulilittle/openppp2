export function formatDuration(startedAt, now = Date.now()) {
  if (!startedAt) return '00:00:00'
  const total = Math.max(0, Math.floor((now - startedAt) / 1000))
  const hours = String(Math.floor(total / 3600)).padStart(2, '0')
  const minutes = String(Math.floor(total / 60) % 60).padStart(2, '0')
  const seconds = String(total % 60).padStart(2, '0')
  return `${hours}:${minutes}:${seconds}`
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return ''
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`
}

export function formatDateTime(value) {
  if (!value) return ''
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(new Date(value))
}
