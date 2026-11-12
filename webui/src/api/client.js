async function postForm(path, fields) {
  const body = new FormData()
  Object.entries(fields).forEach(([k, v]) => body.append(k, v))
  const res = await fetch(path, { method: 'POST', body })
  const data = await res.json().catch(() => ({}))
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || res.statusText || 'Request failed')
  }
  return data
}

export const api = {
  health: () => fetch('/api/health').then((r) => r.json()),
  triage: (repo, number) => postForm('/api/triage', { repo, number: String(number) }),
  scan: (target, { noCve = false, noAgent = false } = {}) =>
    postForm('/api/scan', {
      target,
      no_cve: noCve ? '1' : '',
      no_agent: noAgent ? '1' : '',
    }),
  webscan: (url, { noPaths = false, noAgent = false } = {}) =>
    postForm('/api/webscan', {
      url,
      no_paths: noPaths ? '1' : '',
      no_agent: noAgent ? '1' : '',
    }),
}
