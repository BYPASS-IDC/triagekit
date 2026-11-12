import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

export default function Home() {
  const nav = useNavigate()
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  async function run(kind, fn) {
    setError('')
    setBusy(kind)
    try {
      const data = await fn()
      sessionStorage.setItem(`tk:${kind}`, JSON.stringify(data))
      nav(`/${kind}`)
    } catch (e) {
      setError(e.message || String(e))
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="home">
      <section className="hero">
        <div className="eyebrow">PR · Repo · Web · AI agent</div>
        <h1>Security intelligence<br />for code and the web</h1>
        <p>Same detection engines. New React control surface.</p>
      </section>

      {error && <div className="alert">{error}</div>}

      <div className="grid-3">
        <form className="card" onSubmit={(e) => {
          e.preventDefault()
          const fd = new FormData(e.target)
          run('triage', () => api.triage(fd.get('repo'), fd.get('number')))
        }}>
          <h2>PR Triage</h2>
          <p className="sub">Multi-stage review for a pull request</p>
          <label>Repository</label>
          <input name="repo" placeholder="owner/repo" required />
          <label>PR number</label>
          <input name="number" type="number" min="1" placeholder="652" required />
          <button className="btn primary" disabled={!!busy}>{busy === 'triage' ? 'Running…' : 'Triage PR'}</button>
        </form>

        <form className="card" onSubmit={(e) => {
          e.preventDefault()
          const fd = new FormData(e.target)
          run('scan', () => api.scan(fd.get('target'), {
            noCve: fd.get('no_cve') === 'on',
            noAgent: fd.get('no_agent') === 'on',
          }))
        }}>
          <h2>Repo / local scan</h2>
          <p className="sub">Static heuristics + OSV + agent</p>
          <label>Target</label>
          <input name="target" placeholder="owner/repo or C:\\path" required />
          <label className="check"><input type="checkbox" name="no_cve" /> Skip CVE</label>
          <label className="check"><input type="checkbox" name="no_agent" /> Skip AI agent</label>
          <button className="btn primary" disabled={!!busy}>{busy === 'scan' ? 'Scanning…' : 'Scan code'}</button>
        </form>

        <form className="card accent" onSubmit={(e) => {
          e.preventDefault()
          const fd = new FormData(e.target)
          run('webscan', () => api.webscan(fd.get('url'), {
            noPaths: fd.get('no_paths') === 'on',
            noAgent: fd.get('no_agent') === 'on',
          }))
        }}>
          <h2>Website adviser</h2>
          <p className="sub">Leaks · probes · JS · cookies · playbook</p>
          <label>URL</label>
          <input name="url" placeholder="https://example.com" required />
          <label className="check"><input type="checkbox" name="no_paths" /> Skip path checks</label>
          <label className="check"><input type="checkbox" name="no_agent" /> Skip AI agent</label>
          <button className="btn primary" disabled={!!busy}>{busy === 'webscan' ? 'Scanning…' : 'Scan website'}</button>
        </form>
      </div>
    </div>
  )
}
