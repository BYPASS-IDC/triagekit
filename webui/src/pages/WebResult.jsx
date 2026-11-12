import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import SeverityBar from '../components/SeverityBar'
import SideNav from '../components/SideNav'
import FindingList from '../components/FindingList'

export default function WebResult() {
  const data = useMemo(() => {
    try { return JSON.parse(sessionStorage.getItem('tk:webscan') || 'null') } catch { return null }
  }, [])
  if (!data) return <div className="alert">No web scan loaded. <Link to="/">Back</Link></div>

  const counts = data.counts || {}
  const sections = [
    { id: 'playbook', label: 'Playbook', count: (data.playbook || []).length },
    { id: 'findings', label: 'Findings', count: (data.findings || []).length },
    { id: 'network', label: 'Network', count: (data.network || []).length },
    { id: 'js', label: 'JavaScript', count: (data.js_files || []).length },
    { id: 'cookies', label: 'Cookies', count: (data.cookies || []).length },
    { id: 'forms', label: 'Forms', count: (data.forms || []).length },
    { id: 'endpoints', label: 'Endpoints', count: (data.endpoints || []).length },
  ]

  function copy() {
    navigator.clipboard.writeText(data.markdown || '')
  }
  function exp() {
    const blob = new Blob([data.markdown || ''], { type: 'text/markdown' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'triagekit-webscan.md'
    a.click()
  }

  return (
    <div>
      <div className="result-head">
        <Link to="/" className="back">← Dashboard</Link>
        <h1>Website security adviser</h1>
        <div className="chip">{data.url}</div>
        <p className="verdict">{data.summary}</p>
      </div>

      <div className="stat-grid">
        <div className="stat"><div className="label">Score</div><div className="big">{data.score}<span>/100</span></div><div className="sub">Grade {data.grade}</div></div>
        <div className="stat"><div className="label">Network</div><div className="big">{(data.network || []).length}</div></div>
        <div className="stat"><div className="label">JS / Forms</div><div className="big">{(data.js_files || []).length} / {(data.forms || []).length}</div></div>
        <div className="stat"><div className="label">Findings</div><div className="big">{(data.findings || []).length}</div></div>
      </div>
      <SeverityBar counts={counts} />

      <div className="workspace">
        <SideNav sections={sections} onCopy={copy} onExport={exp} />
        <div className="content">
          <section className="panel" id="playbook">
            <h2>Remediation playbook</h2>
            <FindingList findings={(data.playbook || []).map((p) => ({
              severity: p.severity, category: `P${p.priority}`, title: p.title,
              detail: p.why, recommendation: p.fix, endpoint: p.where, cwe: p.cwe,
            }))} idPrefix="pb" />
          </section>
          <section className="panel" id="findings">
            <h2>Findings</h2>
            <FindingList findings={data.findings || []} />
          </section>
          <section className="panel" id="network">
            <h2>Network traffic</h2>
            <div className="list">
              {(data.network || []).slice(0, 80).map((n, i) => (
                <div className="row" key={i}><code>{n.method} {n.url}</code> <span>{n.status} · {n.bytes}B</span></div>
              ))}
            </div>
          </section>
          <section className="panel" id="js">
            <h2>JavaScript</h2>
            <div className="list">
              {(data.js_files || []).map((j, i) => (
                <div className="row" key={i}><code>{j.url}</code> <span>{j.bytes}B · signals {j.findings}</span></div>
              ))}
            </div>
          </section>
          <section className="panel" id="cookies">
            <h2>Cookies</h2>
            <div className="list">
              {(data.cookies || []).map((c, i) => (
                <div className="row" key={i}>
                  <code>{c.name}</code>
                  <span>
                    {c.secure ? 'Secure ' : ''}{c.httponly ? 'HttpOnly ' : ''}{c.samesite ? `SameSite=${c.samesite}` : 'no SameSite'}
                  </span>
                </div>
              ))}
            </div>
          </section>
          <section className="panel" id="forms">
            <h2>Forms</h2>
            <div className="list">
              {(data.forms || []).map((f, i) => (
                <div className="row" key={i}><code>{f.method} {f.action}</code><span>{(f.inputs || []).join(', ')}</span></div>
              ))}
            </div>
          </section>
          <section className="panel" id="endpoints">
            <h2>Endpoints</h2>
            <div className="list">
              {(data.endpoints || []).slice(0, 120).map((e, i) => (
                <div className="row" key={i}><code>{e.method} {e.path}</code><span>{e.status} · {e.source}</span></div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}
