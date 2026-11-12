import { useMemo } from 'react'
import { Link } from 'react-router-dom'

export default function TriageResult() {
  const data = useMemo(() => {
    try { return JSON.parse(sessionStorage.getItem('tk:triage') || 'null') } catch { return null }
  }, [])
  if (!data) return <div className="alert">No triage loaded. <Link to="/">Back</Link></div>
  const r = data.result || {}
  return (
    <div>
      <div className="result-head">
        <Link to="/" className="back">← Dashboard</Link>
        <h1>PR Triage</h1>
        <div className="chip">{r.repo}#{r.number}</div>
        <p className="verdict">{r.one_line_verdict || r.summary}</p>
      </div>
      <div className="stat-grid">
        <div className="stat"><div className="label">Risk</div><div className="big">{(r.risk_level || '').toString().toUpperCase()}</div><div className="sub">{r.risk_score}/10</div></div>
        <div className="stat"><div className="label">Security</div><div className="big">{(r.security_findings || []).length}</div></div>
        <div className="stat"><div className="label">Suggestions</div><div className="big">{(r.suggestions || []).length}</div></div>
        <div className="stat"><div className="label">Confidence</div><div className="big">{Math.round((r.confidence || 0) * 100)}%</div></div>
      </div>
      <section className="panel">
        <h2>Full report</h2>
        <pre className="report">{data.markdown}</pre>
        <button className="btn ghost" onClick={() => navigator.clipboard.writeText(data.markdown || '')}>Copy Markdown</button>
      </section>
    </div>
  )
}
