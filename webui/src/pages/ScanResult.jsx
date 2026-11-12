import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import SeverityBar from '../components/SeverityBar'
import SideNav from '../components/SideNav'
import FindingList from '../components/FindingList'

export default function ScanResult() {
  const data = useMemo(() => {
    try { return JSON.parse(sessionStorage.getItem('tk:scan') || 'null') } catch { return null }
  }, [])
  if (!data) return <div className="alert">No scan loaded. <Link to="/">Back</Link></div>
  const sections = [
    { id: 'findings', label: 'Findings', count: (data.findings || []).length },
    { id: 'cves', label: 'CVEs', count: (data.cve_findings || []).length },
  ]
  return (
    <div>
      <div className="result-head">
        <Link to="/" className="back">← Dashboard</Link>
        <h1>Repository scan</h1>
        <div className="chip">{data.target}</div>
        <p className="verdict">{data.summary}</p>
      </div>
      <div className="stat-grid">
        <div className="stat"><div className="label">Score</div><div className="big">{data.score}<span>/100</span></div><div className="sub">Grade {data.grade}</div></div>
        <div className="stat"><div className="label">Findings</div><div className="big">{(data.findings || []).length}</div></div>
        <div className="stat"><div className="label">CVEs</div><div className="big">{(data.cve_findings || []).length}</div></div>
      </div>
      <SeverityBar counts={data.counts || {}} />
      <div className="workspace">
        <SideNav sections={sections} onCopy={() => navigator.clipboard.writeText(data.markdown || '')}
          onExport={() => { const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([data.markdown||''],{type:'text/markdown'})); a.download='scan.md'; a.click() }} />
        <div className="content">
          <section className="panel" id="findings"><h2>Static findings</h2><FindingList findings={data.findings || []} /></section>
          <section className="panel" id="cves"><h2>CVE / advisories</h2><FindingList findings={data.cve_findings || []} idPrefix="cve" /></section>
        </div>
      </div>
    </div>
  )
}
