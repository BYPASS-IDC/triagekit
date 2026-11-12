export default function FindingList({ findings = [], idPrefix = 'f' }) {
  if (!findings.length) return <p className="muted">No findings.</p>
  return (
    <div className="findings">
      {findings.map((f, i) => (
        <details key={i} className={`finding sev-${f.severity || 'low'}`} id={`${idPrefix}-${i + 1}`} open={i < 5}>
          <summary>
            <span className="sev">{f.severity || 'info'}</span>
            <span className="cat">{f.category || 'general'}</span>
            <span className="title">{f.title || 'Finding'}</span>
          </summary>
          <div className="body">
            <pre>{f.detail || f.description || ''}</pre>
            {f.endpoint && <div className="meta">Path: {f.endpoint}</div>}
            {f.evidence && <div className="meta">Evidence: {String(f.evidence)}</div>}
            {f.cwe && <div className="meta">{f.cwe} · confidence {f.confidence || 'n/a'}</div>}
            {(f.recommendation || f.fix) && (
              <div className="fix">
                <div className="fix-label">What to do</div>
                <p>{f.recommendation || f.fix}</p>
              </div>
            )}
          </div>
        </details>
      ))}
    </div>
  )
}
