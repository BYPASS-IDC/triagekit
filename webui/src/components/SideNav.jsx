export default function SideNav({ sections = [], onExport, onCopy }) {
  return (
    <aside className="side-nav">
      <div className="side-title">Scan chain</div>
      <ul>
        {sections.map((s) => (
          <li key={s.id}>
            <button type="button" onClick={() => document.getElementById(s.id)?.scrollIntoView({ behavior: 'smooth' })}>
              <span>{s.label}</span>
              {s.count != null && <span className="badge">{s.count}</span>}
            </button>
          </li>
        ))}
      </ul>
      <div className="side-actions">
        {onCopy && <button type="button" className="btn ghost" onClick={onCopy}>Copy report</button>}
        {onExport && <button type="button" className="btn ghost" onClick={onExport}>Export Markdown</button>}
      </div>
    </aside>
  )
}
