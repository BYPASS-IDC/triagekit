export default function SeverityBar({ counts = {} }) {
  const items = [
    ['crit', counts.critical || 0, 'Critical'],
    ['high', counts.high || 0, 'High'],
    ['med', counts.medium || 0, 'Medium'],
    ['low', counts.low || 0, 'Low'],
  ]
  return (
    <div className="sev-bar">
      {items.map(([k, n, label]) => (
        <div className="sev-chip" key={k}>
          <span className={`dot ${k}`} />
          <strong>{n}</strong>
          <span>{label}</span>
        </div>
      ))}
    </div>
  )
}
