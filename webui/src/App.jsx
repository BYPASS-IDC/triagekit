import { Routes, Route, NavLink } from 'react-router-dom'
import Home from './pages/Home'
import WebResult from './pages/WebResult'
import ScanResult from './pages/ScanResult'
import TriageResult from './pages/TriageResult'

export default function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <NavLink to="/" className="brand">
          <span className="brand-mark">◈</span> TriageKit
        </NavLink>
        <nav className="nav">
          <NavLink to="/" end>Dashboard</NavLink>
          <a href="/" title="Classic Jinja UI">Classic UI</a>
        </nav>
        <span className="pill">React · Security Adviser</span>
      </header>
      <main className="page">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/webscan" element={<WebResult />} />
          <Route path="/scan" element={<ScanResult />} />
          <Route path="/triage" element={<TriageResult />} />
        </Routes>
      </main>
    </div>
  )
}
