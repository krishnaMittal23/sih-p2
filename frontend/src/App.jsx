import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  Search,
  Layers,
  Clock,
  Zap,
  Download,
  Terminal,
  Activity,
  Cpu
} from 'lucide-react'

import ExecutiveDashboard from './components/ExecutiveDashboard'
import ScanConsole from './components/ScanConsole'
import CBOMExplorer from './components/CBOMExplorer'
import MoscaSimulator from './components/MoscaSimulator'
import PQCAdvisor from './components/PQCAdvisor'
import ExportCompliance from './components/ExportCompliance'

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [scanResult, setScanResult] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [backendOnline, setBackendOnline] = useState(false)

  useEffect(() => {
    const checkHealthAndLoadDemo = async () => {
      try {
        const healthRes = await fetch('/api/health')
        if (healthRes.ok) {
          setBackendOnline(true)
          const demoRes = await fetch('/api/scan/demo')
          if (demoRes.ok) {
            const data = await demoRes.json()
            setScanResult(data)
          }
        }
      } catch (err) {
        console.error('Backend offline or starting up', err)
      }
    }
    checkHealthAndLoadDemo()
  }, [])

  return (
    <div className="app-container">
      <header className="navbar">
        <div className="nav-brand">
          <div className="nav-badge-ntro">NTRO</div>
          <div className="nav-title-group">
            <h1>ECDAT <span style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--accent-cyan)' }}>Enterprise Cryptographic Discovery & Analysis</span></h1>
            <p>National Technical Research Organisation &bull; Post-Quantum Preparedness & CBOM</p>
          </div>
        </div>

        <div className="nav-status">
          <div className="status-pill">
            <span className="pulse-dot" style={{ background: backendOnline ? 'var(--accent-emerald)' : 'var(--accent-rose)' }} />
            <span>{backendOnline ? 'Engine Online (CycloneDX 1.6)' : 'Connecting Engine...'}</span>
          </div>
          <div className="status-pill">
            <Cpu size={14} color="var(--accent-cyan)" />
            <span>NIST FIPS 203/204/205</span>
          </div>
        </div>
      </header>

      <nav className="nav-tabs">
        <button
          className={`nav-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          <Activity size={16} /> Executive Posture
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'scan' ? 'active' : ''}`}
          onClick={() => setActiveTab('scan')}
        >
          <Search size={16} /> Discovery & Scan
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'cbom' ? 'active' : ''}`}
          onClick={() => setActiveTab('cbom')}
        >
          <Layers size={16} /> CBOM Asset Inventory
          {scanResult && <span style={{ background: 'rgba(255,255,255,0.1)', padding: '0.1rem 0.4rem', borderRadius: '4px', fontSize: '0.7rem' }}>{scanResult.artefacts.length}</span>}
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'mosca' ? 'active' : ''}`}
          onClick={() => setActiveTab('mosca')}
        >
          <Clock size={16} /> Mosca's Theorem Simulator
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'pqc' ? 'active' : ''}`}
          onClick={() => setActiveTab('pqc')}
        >
          <Zap size={16} /> NIST PQC Advisor
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'export' ? 'active' : ''}`}
          onClick={() => setActiveTab('export')}
        >
          <Download size={16} /> Export & Compliance
        </button>
      </nav>

      <main className="main-content">
        {activeTab === 'dashboard' && (
          <ExecutiveDashboard
            scanResult={scanResult}
            onNavigate={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'scan' && (
          <ScanConsole
            onScanComplete={(data) => {
              setScanResult(data)
              setActiveTab('dashboard')
            }}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        )}

        {activeTab === 'cbom' && (
          <CBOMExplorer
            scanResult={scanResult}
            onNavigate={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'mosca' && (
          <MoscaSimulator
            scanResult={scanResult}
            onUpdateScanResult={(updated) => setScanResult(updated)}
          />
        )}

        {activeTab === 'pqc' && (
          <PQCAdvisor scanResult={scanResult} />
        )}

        {activeTab === 'export' && (
          <ExportCompliance scanResult={scanResult} />
        )}
      </main>
    </div>
  )
}
