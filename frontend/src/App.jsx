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
  const [activeTab, setActiveTab] = useState('scan')
  const [scanResult, setScanResult] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [backendOnline, setBackendOnline] = useState(false)

  useEffect(() => {
    const checkHealthAndLoadData = async () => {
      try {
        const healthRes = await fetch('/api/health')
        if (healthRes.ok) {
          setBackendOnline(true)
          const res = await fetch('/api/scan/bundled')
          if (res.ok) {
            const data = await res.json()
            setScanResult(data)
          }
        }
      } catch (err) {
        console.error('Backend offline or starting up', err)
      }
    }
    checkHealthAndLoadData()
  }, [])

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="nav-brand">
          <div className="nav-badge-ntro">NTRO Certified</div>
          <div className="nav-title-group">
            <h1>ECDAT <span>Enterprise Cryptographic Discovery</span></h1>
            <p>Post-Quantum Preparedness & CBOM Platform</p>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab-btn ${activeTab === 'scan' ? 'active' : ''}`}
            onClick={() => setActiveTab('scan')}
          >
            <Search size={18} /> Discovery & Scan
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} /> Executive Posture
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'cbom' ? 'active' : ''}`}
            onClick={() => setActiveTab('cbom')}
          >
            <Layers size={18} /> CBOM Inventory
            {scanResult && (
              <span style={{ 
                marginLeft: 'auto', 
                background: 'rgba(255,255,255,0.1)', 
                padding: '0.15rem 0.5rem', 
                borderRadius: '9999px', 
                fontSize: '0.7rem' 
              }}>
                {scanResult.artefacts.length}
              </span>
            )}
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'mosca' ? 'active' : ''}`}
            onClick={() => setActiveTab('mosca')}
          >
            <Clock size={18} /> Mosca Simulator
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'pqc' ? 'active' : ''}`}
            onClick={() => setActiveTab('pqc')}
          >
            <Zap size={18} /> NIST PQC Advisor
          </button>
          <button
            className={`nav-tab-btn ${activeTab === 'export' ? 'active' : ''}`}
            onClick={() => setActiveTab('export')}
          >
            <Download size={18} /> Export Center
          </button>
        </nav>

        <div className="nav-status">
          <div className="status-pill">
            <span className="pulse-dot" style={{ background: backendOnline ? 'var(--green)' : 'var(--red)' }} />
            <span>{backendOnline ? 'Engine Online' : 'Connecting...'}</span>
          </div>
          <div className="status-pill">
            <Cpu size={14} color="var(--green)" />
            <span>NIST FIPS 203/204/205</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content fade-in">
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
