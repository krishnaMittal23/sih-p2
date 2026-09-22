import React, { useState } from 'react'
import {
  FolderSearch,
  Globe,
  Play,
  Terminal,
  Server,
  CheckCircle2,
  AlertCircle
} from 'lucide-react'

export default function ScanConsole({ onScanComplete, isLoading, setIsLoading }) {
  const [activeMode, setActiveMode] = useState('bundled')
  const [localPath, setLocalPath] = useState('P:\\SIH_2\\sih-p2\\backend\\samples')
  const [remoteHost, setRemoteHost] = useState('google.com')
  const [remotePort, setRemotePort] = useState(443)
  const [logs, setLogs] = useState([])
  const [errorMsg, setErrorMsg] = useState('')

  const addLog = (msg) => {
    const time = new Date().toLocaleTimeString()
    setLogs((prev) => [...prev, `[${time}] ${msg}`])
  }

  const handleRunBundledScan = async () => {
    setIsLoading(true)
    setErrorMsg('')
    setLogs([])
    addLog('Initiating bundled enterprise multi-tier repository discovery scan...')
    addLog('Cataloguing source files across Python, Java, and Go modules...')

    try {
      const res = await fetch('/api/scan/bundled')
      if (!res.ok) throw new Error('Failed to run scan')
      const data = await res.json()
      addLog(`Discovered ${data.summary.total_artefacts} cryptographic artefacts.`)
      addLog(`Computed Quantum Vulnerability Index (QVI): ${data.summary.quantum_vulnerability_index}`)
      addLog(`Mosca theorem status: ${data.mosca_analysis.is_breached ? 'BREACHED' : 'SAFE'}`)
      onScanComplete(data)
    } catch (err) {
      setErrorMsg(err.message)
      addLog(`ERROR: ${err.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  const handleRunLocalScan = async (e) => {
    e.preventDefault()
    if (!localPath) return
    setIsLoading(true)
    setErrorMsg('')
    setLogs([])
    addLog(`Scanning target directory: ${localPath}`)
    addLog('Analyzing AST, regex patterns, key generators, and cipher suites...')

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_path: localPath })
      })
      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.detail || 'Failed to scan target path')
      }
      const data = await res.json()
      addLog(`Scan complete. ${data.summary.total_artefacts} artefacts discovered in ${data.scan_duration_ms} ms.`)
      onScanComplete(data)
    } catch (err) {
      setErrorMsg(err.message)
      addLog(`ERROR: ${err.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  const handleRunRemoteScan = async (e) => {
    e.preventDefault()
    if (!remoteHost) return
    setIsLoading(true)
    setErrorMsg('')
    setLogs([])
    addLog(`Initiating live TLS handshake inspection for: ${remoteHost}:${remotePort}`)
    addLog('Extracting cipher suite, protocol version, and server X.509 certificate...')

    try {
      const res = await fetch('/api/scan/remote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: remoteHost, port: parseInt(remotePort, 10) })
      })
      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.detail || 'Failed to inspect remote endpoint')
      }
      const data = await res.json()
      addLog(`Handshake analyzed. Detected ${data.summary.total_artefacts} cryptographic artefacts.`)
      onScanComplete(data)
    } catch (err) {
      setErrorMsg(err.message)
      addLog(`ERROR: ${err.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
          Cryptographic Discovery & Scan Console
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Scan source code repositories, binaries, libraries, and remote endpoints to build your Cryptographic Bill of Materials (CBOM).
        </p>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <button
          className={`btn-secondary ${activeMode === 'bundled' ? 'active' : ''}`}
          onClick={() => setActiveMode('bundled')}
        >
          <Server size={16} /> 1-Click Bundled Scan
        </button>
        <button
          className={`btn-secondary ${activeMode === 'local' ? 'active' : ''}`}
          onClick={() => setActiveMode('local')}
        >
          <FolderSearch size={16} /> Local Directory / Repo
        </button>
        <button
          className={`btn-secondary ${activeMode === 'remote' ? 'active' : ''}`}
          onClick={() => setActiveMode('remote')}
        >
          <Globe size={16} /> Remote TLS Endpoint
        </button>
      </div>

      <div className="bento-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="card col-span-6 fade-in">
          {activeMode === 'bundled' && (
            <div>
              <div className="card-title">
                <Server size={18} color="var(--green)" /> Bundled Enterprise Repository
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                Pre-configured multi-tier enterprise codebase containing legacy banking modules (RSA-1024, DES, MD5, TLS 1.0), intermediate enterprise services (ECDSA, AES-128, SHA-256), and modern quantum-safe hybrid services (ML-KEM, ML-DSA).
              </p>
              <button
                className="btn-primary"
                onClick={handleRunBundledScan}
                disabled={isLoading}
                style={{ width: '100%' }}
              >
                <Play size={16} /> {isLoading ? 'Scanning Enterprise Assets...' : 'Run 1-Click Scan'}
              </button>
            </div>
          )}

          {activeMode === 'local' && (
            <form onSubmit={handleRunLocalScan}>
              <div className="card-title">
                <FolderSearch size={18} color="var(--accent-blue)" /> Scan Local Directory
              </div>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.4rem' }}>
                  Target Absolute Directory or File Path:
                </label>
                <input
                  type="text"
                  className="input-text"
                  value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)}
                  placeholder="e.g. C:\Projects\my-secure-app"
                  required
                />
              </div>
              <button
                type="submit"
                className="btn-primary"
                disabled={isLoading}
                style={{ width: '100%' }}
              >
                <Play size={16} /> {isLoading ? 'Discovering Artefacts...' : 'Scan Directory'}
              </button>
            </form>
          )}

          {activeMode === 'remote' && (
            <form onSubmit={handleRunRemoteScan}>
              <div className="card-title">
                <Globe size={18} color="var(--green)" /> Inspect Remote TLS Endpoint
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}>
                <div style={{ flex: 3 }}>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.4rem' }}>
                    Hostname / Domain:
                  </label>
                  <input
                    type="text"
                    className="input-text"
                    value={remoteHost}
                    onChange={(e) => setRemoteHost(e.target.value)}
                    placeholder="e.g. api.banking.internal"
                    required
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.4rem' }}>
                    Port:
                  </label>
                  <input
                    type="number"
                    className="input-text"
                    value={remotePort}
                    onChange={(e) => setRemotePort(e.target.value)}
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                className="btn-primary"
                disabled={isLoading}
                style={{ width: '100%' }}
              >
                <Play size={16} /> {isLoading ? 'Connecting & Handshaking...' : 'Inspect Endpoint'}
              </button>
            </form>
          )}

          {errorMsg && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--red)', fontSize: '0.85rem', marginTop: '1rem' }}>
              <AlertCircle size={16} /> {errorMsg}
            </div>
          )}
        </div>

        <div className="card col-span-6 fade-in" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="card-title">
            <Terminal size={18} color="var(--green)" /> Live Engine Telemetry
          </div>
          <div
            className="code-box"
            style={{
              flex: 1,
              minHeight: '180px',
              maxHeight: '220px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.78rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.25rem'
            }}
          >
            {logs.length === 0 ? (
              <span style={{ color: 'var(--text-muted)' }}>Ready for scan execution...</span>
            ) : (
              logs.map((log, idx) => <div key={idx}>{log}</div>)
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
