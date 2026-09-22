import React, { useState } from 'react'
import {
  Search,
  Filter,
  Code2,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  X,
  Zap
} from 'lucide-react'

export default function CBOMExplorer({ scanResult, onNavigate }) {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('ALL')
  const [selectedArtefact, setSelectedArtefact] = useState(null)

  if (!scanResult) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No scan data available. Run a scan to view the CBOM.</p>
      </div>
    )
  }

  const { artefacts } = scanResult

  const filteredArtefacts = artefacts.filter((art) => {
    const matchesSearch =
      art.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      art.code_snippet.toLowerCase().includes(searchTerm.toLowerCase())

    if (!matchesSearch) return false

    if (filterType === 'VULNERABLE') return art.quantum_status === 'VULNERABLE'
    if (filterType === 'WEAKENED') return art.quantum_status === 'WEAKENED'
    if (filterType === 'QUANTUM_SAFE') return art.quantum_status === 'QUANTUM_SAFE'
    if (filterType === 'CRITICAL') return art.business_criticality === 'CRITICAL'
    if (filterType === 'MOSCA_BREACHED') return art.mosca_breached === true

    return true
  })

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
            Cryptographic Bill of Materials (CBOM)
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            CycloneDX 1.6 compliant cryptographic inventory & vulnerability assessment.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn-secondary" onClick={() => onNavigate('export')}>
            Export CBOM
          </button>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
            <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              className="input-text"
              style={{ paddingLeft: '2.4rem' }}
              placeholder="Filter by algorithm, file, code snippet, or name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            <button
              className={`btn-secondary ${filterType === 'ALL' ? 'active' : ''}`}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: filterType === 'ALL' ? 'var(--accent-cyan)' : 'var(--border-subtle)' }}
              onClick={() => setFilterType('ALL')}
            >
              All ({artefacts.length})
            </button>
            <button
              className={`btn-secondary ${filterType === 'VULNERABLE' ? 'active' : ''}`}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: filterType === 'VULNERABLE' ? 'var(--accent-rose)' : 'var(--border-subtle)' }}
              onClick={() => setFilterType('VULNERABLE')}
            >
              Vulnerable ({artefacts.filter((a) => a.quantum_status === 'VULNERABLE').length})
            </button>
            <button
              className={`btn-secondary ${filterType === 'WEAKENED' ? 'active' : ''}`}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: filterType === 'WEAKENED' ? 'var(--accent-amber)' : 'var(--border-subtle)' }}
              onClick={() => setFilterType('WEAKENED')}
            >
              Weakened ({artefacts.filter((a) => a.quantum_status === 'WEAKENED').length})
            </button>
            <button
              className={`btn-secondary ${filterType === 'QUANTUM_SAFE' ? 'active' : ''}`}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: filterType === 'QUANTUM_SAFE' ? 'var(--accent-emerald)' : 'var(--border-subtle)' }}
              onClick={() => setFilterType('QUANTUM_SAFE')}
            >
              Quantum-Safe ({artefacts.filter((a) => a.quantum_status === 'QUANTUM_SAFE').length})
            </button>
            <button
              className={`btn-secondary ${filterType === 'MOSCA_BREACHED' ? 'active' : ''}`}
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem', borderColor: filterType === 'MOSCA_BREACHED' ? 'var(--accent-rose)' : 'var(--border-subtle)' }}
              onClick={() => setFilterType('MOSCA_BREACHED')}
            >
              Mosca Breached ({artefacts.filter((a) => a.mosca_breached).length})
            </button>
          </div>
        </div>
      </div>

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Artefact Name & Type</th>
              <th>Algorithm</th>
              <th>Key / Mode</th>
              <th>Threat</th>
              <th>Quantum Status</th>
              <th>Mosca</th>
              <th>Risk</th>
              <th>Location</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredArtefacts.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  No artefacts matching current criteria.
                </td>
              </tr>
            ) : (
              filteredArtefacts.map((art) => (
                <tr key={art.id}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{art.name}</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      {art.type}
                    </div>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{art.algorithm}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {art.key_size ? `${art.key_size} bits` : 'Default'}
                    </span>
                  </td>
                  <td>
                    {art.quantum_threat === 'SHOR' && <span className="badge badge-shor">Shor (Asym)</span>}
                    {art.quantum_threat === 'GROVER' && <span className="badge badge-grover">Grover (Sym)</span>}
                    {art.quantum_threat === 'NONE' && <span className="badge badge-safe">None</span>}
                  </td>
                  <td>
                    {art.quantum_status === 'VULNERABLE' && <span className="badge badge-vulnerable">Vulnerable</span>}
                    {art.quantum_status === 'WEAKENED' && <span className="badge badge-weakened">Weakened</span>}
                    {art.quantum_status === 'QUANTUM_SAFE' && <span className="badge badge-safe">Quantum Safe</span>}
                  </td>
                  <td>
                    {art.mosca_breached ? (
                      <span className="badge badge-vulnerable" title="X + Y > Z: Data compromised during lifetime">Breached</span>
                    ) : (
                      <span className="badge badge-safe">Safe</span>
                    )}
                  </td>
                  <td>
                    <span
                      style={{
                        fontWeight: 700,
                        color: art.quantum_risk_score >= 70 ? 'var(--accent-rose)' : art.quantum_risk_score >= 40 ? 'var(--accent-amber)' : 'var(--accent-emerald)'
                      }}
                    >
                      {art.quantum_risk_score}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-cyan)' }}>
                      {art.file_path}:{art.line_number}
                    </div>
                  </td>
                  <td>
                    <button
                      className="btn-secondary"
                      style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }}
                      onClick={() => setSelectedArtefact(art)}
                    >
                      <Code2 size={13} /> Inspect
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {selectedArtefact && (
        <div className="modal-backdrop" onClick={() => setSelectedArtefact(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <Zap size={20} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: '1.15rem', fontWeight: 700 }}>{selectedArtefact.name}</h3>
              </div>
              <button
                onClick={() => setSelectedArtefact(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
              <span className="badge badge-vulnerable">{selectedArtefact.quantum_status}</span>
              <span className="badge badge-shor">Threat: {selectedArtefact.quantum_threat}</span>
              <span className="badge badge-weakened">Criticality: {selectedArtefact.business_criticality}</span>
              <span className="badge badge-safe">Risk Score: {selectedArtefact.quantum_risk_score}/100</span>
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Discovered Location: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedArtefact.file_path}:{selectedArtefact.line_number}</strong>
              </div>
              <div className="code-box">
                <code>{selectedArtefact.code_snippet}</code>
              </div>
            </div>

            {selectedArtefact.recommendation_details ? (
              <div className="card" style={{ background: 'rgba(6, 182, 212, 0.05)', borderColor: 'rgba(6, 182, 212, 0.25)', marginBottom: '1.25rem' }}>
                <div style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--accent-cyan)', marginBottom: '0.5rem' }}>
                  Recommended NIST Post-Quantum Alternative
                </div>
                <div style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                  {selectedArtefact.recommendation_details.recommended_pqc}
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                  Standard: <strong>{selectedArtefact.recommendation_details.nist_standard}</strong> (NIST Category {selectedArtefact.recommendation_details.security_category})
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.5, background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: 'var(--radius-sm)' }}>
                  {selectedArtefact.recommendation_details.code_migration_guide}
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                This cryptographic primitive currently meets quantum resiliency standards.
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button className="btn-secondary" onClick={() => setSelectedArtefact(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
