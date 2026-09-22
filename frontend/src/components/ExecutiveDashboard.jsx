import React from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Lock,
  Clock,
  AlertTriangle,
  FileCode,
  Layers,
  Flame
} from 'lucide-react'

export default function ExecutiveDashboard({ scanResult, onNavigate }) {
  if (!scanResult) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
        <Cpu size={54} color="#06b6d4" style={{ marginBottom: '1rem', opacity: 0.8 }} />
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>No Active Scan Loaded</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem', maxWidth: '500px', margin: '0 auto 1.5rem' }}>
          Discover cryptographic artefacts, compute quantum vulnerability against Shor's and Grover's algorithms, and run Mosca's theorem.
        </p>
        <button className="btn-primary" onClick={() => onNavigate('scan')}>
          Launch Discovery Scan
        </button>
      </div>
    )
  }

  const { summary, mosca_analysis, target_path, timestamp, scan_duration_ms, artefacts } = scanResult
  const qvi = summary.quantum_vulnerability_index || 0

  const getQviColor = (val) => {
    if (val >= 75) return 'var(--accent-rose)'
    if (val >= 45) return 'var(--accent-amber)'
    return 'var(--accent-emerald)'
  }

  const circumference = 2 * Math.PI * 65
  const strokeDashoffset = circumference - (qvi / 100) * circumference

  const algoCounts = {}
  artefacts.forEach((a) => {
    algoCounts[a.algorithm] = (algoCounts[a.algorithm] || 0) + 1
  })
  const sortedAlgos = Object.entries(algoCounts).sort((a, b) => b[1] - a[1]).slice(0, 6)

  return (
    <div>
      {mosca_analysis.is_breached ? (
        <div className="alert-banner alert-banner-danger">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Flame size={32} color="#fb7185" />
            <div>
              <div style={{ fontWeight: 700, fontSize: '1.05rem', color: '#fb7185' }}>
                MOSCA'S THEOREM COLLAPSE DETECTED (X + Y &gt; Z)
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {mosca_analysis.narrative}
              </div>
            </div>
          </div>
          <button className="btn-secondary" onClick={() => onNavigate('mosca')}>
            Simulate Mosca Risk
          </button>
        </div>
      ) : (
        <div className="alert-banner alert-banner-safe">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <ShieldCheck size={32} color="#34d399" />
            <div>
              <div style={{ fontWeight: 700, fontSize: '1.05rem', color: '#34d399' }}>
                Quantum Transition Window Currently Safe
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Time to CRQC ({mosca_analysis.years_to_crqc.toFixed(1)} yrs) currently accommodates migration window.
              </div>
            </div>
          </div>
          <button className="btn-secondary" onClick={() => onNavigate('mosca')}>
            View Timeline
          </button>
        </div>
      )}

      <div className="grid-cols-4" style={{ marginBottom: '1.5rem' }}>
        <div className="card">
          <div className="card-title">
            <Layers size={18} color="var(--accent-cyan)" /> Total Artefacts
          </div>
          <div className="metric-stat" style={{ color: 'var(--accent-cyan)' }}>
            {summary.total_artefacts}
          </div>
          <div className="metric-sub">Catalogued in CBOM inventory</div>
        </div>

        <div className="card">
          <div className="card-title">
            <ShieldAlert size={18} color="var(--accent-rose)" /> Shor Exposed (Asym)
          </div>
          <div className="metric-stat" style={{ color: 'var(--accent-rose)' }}>
            {summary.shor_exposure_count}
          </div>
          <div className="metric-sub">Vulnerable to polynomial-time break</div>
        </div>

        <div className="card">
          <div className="card-title">
            <AlertTriangle size={18} color="var(--accent-amber)" /> Grover Weakened (Sym)
          </div>
          <div className="metric-stat" style={{ color: 'var(--accent-amber)' }}>
            {summary.grover_exposure_count}
          </div>
          <div className="metric-sub">Effective bit security halved</div>
        </div>

        <div className="card">
          <div className="card-title">
            <ShieldCheck size={18} color="var(--accent-emerald)" /> Quantum Safe Ready
          </div>
          <div className="metric-stat" style={{ color: 'var(--accent-emerald)' }}>
            {summary.quantum_safe_count}
          </div>
          <div className="metric-sub">NIST PQC & 256-bit compliant</div>
        </div>
      </div>

      <div className="grid-cols-3" style={{ marginBottom: '1.5rem' }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
          <div className="card-title" style={{ alignSelf: 'flex-start' }}>
            <Cpu size={18} color="var(--accent-cyan)" /> Quantum Vulnerability Index
          </div>
          <div className="gauge-container" style={{ margin: '1rem 0' }}>
            <svg className="gauge-svg" width="160" height="160">
              <circle className="gauge-bg" cx="80" cy="80" r="65" />
              <circle
                className="gauge-fill"
                cx="80"
                cy="80"
                r="65"
                stroke={getQviColor(qvi)}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
              />
            </svg>
            <div className="gauge-center-text">
              <div style={{ fontSize: '2.2rem', fontWeight: 800, color: getQviColor(qvi), lineHeight: 1 }}>
                {qvi}
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '0.2rem' }}>
                Score / 100
              </div>
            </div>
          </div>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: getQviColor(qvi) }}>
            {qvi >= 75 ? 'HIGH QUANTUM EXPOSURE' : qvi >= 45 ? 'MODERATE TRANSITION RISK' : 'LOW RISK / RESILIENT'}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Lock size={18} color="var(--accent-purple)" /> Top Cryptographic Algorithms
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginTop: '0.5rem' }}>
            {sortedAlgos.map(([algo, count]) => {
              const pct = Math.round((count / summary.total_artefacts) * 100)
              return (
                <div key={algo}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{algo}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ height: '6px', background: 'rgba(255,255,255,0.06)', borderRadius: '9999px', overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${pct}%`,
                        background: algo.includes('RSA') || algo.includes('EC') ? 'var(--accent-rose)' : algo.includes('AES-256') || algo.includes('ML-') ? 'var(--accent-emerald)' : 'var(--accent-blue)'
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <Clock size={18} color="var(--accent-amber)" /> Mosca's Parameters
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Data Shelf-Life (X):</span>
              <span style={{ fontWeight: 600, color: 'var(--accent-blue)' }}>{mosca_analysis.data_shelf_life_x} yrs</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Migration Time (Y):</span>
              <span style={{ fontWeight: 600, color: 'var(--accent-amber)' }}>{mosca_analysis.migration_time_y} yrs</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>CRQC Horizon (Z):</span>
              <span style={{ fontWeight: 600, color: 'var(--accent-rose)' }}>Year {mosca_analysis.crqc_year_z}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>HNDL Exposure:</span>
              <span className="badge badge-vulnerable">{mosca_analysis.hndl_exposure_level}</span>
            </div>
            <button className="btn-secondary" style={{ width: '100%', marginTop: '0.5rem' }} onClick={() => onNavigate('mosca')}>
              Adjust Parameters
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <FileCode size={24} color="var(--accent-cyan)" />
          <div>
            <div style={{ fontSize: '0.88rem', fontWeight: 600 }}>Active Target: {target_path}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Scan completed in {scan_duration_ms} ms &bull; {new Date(timestamp).toLocaleString()}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn-secondary" onClick={() => onNavigate('cbom')}>
            View Full CBOM ({artefacts.length} items)
          </button>
          <button className="btn-primary" onClick={() => onNavigate('pqc')}>
            View PQC Recommendations
          </button>
        </div>
      </div>
    </div>
  )
}
