import React, { useState } from 'react'
import {
  Clock,
  AlertOctagon,
  ShieldCheck,
  RefreshCw,
  Info,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react'

export default function MoscaSimulator({ scanResult, onUpdateScanResult }) {
  if (!scanResult) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No scan loaded. Please run a discovery scan first.</p>
      </div>
    )
  }

  const { mosca_analysis, scan_id } = scanResult
  const currentYear = 2026

  const [shelfLifeX, setShelfLifeX] = useState(mosca_analysis.data_shelf_life_x || 10)
  const [migrationY, setMigrationY] = useState(mosca_analysis.migration_time_y || 3)
  const [crqcYearZ, setCrqcYearZ] = useState(mosca_analysis.crqc_year_z || 2030)
  const [isSimulating, setIsSimulating] = useState(false)

  const yearsToCrqc = Math.max(0.1, crqcYearZ - currentYear)
  const combinedTimeline = parseFloat(shelfLifeX) + parseFloat(migrationY)
  const isBreached = combinedTimeline > yearsToCrqc
  const breachMargin = combinedTimeline - yearsToCrqc

  const handleSimulate = async () => {
    setIsSimulating(true)
    try {
      const url = `/api/mosca/simulate?scan_id=${scan_id}&data_shelf_life_x=${shelfLifeX}&migration_time_y=${migrationY}&crqc_year_z=${crqcYearZ}`
      const res = await fetch(url, { method: 'POST' })
      if (!res.ok) throw new Error('Simulation failed')
      const updated = await res.json()
      onUpdateScanResult(updated)
    } catch (err) {
      console.error(err)
    } finally {
      setIsSimulating(false)
    }
  }

  const maxScaleYears = 25
  const shelfPct = Math.min(100, (shelfLifeX / maxScaleYears) * 100)
  const migPct = Math.min(100 - shelfPct, (migrationY / maxScaleYears) * 100)
  const crqcPct = Math.min(100, (yearsToCrqc / maxScaleYears) * 100)

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
          Mosca's Theorem Quantum Risk Simulator
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Assess vulnerability windows using Mosca's canonical quantum inequality: If <strong>X + Y &gt; Z</strong>, confidential data is compromised.
        </p>
      </div>

      <div className="bento-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="card col-span-8 fade-in">
          <div className="card-title">
            <Clock size={18} color="var(--accent-amber)" /> Timeline Parameters
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '1rem' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                  Data Shelf-Life (X): <span style={{ color: 'var(--accent-blue)' }}>{shelfLifeX} Years</span>
                </label>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>How long must confidential data remain secret?</span>
              </div>
              <input
                type="range"
                className="slider-blue"
                min="1"
                max="20"
                step="0.5"
                value={shelfLifeX}
                onChange={(e) => setShelfLifeX(parseFloat(e.target.value))}
              />
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                  Migration Duration (Y): <span style={{ color: 'var(--accent-amber)' }}>{migrationY} Years</span>
                </label>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Time to refactor, validate, and deploy PQC</span>
              </div>
              <input
                type="range"
                className="slider-amber"
                min="0.5"
                max="10"
                step="0.5"
                value={migrationY}
                onChange={(e) => setMigrationY(parseFloat(e.target.value))}
              />
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                  CRQC Arrival Horizon (Z): <span style={{ color: 'var(--accent-rose)' }}>Year {crqcYearZ}</span> ({yearsToCrqc.toFixed(1)} yrs from now)
                </label>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>When Cryptographically Relevant Quantum Computer arrives</span>
              </div>
              <input
                type="range"
                className="slider-rose"
                min="2027"
                max="2040"
                step="1"
                value={crqcYearZ}
                onChange={(e) => setCrqcYearZ(parseInt(e.target.value, 10))}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button
                className="btn-primary"
                onClick={handleSimulate}
                disabled={isSimulating}
              >
                <RefreshCw size={16} className={isSimulating ? 'spin' : ''} />
                {isSimulating ? 'Recalculating...' : 'Apply & Recompute Asset Risk'}
              </button>
            </div>
          </div>
        </div>

        <div className="card col-span-4 fade-in" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div className="card-title">
            <Info size={18} color="var(--accent-cyan)" /> Mathematical Evaluation
          </div>

          <div style={{ background: 'rgba(0,0,0,0.35)', padding: '1rem', borderRadius: 'var(--radius-md)', marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Mosca Formulation:</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.05rem', fontWeight: 700, margin: '0.35rem 0' }}>
              X + Y = {combinedTimeline.toFixed(1)} yrs
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.05rem', fontWeight: 700, color: 'var(--accent-rose)' }}>
              Z - Current = {yearsToCrqc.toFixed(1)} yrs
            </div>
          </div>

          {isBreached ? (
            <div style={{ borderLeft: '4px solid var(--accent-rose)', paddingLeft: '0.85rem' }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-rose)', fontSize: '0.95rem' }}>
                Inequality Breached (+{breachMargin.toFixed(1)} yrs)
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                Active Harvest-Now-Decrypt-Later (HNDL) vulnerability window. Encrypted data captured today will be decipherable before its required secrecy expires.
              </div>
            </div>
          ) : (
            <div style={{ borderLeft: '4px solid var(--accent-emerald)', paddingLeft: '0.85rem' }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-emerald)', fontSize: '0.95rem' }}>
                Inequality Satisfied ({Math.abs(breachMargin).toFixed(1)} yrs margin)
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                Migration completes before quantum computers arrive, preserving confidentiality requirements.
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card fade-in">
        <div className="card-title">
          <Calendar size={18} color="var(--accent-cyan)" /> Quantum Timeline Visualization (2026 - 2045)
        </div>

        <div style={{ margin: '2rem 0 1rem', position: 'relative' }}>
          <div className="timeline-bar" style={{ height: '32px' }}>
            <div
              className="timeline-segment-shelf"
              style={{ width: `${shelfPct}%` }}
              title={`Data Shelf-life: ${shelfLifeX} years`}
            />
            <div
              className="timeline-segment-migration"
              style={{ width: `${migPct}%` }}
              title={`Migration Time: ${migrationY} years`}
            />
            <div
              className="timeline-marker-crqc"
              style={{ left: `${crqcPct}%` }}
            />
          </div>

          <div
            style={{
              position: 'absolute',
              left: `${crqcPct}%`,
              top: '-24px',
              transform: 'translateX(-50%)',
              fontSize: '0.72rem',
              fontWeight: 700,
              color: 'var(--accent-rose)',
              whiteSpace: 'nowrap'
            }}
          >
            CRQC ({crqcYearZ})
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
            <span>2026 (Today)</span>
            <span>2031 (+5 yrs)</span>
            <span>2036 (+10 yrs)</span>
            <span>2041 (+15 yrs)</span>
            <span>2046+ (&gt;20 yrs)</span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '1.5rem', marginTop: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '3px', background: 'var(--accent-blue)' }} />
            <span>Data Shelf-life (X): {shelfLifeX} yrs</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '3px', background: 'var(--accent-amber)' }} />
            <span>Migration Duration (Y): {migrationY} yrs</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
            <div style={{ width: '3px', height: '12px', background: 'var(--accent-rose)' }} />
            <span>CRQC Arrival (Z): Year {crqcYearZ}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
