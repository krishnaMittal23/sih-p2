import React from 'react'
import {
  ShieldCheck,
  ArrowRight,
  Zap,
  Gauge,
  Cpu,
  Layers,
  CheckCircle2,
  FileCheck2
} from 'lucide-react'

export default function PQCAdvisor({ scanResult }) {
  if (!scanResult) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No scan loaded. Run a scan to generate PQC recommendations.</p>
      </div>
    )
  }

  const { recommendations } = scanResult

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
          NIST Post-Quantum Cryptography (PQC) Migration Advisor
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Recommended quantum-resilient replacements adhering to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and hybrid architectures.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {recommendations.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '2rem' }}>
            <CheckCircle2 size={32} color="var(--accent-emerald)" style={{ marginBottom: '0.5rem' }} />
            <div style={{ fontWeight: 600 }}>All cryptographic artefacts are currently post-quantum resilient.</div>
          </div>
        ) : (
          recommendations.map((rec, idx) => (
            <div key={idx} className="card fade-in" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '1.1rem',
                      fontWeight: 700,
                      color: 'var(--accent-rose)',
                      background: 'rgba(244,63,94,0.1)',
                      padding: '0.3rem 0.75rem',
                      borderRadius: 'var(--radius-sm)'
                    }}
                  >
                    {rec.legacy_algorithm}
                  </span>
                  <ArrowRight size={20} color="var(--text-muted)" />
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '1.1rem',
                      fontWeight: 700,
                      color: 'var(--accent-emerald)',
                      background: 'rgba(16,185,129,0.1)',
                      padding: '0.3rem 0.75rem',
                      borderRadius: 'var(--radius-sm)'
                    }}
                  >
                    {rec.recommended_pqc}
                  </span>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <span className="badge badge-shor">NIST Level {rec.security_category}</span>
                  <span className="badge badge-vulnerable">Urgency: {rec.migration_urgency}</span>
                </div>
              </div>

              <div className="grid-cols-3" style={{ background: 'rgba(0,0,0,0.25)', padding: '1rem', borderRadius: 'var(--radius-md)', marginBottom: '1rem' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Standard / Specification
                  </div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                    {rec.nist_standard}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Key & Payload Impact
                  </div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    {rec.public_key_overhead}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Latency & Computation
                  </div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    {rec.computational_overhead}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  Actionable Refactoring Guidance:
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.5, background: 'rgba(255,255,255,0.02)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                  {rec.code_migration_guide}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
