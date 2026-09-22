import React, { useState, useEffect } from 'react'
import {
  Download,
  FileJson,
  FileSpreadsheet,
  FileText,
  Copy,
  Check,
  ShieldCheck
} from 'lucide-react'

export default function ExportCompliance({ scanResult }) {
  const [copied, setCopied] = useState(false)
  const [cbomJson, setCbomJson] = useState(null)
  const [loadingCbom, setLoadingCbom] = useState(false)

  const scanId = scanResult?.scan_id

  useEffect(() => {
    if (!scanId) return
    const fetchCbom = async () => {
      setLoadingCbom(true)
      try {
        const res = await fetch(`/api/cbom/export/${scanId}?format=cyclonedx`)
        if (res.ok) {
          const data = await res.json()
          setCbomJson(data)
        }
      } catch (e) {
        console.error(e)
      } finally {
        setLoadingCbom(false)
      }
    }
    fetchCbom()
  }, [scanId])

  if (!scanResult) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <p style={{ color: 'var(--text-secondary)' }}>No scan loaded. Run a scan to generate exportable CBOM records.</p>
      </div>
    )
  }

  const handleCopyJson = () => {
    if (!cbomJson) return
    navigator.clipboard.writeText(JSON.stringify(cbomJson, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
          Compliance & CBOM Export Center
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Standardized Cryptography Bill of Materials (CBOM) conforming to the CycloneDX v1.6 Cryptographic Asset Extension.
        </p>
      </div>

      <div className="grid-cols-3" style={{ marginBottom: '1.5rem' }}>
        <div className="card">
          <div className="card-title">
            <FileJson size={18} color="var(--accent-cyan)" /> CycloneDX 1.6 CBOM
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Machine-readable JSON specification containing algorithm definitions, OIDs, key lengths, and quantum security categories.
          </p>
          <a
            href={`/api/cbom/export/${scanId}?format=cyclonedx`}
            download={`cbom-cyclonedx-${scanId}.json`}
            className="btn-primary"
            style={{ width: '100%', textDecoration: 'none' }}
          >
            <Download size={16} /> Download CycloneDX JSON
          </a>
        </div>

        <div className="card">
          <div className="card-title">
            <FileSpreadsheet size={18} color="var(--accent-emerald)" /> Asset Inventory CSV
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Tabular spreadsheet including file locations, lines, business criticality, Shor/Grover classification, and risk scores.
          </p>
          <a
            href={`/api/cbom/export/${scanId}?format=csv`}
            download={`cbom-${scanId}.csv`}
            className="btn-secondary"
            style={{ width: '100%', textDecoration: 'none' }}
          >
            <Download size={16} /> Download CSV Inventory
          </a>
        </div>

        <div className="card">
          <div className="card-title">
            <FileText size={18} color="var(--accent-purple)" /> Executive Quantum Report
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
            Comprehensive NTRO executive audit report with Mosca timeline calculations, HNDL risk status, and PQC transition matrix.
          </p>
          <a
            href={`/api/cbom/export/${scanId}?format=markdown`}
            download={`ecdat-report-${scanId}.md`}
            className="btn-secondary"
            style={{ width: '100%', textDecoration: 'none' }}
          >
            <Download size={16} /> Download Audit Report
          </a>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div className="card-title" style={{ margin: 0 }}>
            <ShieldCheck size={18} color="var(--accent-cyan)" /> CycloneDX 1.6 CBOM Preview
          </div>
          <button className="btn-secondary" style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }} onClick={handleCopyJson}>
            {copied ? <Check size={14} color="var(--accent-emerald)" /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy JSON'}
          </button>
        </div>

        <div
          className="code-box"
          style={{
            maxHeight: '400px',
            overflowY: 'auto',
            fontSize: '0.78rem',
            lineHeight: 1.4,
            whiteSpace: 'pre'
          }}
        >
          {loadingCbom ? (
            <span>Generating CycloneDX 1.6 document...</span>
          ) : cbomJson ? (
            JSON.stringify(cbomJson, null, 2)
          ) : (
            <span>Unable to load preview.</span>
          )}
        </div>
      </div>
    </div>
  )
}
