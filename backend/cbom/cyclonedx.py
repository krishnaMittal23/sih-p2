import io
import csv
import uuid
import datetime
from typing import Dict, Any, List
from ..models import (
    ScanResult,
    CryptographicArtefact,
    QuantumStatus,
    QuantumThreat,
    CryptoType
)

def generate_cyclonedx_cbom(scan_result: ScanResult) -> Dict[str, Any]:
    components = []
    
    for art in scan_result.artefacts:
        primitive = "other"
        if art.type == CryptoType.ASYMMETRIC:
            primitive = "asymmetric-encryption"
        elif art.type == CryptoType.SYMMETRIC:
            primitive = "block-cipher"
        elif art.type == CryptoType.HASH:
            primitive = "message-digest"
        elif art.type == CryptoType.PROTOCOL:
            primitive = "key-exchange-protocol"
        elif art.type == CryptoType.KEM:
            primitive = "key-encapsulation-mechanism"
        elif art.type == CryptoType.SIGNATURE:
            primitive = "digital-signature"
        elif art.type == CryptoType.CERTIFICATE:
            primitive = "public-key-certificate"

        q_level = 0
        if art.quantum_status == QuantumStatus.QUANTUM_SAFE:
            q_level = 5 if "256" in art.algorithm or "1024" in art.algorithm else 3
        elif art.quantum_status == QuantumStatus.WEAKENED:
            q_level = 1
            
        threat_str = "none"
        if art.quantum_threat == QuantumThreat.SHOR:
            threat_str = "shor"
        elif art.quantum_threat == QuantumThreat.GROVER:
            threat_str = "grover"

        comp = {
            "type": "cryptographic-asset",
            "bom-ref": art.id,
            "name": art.name,
            "version": str(art.key_size) if art.key_size else "standard",
            "description": f"Cryptographic artefact detected in {art.file_path}:{art.line_number}",
            "cryptoProperties": {
                "assetType": "algorithm" if art.type in [CryptoType.ASYMMETRIC, CryptoType.SYMMETRIC, CryptoType.HASH] else str(art.type.value),
                "algorithmProperties": {
                    "name": art.algorithm,
                    "primitive": primitive,
                    "parameterSetIdentifier": str(art.key_size) if art.key_size else "default",
                    "quantumProperties": {
                        "quantumSecurityLevel": q_level,
                        "quantumVulnerable": art.quantum_status in [QuantumStatus.VULNERABLE, QuantumStatus.WEAKENED],
                        "threatModel": threat_str
                    }
                }
            },
            "evidence": {
                "occurrences": [
                    {
                        "location": art.file_path,
                        "line": art.line_number,
                        "offset": 0,
                        "symbol": art.code_snippet
                    }
                ]
            },
            "properties": [
                {"name": "ecdat:businessCriticality", "value": art.business_criticality.value},
                {"name": "ecdat:quantumStatus", "value": art.quantum_status.value},
                {"name": "ecdat:quantumRiskScore", "value": str(art.quantum_risk_score)},
                {"name": "ecdat:moscaBreached", "value": str(art.mosca_breached)},
                {"name": "ecdat:recommendedPQC", "value": art.recommended_replacement or "None"}
            ]
        }
        components.append(comp)

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "NTRO",
                    "name": "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": scan_result.target_path or "Scanned Infrastructure",
                "version": "latest"
            },
            "properties": [
                {"name": "ecdat:scanId", "value": scan_result.scan_id},
                {"name": "ecdat:qviScore", "value": str(scan_result.summary.quantum_vulnerability_index)},
                {"name": "ecdat:moscaBreached", "value": str(scan_result.mosca_analysis.is_breached)},
                {"name": "ecdat:hndlExposure", "value": scan_result.mosca_analysis.hndl_exposure_level}
            ]
        },
        "components": components
    }
    return cbom

def export_cbom_csv(scan_result: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        "Artefact ID",
        "Name",
        "Type",
        "Algorithm",
        "Key Size (bits)",
        "File Location",
        "Line",
        "Quantum Status",
        "Quantum Threat",
        "Risk Score",
        "Business Criticality",
        "Mosca Breached",
        "Recommended NIST PQC",
        "NIST Standard",
        "Code Snippet"
    ])
    
    for art in scan_result.artefacts:
        writer.writerow([
            art.id,
            art.name,
            art.type.value,
            art.algorithm,
            art.key_size or "N/A",
            art.file_path,
            art.line_number,
            art.quantum_status.value,
            art.quantum_threat.value,
            art.quantum_risk_score,
            art.business_criticality.value,
            "YES" if art.mosca_breached else "NO",
            art.recommended_replacement or "N/A",
            art.recommendation_details.nist_standard if art.recommendation_details else "N/A",
            art.code_snippet
        ])
        
    return output.getvalue()

def generate_markdown_audit_report(scan_result: ScanResult) -> str:
    s = scan_result.summary
    m = scan_result.mosca_analysis
    
    md = f"""# Enterprise Cryptographic Discovery & Quantum Risk Report (ECDAT)
**Target**: `{scan_result.target_path}`  
**Scan ID**: `{scan_result.scan_id}`  
**Timestamp**: `{scan_result.timestamp}`  
**Organization**: National Technical Research Organisation (NTRO)

---

## 1. Executive Summary
- **Quantum Vulnerability Index (QVI)**: **{s.quantum_vulnerability_index} / 100**
- **Total Cryptographic Artefacts**: {s.total_artefacts}
- **Quantum Vulnerable (Shor/Grover)**: {s.vulnerable_count}
- **Weakened (Key Space Reduction)**: {s.weakened_count}
- **Quantum-Safe Ready**: {s.quantum_safe_count}
- **Shor's Algorithm Exposure (Asymmetric)**: {s.shor_exposure_count}
- **Grover's Algorithm Exposure (Symmetric/Hash)**: {s.grover_exposure_count}
- **Critical Business Assets at Risk**: {s.critical_criticality_count}

---

## 2. Mosca's Theorem Timeline Assessment
- **Data Shelf-Life ($X$)**: {m.data_shelf_life_x} years
- **Migration Duration ($Y$)**: {m.migration_time_y} years
- **CRQC Projected Year ($Z$)**: {m.crqc_year_z} (Years to CRQC: {m.years_to_crqc:.1f})
- **Mosca Inequality Status**: **{'COLLAPSE DETECTED (X + Y > Z)' if m.is_breached else 'ADEQUATE MARGIN (X + Y <= Z)'}**
- **Breach Margin**: {m.breach_margin_years:+.1f} years
- **HNDL (Harvest Now, Decrypt Later) Risk**: **{m.hndl_exposure_level}**
- **Narrative**: {m.narrative}

---

## 3. Top Recommended NIST Post-Quantum Upgrades
| Legacy Cipher | Recommended PQC | NIST Standard | Security Level | Urgency |
|---|---|---|---|---|
"""
    for rec in scan_result.recommendations:
        md += f"| `{rec.legacy_algorithm}` | **{rec.recommended_pqc}** | {rec.nist_standard} | Level {rec.security_category} | `{rec.migration_urgency}` |\n"
        
    md += f"""
---

## 4. Cryptographic Asset Inventory (CBOM)
Total items: {len(scan_result.artefacts)}

| ID | Name | Type | Algorithm | File & Line | Status | Risk |
|---|---|---|---|---|---|---|
"""
    for art in scan_result.artefacts[:30]:
        md += f"| `{art.id}` | {art.name} | {art.type.value} | `{art.algorithm}` | `{art.file_path}:{art.line_number}` | `{art.quantum_status.value}` | {art.quantum_risk_score} |\n"
        
    if len(scan_result.artefacts) > 30:
        md += f"\n*(Displaying top 30 of {len(scan_result.artefacts)} artefacts. Export full CycloneDX JSON or CSV for complete records.)*\n"
        
    return md
