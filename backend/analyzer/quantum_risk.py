from typing import List, Tuple
from ..models import (
    CryptographicArtefact,
    QuantumStatus,
    QuantumThreat,
    Criticality,
    MoscaParameters,
    MoscaResult,
    ScanSummary
)

def evaluate_quantum_risk_for_artefact(
    algo: str,
    key_size: int = None,
    criticality: Criticality = Criticality.HIGH
) -> Tuple[QuantumStatus, QuantumThreat, float]:
    algo_u = algo.upper().strip()
    
    if any(k in algo_u for k in ["KYBER", "ML-KEM", "MLKEM", "DILITHIUM", "ML-DSA", "MLDSA", "SPHINCS", "SLH-DSA", "SLHDSA", "FALCON", "XMSS", "LMS"]):
        return QuantumStatus.QUANTUM_SAFE, QuantumThreat.NONE, 0.0
    
    if "AES" in algo_u:
        if key_size == 256 or "256" in algo_u:
            return QuantumStatus.QUANTUM_SAFE, QuantumThreat.NONE, 5.0
        elif key_size == 192 or "192" in algo_u:
            return QuantumStatus.WEAKENED, QuantumThreat.GROVER, 35.0
        else:
            return QuantumStatus.WEAKENED, QuantumThreat.GROVER, 65.0
            
    if any(k in algo_u for k in ["CHACHA20", "CHACHA"]):
        return QuantumStatus.QUANTUM_SAFE, QuantumThreat.NONE, 5.0
        
    if any(k in algo_u for k in ["SHA-384", "SHA384", "SHA-512", "SHA512", "SHA3-384", "SHA3-512", "BLAKE3"]):
        return QuantumStatus.QUANTUM_SAFE, QuantumThreat.NONE, 5.0
        
    if any(k in algo_u for k in ["SHA-256", "SHA256", "SHA3-256"]):
        return QuantumStatus.WEAKENED, QuantumThreat.GROVER, 25.0
        
    if any(k in algo_u for k in ["MD5", "SHA-1", "SHA1", "DES", "3DES", "TRIPLEDES", "RC4", "BLOWFISH"]):
        return QuantumStatus.VULNERABLE, QuantumThreat.GROVER, 95.0
        
    if any(k in algo_u for k in ["RSA", "ECDSA", "ECDH", "SECP", "PRIME256", "ED25519", "ED448", "X25519", "X448", "DIFFIE-HELLMAN", "DH", "DSA", "ELGAMAL"]):
        if "RSA" in algo_u and key_size and key_size <= 1024:
            return QuantumStatus.VULNERABLE, QuantumThreat.SHOR, 100.0
        return QuantumStatus.VULNERABLE, QuantumThreat.SHOR, 90.0
        
    if "TLS" in algo_u:
        if "1.3" in algo_u:
            if "KYBER" in algo_u or "MLKEM" in algo_u:
                return QuantumStatus.QUANTUM_SAFE, QuantumThreat.NONE, 5.0
            return QuantumStatus.WEAKENED, QuantumThreat.SHOR, 50.0
        return QuantumStatus.VULNERABLE, QuantumThreat.SHOR, 90.0
        
    return QuantumStatus.UNKNOWN, QuantumThreat.NONE, 40.0

def compute_mosca_analysis(
    artefacts: List[CryptographicArtefact],
    params: MoscaParameters
) -> Tuple[MoscaResult, List[CryptographicArtefact]]:
    years_to_crqc = max(0.1, float(params.crqc_year_z - params.current_year))
    combined_timeline = params.data_shelf_life_x + params.migration_time_y
    is_breached = combined_timeline > years_to_crqc
    breach_margin = combined_timeline - years_to_crqc
    
    affected_count = 0
    updated_artefacts: List[CryptographicArtefact] = []
    
    for art in artefacts:
        art_copy = art.model_copy()
        art_copy.data_shelf_life_years = params.data_shelf_life_x
        art_copy.migration_time_years = params.migration_time_y
        
        is_threatened = art_copy.quantum_status in [QuantumStatus.VULNERABLE, QuantumStatus.WEAKENED]
        if is_threatened and is_breached:
            art_copy.mosca_breached = True
            affected_count += 1
            art_copy.quantum_risk_score = min(100.0, art_copy.quantum_risk_score + 15.0)
        else:
            art_copy.mosca_breached = False
            
        updated_artefacts.append(art_copy)
        
    if breach_margin > 5.0:
        risk_level = "CRITICAL_COLLAPSE"
        hndl_level = "ACTIVE_EXTREME"
        narrative = f"Mosca inequality severely violated: Data shelf-life ({params.data_shelf_life_x} yrs) + Migration ({params.migration_time_y} yrs) exceeds CRQC arrival by {breach_margin:.1f} years. Any harvested encrypted data will be broken before shelf-life expires."
    elif breach_margin > 0.0:
        risk_level = "BREACHED"
        hndl_level = "HIGH_VULNERABILITY"
        narrative = f"Mosca inequality breached: Total transition window ({combined_timeline:.1f} yrs) exceeds time until CRQC ({years_to_crqc:.1f} yrs). Harvest-Now-Decrypt-Later (HNDL) attacks threaten sensitive communications."
    elif breach_margin > -2.0:
        risk_level = "TIGHT_MARGIN"
        hndl_level = "MODERATE"
        narrative = f"Safe margin is razor-thin ({abs(breach_margin):.1f} yrs remaining before breach). Immediate migration planning required to avoid schedule slippage."
    else:
        risk_level = "SUFFICIENT_WINDOW"
        hndl_level = "MANAGED"
        narrative = f"Adequate timeline window: Time to CRQC ({years_to_crqc:.1f} yrs) exceeds combined migration and shelf-life requirement ({combined_timeline:.1f} yrs)."

    mosca_res = MoscaResult(
        data_shelf_life_x=params.data_shelf_life_x,
        migration_time_y=params.migration_time_y,
        crqc_year_z=params.crqc_year_z,
        current_year=params.current_year,
        years_to_crqc=years_to_crqc,
        combined_timeline=combined_timeline,
        is_breached=is_breached,
        breach_margin_years=breach_margin,
        risk_level=risk_level,
        affected_artefacts_count=affected_count,
        hndl_exposure_level=hndl_level,
        narrative=narrative
    )
    return mosca_res, updated_artefacts

def calculate_summary(
    artefacts: List[CryptographicArtefact],
    mosca_res: MoscaResult
) -> ScanSummary:
    summary = ScanSummary()
    summary.total_artefacts = len(artefacts)
    
    if not artefacts:
        return summary
        
    crit_weight_map = {
        Criticality.CRITICAL: 4.0,
        Criticality.HIGH: 3.0,
        Criticality.MEDIUM: 2.0,
        Criticality.LOW: 1.0
    }
    
    total_weighted_risk = 0.0
    total_weight = 0.0
    algo_freq = {}
    
    for art in artefacts:
        if art.quantum_status == QuantumStatus.VULNERABLE:
            summary.vulnerable_count += 1
        elif art.quantum_status == QuantumStatus.WEAKENED:
            summary.weakened_count += 1
        elif art.quantum_status == QuantumStatus.QUANTUM_SAFE:
            summary.quantum_safe_count += 1
            
        if art.quantum_threat == QuantumThreat.SHOR:
            summary.shor_exposure_count += 1
        elif art.quantum_threat == QuantumThreat.GROVER:
            summary.grover_exposure_count += 1
            
        if art.business_criticality == Criticality.CRITICAL:
            summary.critical_criticality_count += 1
            
        if art.mosca_breached:
            summary.mosca_breached_count += 1
            
        w = crit_weight_map.get(art.business_criticality, 2.0)
        total_weighted_risk += art.quantum_risk_score * w
        total_weight += w
        
        algo_freq[art.algorithm] = algo_freq.get(art.algorithm, 0) + 1
        
    base_qvi = (total_weighted_risk / total_weight) if total_weight > 0 else 0.0
    
    if mosca_res.is_breached:
        base_qvi = min(100.0, base_qvi * 1.15 + 10.0)
        
    summary.quantum_vulnerability_index = round(base_qvi, 1)
    
    if algo_freq:
        summary.highest_risk_algorithm = sorted(
            algo_freq.keys(),
            key=lambda a: algo_freq[a],
            reverse=True
        )[0]
        
    return summary
