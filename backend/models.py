from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class CryptoType(str, Enum):
    ASYMMETRIC = "asymmetric"
    SYMMETRIC = "symmetric"
    HASH = "hash"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    CERTIFICATE = "certificate"
    KEM = "kem"
    SIGNATURE = "signature"
    RNG = "rng"

class QuantumStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    WEAKENED = "WEAKENED"
    QUANTUM_SAFE = "QUANTUM_SAFE"
    UNKNOWN = "UNKNOWN"

class QuantumThreat(str, Enum):
    SHOR = "SHOR"
    GROVER = "GROVER"
    NONE = "NONE"

class Criticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class PQCRecommendation(BaseModel):
    legacy_algorithm: str
    recommended_pqc: str
    nist_standard: str
    security_category: int
    classical_security_bits: int
    quantum_security_bits: int
    public_key_overhead: str
    ciphertext_or_sig_overhead: str
    computational_overhead: str
    migration_urgency: str
    code_migration_guide: str

class CryptographicArtefact(BaseModel):
    id: str
    name: str
    type: CryptoType
    algorithm: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    file_path: str
    line_number: int
    code_snippet: str
    quantum_status: QuantumStatus
    quantum_threat: QuantumThreat
    business_criticality: Criticality
    data_shelf_life_years: float = 10.0
    migration_time_years: float = 3.0
    mosca_breached: bool = False
    quantum_risk_score: float = 0.0
    recommended_replacement: Optional[str] = None
    recommendation_details: Optional[PQCRecommendation] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class MoscaParameters(BaseModel):
    data_shelf_life_x: float = 10.0
    migration_time_y: float = 3.0
    crqc_year_z: int = 2030
    current_year: int = 2026

class MoscaResult(BaseModel):
    data_shelf_life_x: float
    migration_time_y: float
    crqc_year_z: int
    current_year: int
    years_to_crqc: float
    combined_timeline: float
    is_breached: bool
    breach_margin_years: float
    risk_level: str
    affected_artefacts_count: int
    hndl_exposure_level: str
    narrative: str

class ScanSummary(BaseModel):
    total_artefacts: int = 0
    vulnerable_count: int = 0
    weakened_count: int = 0
    quantum_safe_count: int = 0
    critical_criticality_count: int = 0
    mosca_breached_count: int = 0
    shor_exposure_count: int = 0
    grover_exposure_count: int = 0
    quantum_vulnerability_index: float = 0.0
    highest_risk_algorithm: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    target_path: str
    timestamp: str
    scan_duration_ms: float
    summary: ScanSummary
    artefacts: List[CryptographicArtefact]
    mosca_analysis: MoscaResult
    recommendations: List[PQCRecommendation]

class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    include_patterns: Optional[List[str]] = None
    exclude_patterns: Optional[List[str]] = None
    data_shelf_life_x: Optional[float] = 10.0
    migration_time_y: Optional[float] = 3.0
    crqc_year_z: Optional[int] = 2030

class RemoteScanRequest(BaseModel):
    host: str
    port: int = 443
    data_shelf_life_x: Optional[float] = 10.0
    migration_time_y: Optional[float] = 3.0
    crqc_year_z: Optional[int] = 2030
