import os
from fastapi.testclient import TestClient
from backend.api import app, get_samples_dir
from backend.models import (
    QuantumStatus,
    QuantumThreat,
    CryptoType,
    MoscaParameters
)
from backend.scanner.engine import scan_directory_for_crypto
from backend.analyzer.quantum_risk import evaluate_quantum_risk_for_artefact, compute_mosca_analysis
from backend.cbom.cyclonedx import generate_cyclonedx_cbom

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)"
    assert data["status"] == "healthy"

def test_quantum_risk_evaluator():
    status, threat, score = evaluate_quantum_risk_for_artefact("RSA", 1024)
    assert status == QuantumStatus.VULNERABLE
    assert threat == QuantumThreat.SHOR
    assert score == 100.0

    status, threat, score = evaluate_quantum_risk_for_artefact("AES", 128)
    assert status == QuantumStatus.WEAKENED
    assert threat == QuantumThreat.GROVER

    status, threat, score = evaluate_quantum_risk_for_artefact("AES", 256)
    assert status == QuantumStatus.QUANTUM_SAFE
    assert threat == QuantumThreat.NONE

    status, threat, score = evaluate_quantum_risk_for_artefact("ML-KEM-768")
    assert status == QuantumStatus.QUANTUM_SAFE
    assert threat == QuantumThreat.NONE

def test_sample_repo_scan():
    samples_dir = get_samples_dir()
    artefacts = scan_directory_for_crypto(samples_dir)
    assert len(artefacts) >= 5
    
    algos = [a.algorithm for a in artefacts]
    assert "RSA" in algos
    assert any("DES" in a or "3DES" in a for a in algos)
    assert any("ML-KEM" in a for a in algos)

def test_mosca_analysis():
    samples_dir = get_samples_dir()
    artefacts = scan_directory_for_crypto(samples_dir)
    params = MoscaParameters(
        data_shelf_life_x=10.0,
        migration_time_y=3.0,
        crqc_year_z=2030,
        current_year=2026
    )
    res, evaluated = compute_mosca_analysis(artefacts, params)
    assert res.is_breached is True
    assert res.breach_margin_years > 0.0

def test_api_demo_scan():
    response = client.get("/api/scan/demo")
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["summary"]["total_artefacts"] > 0
    assert len(data["artefacts"]) > 0
    assert len(data["recommendations"]) > 0

def test_cyclonedx_export():
    response = client.get("/api/scan/demo")
    assert response.status_code == 200
    data = response.json()
    scan_id = data["scan_id"]

    export_res = client.get(f"/api/cbom/export/{scan_id}?format=cyclonedx")
    assert export_res.status_code == 200
    cbom = export_res.json()
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) > 0
