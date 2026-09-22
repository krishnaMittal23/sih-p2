import os
import time
import uuid
import datetime
from typing import Dict, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

from .models import (
    ScanResult,
    ScanRequest,
    RemoteScanRequest,
    MoscaParameters,
    PQCRecommendation
)
from .scanner.engine import scan_directory_for_crypto
from .scanner.cert_scanner import scan_remote_tls_endpoint
from .analyzer.quantum_risk import compute_mosca_analysis, calculate_summary
from .analyzer.pqc_advisor import get_pqc_recommendation, PQC_KNOWLEDGE_BASE
from .cbom.cyclonedx import generate_cyclonedx_cbom, export_cbom_csv, generate_markdown_audit_report

app = FastAPI(
    title="Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
    description="NTRO Post-Quantum Cryptographic Discovery, CBOM, and Mosca Risk Analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCANS_CACHE: Dict[str, ScanResult] = {}

def get_samples_dir() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "samples")

def process_scan(
    target_name: str,
    artefacts: list,
    data_shelf_life_x: float,
    migration_time_y: float,
    crqc_year_z: int,
    elapsed_ms: float
) -> ScanResult:
    current_year = datetime.datetime.now().year
    mosca_params = MoscaParameters(
        data_shelf_life_x=data_shelf_life_x,
        migration_time_y=migration_time_y,
        crqc_year_z=crqc_year_z,
        current_year=current_year
    )
    
    mosca_res, evaluated_artefacts = compute_mosca_analysis(artefacts, mosca_params)
    summary = calculate_summary(evaluated_artefacts, mosca_res)
    
    seen_algos = set()
    recommendations = []
    for art in evaluated_artefacts:
        if art.recommendation_details and art.recommendation_details.legacy_algorithm not in seen_algos:
            recommendations.append(art.recommendation_details)
            seen_algos.add(art.recommendation_details.legacy_algorithm)
            
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    result = ScanResult(
        scan_id=scan_id,
        target_path=target_name,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scan_duration_ms=round(elapsed_ms, 2),
        summary=summary,
        artefacts=evaluated_artefacts,
        mosca_analysis=mosca_res,
        recommendations=recommendations
    )
    SCANS_CACHE[scan_id] = result
    return result

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
        "organization": "National Technical Research Organisation (NTRO)",
        "pqc_standard": "NIST FIPS 203, 204, 205",
        "cbom_spec": "CycloneDX 1.6"
    }

@app.get("/api/pqc/knowledge-base")
def get_pqc_kb():
    return PQC_KNOWLEDGE_BASE

@app.get("/api/scan/bundled")
@app.get("/api/scan/samples")
@app.get("/api/scan/demo")
def run_bundled_scan(
    data_shelf_life_x: float = 10.0,
    migration_time_y: float = 3.0,
    crqc_year_z: int = 2030
):
    samples_path = get_samples_dir()
    start_t = time.perf_counter()
    artefacts = scan_directory_for_crypto(samples_path)
    elapsed_ms = (time.perf_counter() - start_t) * 1000
    
    return process_scan(
        target_name="Bundled Enterprise Samples (Banking, Service, Quantum-Safe)",
        artefacts=artefacts,
        data_shelf_life_x=data_shelf_life_x,
        migration_time_y=migration_time_y,
        crqc_year_z=crqc_year_z,
        elapsed_ms=elapsed_ms
    )

@app.post("/api/scan")
def run_filesystem_scan(req: ScanRequest):
    target = req.target_path or get_samples_dir()
    if not os.path.exists(target):
        raise HTTPException(status_code=400, detail=f"Target path '{target}' does not exist.")
        
    start_t = time.perf_counter()
    artefacts = scan_directory_for_crypto(
        target_path=target,
        include_patterns=req.include_patterns,
        exclude_patterns=req.exclude_patterns
    )
    elapsed_ms = (time.perf_counter() - start_t) * 1000
    
    return process_scan(
        target_name=target,
        artefacts=artefacts,
        data_shelf_life_x=req.data_shelf_life_x or 10.0,
        migration_time_y=req.migration_time_y or 3.0,
        crqc_year_z=req.crqc_year_z or 2030,
        elapsed_ms=elapsed_ms
    )

@app.post("/api/scan/remote")
def run_remote_scan(req: RemoteScanRequest):
    start_t = time.perf_counter()
    artefacts = scan_remote_tls_endpoint(host=req.host, port=req.port)
    elapsed_ms = (time.perf_counter() - start_t) * 1000
    
    return process_scan(
        target_name=f"{req.host}:{req.port}",
        artefacts=artefacts,
        data_shelf_life_x=req.data_shelf_life_x or 10.0,
        migration_time_y=req.migration_time_y or 3.0,
        crqc_year_z=req.crqc_year_z or 2030,
        elapsed_ms=elapsed_ms
    )

@app.post("/api/mosca/simulate")
def simulate_mosca_timeline(
    scan_id: str = Query(...),
    data_shelf_life_x: float = Query(...),
    migration_time_y: float = Query(...),
    crqc_year_z: int = Query(...)
):
    if scan_id not in SCANS_CACHE:
        raise HTTPException(status_code=404, detail="Scan result not found in cache.")
        
    scan_prev = SCANS_CACHE[scan_id]
    current_year = datetime.datetime.now().year
    
    mosca_params = MoscaParameters(
        data_shelf_life_x=data_shelf_life_x,
        migration_time_y=migration_time_y,
        crqc_year_z=crqc_year_z,
        current_year=current_year
    )
    
    mosca_res, updated_artefacts = compute_mosca_analysis(scan_prev.artefacts, mosca_params)
    summary = calculate_summary(updated_artefacts, mosca_res)
    
    updated_result = ScanResult(
        scan_id=scan_prev.scan_id,
        target_path=scan_prev.target_path,
        timestamp=scan_prev.timestamp,
        scan_duration_ms=scan_prev.scan_duration_ms,
        summary=summary,
        artefacts=updated_artefacts,
        mosca_analysis=mosca_res,
        recommendations=scan_prev.recommendations
    )
    SCANS_CACHE[scan_id] = updated_result
    return updated_result

@app.get("/api/cbom/export/{scan_id}")
def export_cbom(scan_id: str, format: str = "cyclonedx"):
    if scan_id not in SCANS_CACHE:
        raise HTTPException(status_code=404, detail="Scan result not found.")
        
    scan = SCANS_CACHE[scan_id]
    
    if format == "cyclonedx":
        cbom_data = generate_cyclonedx_cbom(scan)
        return JSONResponse(
            content=cbom_data,
            headers={"Content-Disposition": f"attachment; filename=cbom-cyclonedx-{scan_id}.json"}
        )
    elif format == "csv":
        csv_str = export_cbom_csv(scan)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=cbom-{scan_id}.csv"}
        )
    elif format == "markdown":
        md_str = generate_markdown_audit_report(scan)
        return Response(
            content=md_str,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=ecdat-report-{scan_id}.md"}
        )
    else:
        return JSONResponse(
            content=scan.model_dump(),
            headers={"Content-Disposition": f"attachment; filename=ecdat-scan-{scan_id}.json"}
        )
