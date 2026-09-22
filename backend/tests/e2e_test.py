import json
import urllib.request
import urllib.error
import sys

def create_local_opener():
    proxy_handler = urllib.request.ProxyHandler({})
    return urllib.request.build_opener(proxy_handler)

def run_e2e_tests():
    opener = create_local_opener()
    backend_url = "http://127.0.0.1:8000"
    frontend_url = "http://127.0.0.1:5173"
    results = []

    print("--- [E2E STEP 1] Verifying Backend Health ---")
    try:
        req = opener.open(f"{backend_url}/api/health", timeout=5)
        assert req.status == 200
        data = json.loads(req.read().decode())
        assert data["status"] == "healthy"
        assert data["cbom_spec"] == "CycloneDX 1.6"
        print(f"PASS: Backend healthy ({data['service']})")
        results.append(("Health Check", True))
    except Exception as e:
        print(f"FAIL: Health Check ({e})")
        results.append(("Health Check", False))

    print("\n--- [E2E STEP 2] Verifying Frontend Dev Server ---")
    try:
        req = opener.open(frontend_url, timeout=5)
        assert req.status == 200
        html = req.read().decode()
        assert "ECDAT" in html
        assert "<div id=\"root\"></div>" in html
        print("PASS: Frontend server delivering index.html with root container")
        results.append(("Frontend Index", True))
    except Exception as e:
        print(f"FAIL: Frontend Index ({e})")
        results.append(("Frontend Index", False))

    print("\n--- [E2E STEP 3] Executing Discovery Scan on Enterprise Codebase ---")
    scan_id = None
    try:
        req = opener.open(f"{backend_url}/api/scan/demo", timeout=10)
        assert req.status == 200
        scan_data = json.loads(req.read().decode())
        scan_id = scan_data["scan_id"]
        artefacts = scan_data["artefacts"]
        summary = scan_data["summary"]
        mosca = scan_data["mosca_analysis"]

        assert len(artefacts) >= 10
        assert summary["vulnerable_count"] > 0
        assert summary["shor_exposure_count"] > 0
        assert summary["quantum_safe_count"] > 0
        print(f"PASS: Discovery scan returned {len(artefacts)} artefacts across multi-language targets")
        print(f"      QVI Score: {summary['quantum_vulnerability_index']}/100")
        print(f"      Shor Exposed: {summary['shor_exposure_count']}, Grover Weakened: {summary['grover_exposure_count']}, Safe: {summary['quantum_safe_count']}")
        results.append(("Discovery Scan", True))
    except Exception as e:
        print(f"FAIL: Discovery Scan ({e})")
        results.append(("Discovery Scan", False))

    print("\n--- [E2E STEP 4] Validating Quantum Threat Modeling ---")
    try:
        algos = {a["algorithm"]: a for a in artefacts}
        assert "RSA" in algos
        assert algos["RSA"]["quantum_threat"] == "SHOR"
        assert algos["RSA"]["quantum_status"] == "VULNERABLE"

        assert any("ML-KEM" in k for k in algos)
        kem_key = [k for k in algos if "ML-KEM" in k][0]
        assert algos[kem_key]["quantum_status"] == "QUANTUM_SAFE"
        assert algos[kem_key]["quantum_threat"] == "NONE"

        print("PASS: Quantum threat categorization accurately mapped Shor vs Grover vs Quantum-Safe")
        results.append(("Threat Classification", True))
    except Exception as e:
        print(f"FAIL: Threat Classification ({e})")
        results.append(("Threat Classification", False))

    print("\n--- [E2E STEP 5] Testing Mosca's Theorem Risk Simulation ---")
    try:
        assert mosca["is_breached"] is True
        assert mosca["breach_margin_years"] > 0

        sim_url = f"{backend_url}/api/mosca/simulate?scan_id={scan_id}&data_shelf_life_x=1.0&migration_time_y=1.0&crqc_year_z=2035"
        sim_req = urllib.request.Request(sim_url, method="POST")
        res = opener.open(sim_req, timeout=5)
        sim_data = json.loads(res.read().decode())
        new_mosca = sim_data["mosca_analysis"]

        assert new_mosca["is_breached"] is False
        assert new_mosca["breach_margin_years"] < 0
        assert new_mosca["risk_level"] == "SUFFICIENT_WINDOW"
        print(f"PASS: Mosca simulation dynamically resolved breach status: X+Y={new_mosca['combined_timeline']} yrs <= Z-Now={new_mosca['years_to_crqc']} yrs")
        results.append(("Mosca Simulator", True))
    except Exception as e:
        print(f"FAIL: Mosca Simulator ({e})")
        results.append(("Mosca Simulator", False))

    print("\n--- [E2E STEP 6] Validating NIST PQC Recommendations ---")
    try:
        recs = scan_data["recommendations"]
        assert len(recs) >= 5
        rec_map = {r["legacy_algorithm"]: r for r in recs}

        assert "RSA-1024" in rec_map
        assert "ML-KEM" in rec_map["RSA-1024"]["recommended_pqc"]
        assert "FIPS 203" in rec_map["RSA-1024"]["nist_standard"]

        assert "3DES" in rec_map
        assert "AES-256" in rec_map["3DES"]["recommended_pqc"]

        print(f"PASS: NIST PQC advisor produced {len(recs)} validated migration paths")
        results.append(("NIST PQC Advisor", True))
    except Exception as e:
        print(f"FAIL: NIST PQC Advisor ({e})")
        results.append(("NIST PQC Advisor", False))

    print("\n--- [E2E STEP 7] Verifying CycloneDX 1.6 CBOM Export ---")
    try:
        cbom_res = opener.open(f"{backend_url}/api/cbom/export/{scan_id}?format=cyclonedx", timeout=5)
        assert cbom_res.status == 200
        cbom = json.loads(cbom_res.read().decode())
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert len(cbom["components"]) == len(artefacts)

        first_comp = cbom["components"][0]
        assert "cryptoProperties" in first_comp
        assert "algorithmProperties" in first_comp["cryptoProperties"]
        assert "quantumProperties" in first_comp["cryptoProperties"]["algorithmProperties"]
        print(f"PASS: Standardized CycloneDX 1.6 CBOM validated ({len(cbom['components'])} components)")
        results.append(("CycloneDX 1.6 Export", True))
    except Exception as e:
        print(f"FAIL: CycloneDX 1.6 Export ({e})")
        results.append(("CycloneDX 1.6 Export", False))

    print("\n--- [E2E STEP 8] Verifying CSV & Markdown Reports Export ---")
    try:
        csv_res = opener.open(f"{backend_url}/api/cbom/export/{scan_id}?format=csv", timeout=5)
        assert csv_res.status == 200
        csv_text = csv_res.read().decode()
        assert "Artefact ID,Name,Type,Algorithm" in csv_text
        assert "RSA" in csv_text

        md_res = opener.open(f"{backend_url}/api/cbom/export/{scan_id}?format=markdown", timeout=5)
        assert md_res.status == 200
        md_text = md_res.read().decode()
        assert "# Enterprise Cryptographic Discovery & Quantum Risk Report" in md_text
        assert "Mosca's Theorem Timeline Assessment" in md_text

        print("PASS: CSV and Markdown report formats generated correctly")
        results.append(("Reports Export", True))
    except Exception as e:
        print(f"FAIL: Reports Export ({e})")
        results.append(("Reports Export", False))

    print("\n=================== E2E TEST SUMMARY ===================")
    all_passed = True
    for name, passed in results:
        status_str = "PASSED" if passed else "FAILED"
        print(f"{name:30}: {status_str}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nALL 8 END-TO-END WORKFLOWS COMPLETED SUCCESSFULLY.")
        sys.exit(0)
    else:
        print("\nSOME E2E WORKFLOWS FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    run_e2e_tests()
