import socket
import ssl
import uuid
import datetime
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from ..models import (
    CryptographicArtefact,
    CryptoType,
    Criticality,
    QuantumStatus,
    QuantumThreat
)
from ..analyzer.quantum_risk import evaluate_quantum_risk_for_artefact
from ..analyzer.pqc_advisor import get_pqc_recommendation

def parse_x509_certificate(cert_data: bytes, origin_identifier: str) -> List[CryptographicArtefact]:
    artefacts = []
    try:
        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
        public_key = cert.public_key()
        algo = "UNKNOWN"
        key_size = 0
        
        if isinstance(public_key, rsa.RSAPublicKey):
            algo = "RSA"
            key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo = "ECDSA"
            key_size = public_key.curve.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            algo = "ED25519"
            key_size = 256
        elif isinstance(public_key, dsa.DSAPublicKey):
            algo = "DSA"
            key_size = public_key.key_size

        q_status, q_threat, risk_score = evaluate_quantum_risk_for_artefact(
            algo, key_size, Criticality.CRITICAL
        )
        recommendation = get_pqc_recommendation(algo, key_size)
        
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else "Signature-Algo"
        
        pubkey_art = CryptographicArtefact(
            id=f"cert-{uuid.uuid4().hex[:10]}",
            name=f"Certificate Public Key ({algo}-{key_size})",
            type=CryptoType.CERTIFICATE,
            algorithm=algo,
            key_size=key_size,
            file_path=origin_identifier,
            line_number=1,
            code_snippet=f"Subject: {cert.subject.rfc4514_string()[:100]} | Issuer: {cert.issuer.rfc4514_string()[:100]}",
            quantum_status=q_status,
            quantum_threat=q_threat,
            business_criticality=Criticality.CRITICAL,
            quantum_risk_score=risk_score,
            recommended_replacement=recommendation.recommended_pqc if recommendation else "ML-DSA-65 (FIPS 204)",
            recommendation_details=recommendation,
            metadata={
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat(),
                "serial_number": str(cert.serial_number),
                "signature_algorithm": sig_algo
            }
        )
        artefacts.append(pubkey_art)
        
        sig_status, sig_threat, sig_risk = evaluate_quantum_risk_for_artefact(
            sig_algo, None, Criticality.HIGH
        )
        sig_recommendation = get_pqc_recommendation(sig_algo)
        sig_art = CryptographicArtefact(
            id=f"cert-sig-{uuid.uuid4().hex[:10]}",
            name=f"Certificate Signature Scheme ({sig_algo})",
            type=CryptoType.SIGNATURE,
            algorithm=sig_algo,
            key_size=key_size,
            file_path=origin_identifier,
            line_number=1,
            code_snippet=f"Sig Algorithm OID: {cert.signature_algorithm_oid.dotted_string}",
            quantum_status=sig_status,
            quantum_threat=sig_threat,
            business_criticality=Criticality.HIGH,
            quantum_risk_score=sig_risk,
            recommended_replacement=sig_recommendation.recommended_pqc if sig_recommendation else "ML-DSA-65",
            recommendation_details=sig_recommendation,
            metadata={
                "oid": cert.signature_algorithm_oid.dotted_string
            }
        )
        artefacts.append(sig_art)
        
    except Exception:
        pass
        
    return artefacts

def scan_remote_tls_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> List[CryptographicArtefact]:
    artefacts = []
    origin = f"tls://{host}:{port}"
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                cipher_name = cipher_tuple[0] if cipher_tuple else "UNKNOWN"
                cipher_protocol = cipher_tuple[1] if cipher_tuple else tls_version
                cipher_bits = cipher_tuple[2] if cipher_tuple else 128
                
                proto_status, proto_threat, proto_risk = evaluate_quantum_risk_for_artefact(
                    tls_version, None, Criticality.CRITICAL
                )
                proto_rec = get_pqc_recommendation(tls_version)
                proto_art = CryptographicArtefact(
                    id=f"tls-proto-{uuid.uuid4().hex[:10]}",
                    name=f"Negotiated Protocol ({tls_version})",
                    type=CryptoType.PROTOCOL,
                    algorithm=tls_version,
                    key_size=None,
                    file_path=origin,
                    line_number=1,
                    code_snippet=f"Handshake Protocol: {tls_version}",
                    quantum_status=proto_status,
                    quantum_threat=proto_threat,
                    business_criticality=Criticality.CRITICAL,
                    quantum_risk_score=proto_risk,
                    recommended_replacement=proto_rec.recommended_pqc if proto_rec else "TLS 1.3 with Hybrid ML-KEM",
                    recommendation_details=proto_rec,
                    metadata={"endpoint": f"{host}:{port}", "version": tls_version}
                )
                artefacts.append(proto_art)
                
                c_status, c_threat, c_risk = evaluate_quantum_risk_for_artefact(
                    cipher_name, cipher_bits, Criticality.HIGH
                )
                c_rec = get_pqc_recommendation(cipher_name, cipher_bits)
                cipher_art = CryptographicArtefact(
                    id=f"tls-cipher-{uuid.uuid4().hex[:10]}",
                    name=f"Negotiated Cipher Suite ({cipher_name})",
                    type=CryptoType.SYMMETRIC,
                    algorithm=cipher_name,
                    key_size=cipher_bits,
                    file_path=origin,
                    line_number=1,
                    code_snippet=f"Cipher: {cipher_name} ({cipher_bits} bits)",
                    quantum_status=c_status,
                    quantum_threat=c_threat,
                    business_criticality=Criticality.HIGH,
                    quantum_risk_score=c_risk,
                    recommended_replacement=c_rec.recommended_pqc if c_rec else "AES-256-GCM / ML-KEM Hybrid",
                    recommendation_details=c_rec,
                    metadata={"cipher_suite": cipher_name, "bits": cipher_bits}
                )
                artefacts.append(cipher_art)
                
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    cert_artefacts = parse_x509_certificate(der_cert, origin)
                    artefacts.extend(cert_artefacts)
                    
    except Exception as e:
        error_art = CryptographicArtefact(
            id=f"tls-err-{uuid.uuid4().hex[:10]}",
            name=f"TLS Connection Error",
            type=CryptoType.PROTOCOL,
            algorithm="TLS",
            file_path=origin,
            line_number=1,
            code_snippet=f"Connection failure: {str(e)[:150]}",
            quantum_status=QuantumStatus.UNKNOWN,
            quantum_threat=QuantumThreat.NONE,
            business_criticality=Criticality.LOW,
            metadata={"error": str(e)}
        )
        artefacts.append(error_art)
        
    return artefacts
