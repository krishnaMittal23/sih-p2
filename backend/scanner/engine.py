import os
import re
import uuid
from typing import List, Dict, Any, Optional
from ..models import (
    CryptographicArtefact,
    CryptoType,
    Criticality
)
from ..analyzer.quantum_risk import evaluate_quantum_risk_for_artefact
from ..analyzer.pqc_advisor import get_pqc_recommendation

PATTERN_RULES = [
    {
        "name": "RSA Key Generation",
        "pattern": r"(?:RSA\.generate\s*\(\s*(\d+)|KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"'].*?\.initialize\s*\(\s*(\d+)|RSACryptoServiceProvider\s*\(\s*(\d+)|crypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"].*?modulusLength:\s*(\d+)|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA|rsa_generate_key\s*\(\s*(\d+))",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "RSA",
        "key_group_indices": [1, 2, 3, 4, 5],
        "default_key_size": 2048,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "RSA Cipher / Signature Usage",
        "pattern": r"(?:Cipher\.getInstance\s*\(\s*[\"']RSA(?:/[^\"']+)?[\"']|PKCS1_OAEP\.new|PKCS1_v1_5\.new|crypto\.publicEncrypt|RSASSA-PKCS1-v1_5|RSA-PSS|EVP_PKEY_sign_init|RSA_sign\b)",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "RSA",
        "key_group_indices": [],
        "default_key_size": 2048,
        "criticality": Criticality.HIGH
    },
    {
        "name": "ECDSA / Elliptic Curve",
        "pattern": r"(?:ECDsa\.Create|KeyPairGenerator\.getInstance\s*\(\s*[\"']EC[\"']|ec\.generate_private_key\s*\(\s*ec\.(SECP\w+|Prime\w+)|crypto\.createSign\s*\(\s*[\"'](?:SHA256withECDSA|ecdsa)[\"']|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC|namedCurve:\s*[\"']([a-zA-Z0-9_-]+)[\"'])",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "ECDSA",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.HIGH
    },
    {
        "name": "ECDH Key Exchange",
        "pattern": r"(?:ECDH\.Create|KeyAgreement\.getInstance\s*\(\s*[\"']ECDH[\"']|ecdh\.computeSecret|EVP_PKEY_derive_init|x25519\.ScalarMult|X25519Agreement)",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "ECDH",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "Diffie-Hellman Key Exchange",
        "pattern": r"(?:crypto\.createDiffieHellman\s*\(\s*(\d+)|KeyPairGenerator\.getInstance\s*\(\s*[\"']DH[\"']|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_DH|DH_new\(\))",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "DIFFIE-HELLMAN",
        "key_group_indices": [1],
        "default_key_size": 2048,
        "criticality": Criticality.HIGH
    },
    {
        "name": "Ed25519 Signatures",
        "pattern": r"(?:ed25519\.GenerateKey|Ed25519Signer|crypto_sign_ed25519|Ed25519PrivateKey\.generate|crypto\.createSign\s*\(\s*[\"']ed25519[\"'])",
        "type": CryptoType.ASYMMETRIC,
        "algo_default": "ED25519",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.HIGH
    },
    {
        "name": "AES-128 Encryption",
        "pattern": r"(?:AES\.new\(.*?AES\.block_size.*?|Cipher\.getInstance\s*\(\s*[\"']AES/(?:CBC|ECB|GCM|CTR)/.*?[\"'].*?128|crypto\.createCipheriv\s*\(\s*[\"']aes-128-(?:gcm|cbc|ctr|ecb)[\"']|EVP_aes_128_(?:gcm|cbc|ctr|ecb)|aes128\.NewCipher|AesManaged.*?KeySize\s*=\s*128|AES-128)",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "AES-128",
        "key_group_indices": [],
        "default_key_size": 128,
        "criticality": Criticality.HIGH
    },
    {
        "name": "AES-128-CBC (Java SecretKeySpec 16-byte)",
        "pattern": r"(?:Cipher\.getInstance\s*\(\s*[\"']AES/(?:CBC|ECB|GCM|CTR)[^\"']*[\"']|SecretKeySpec\s*\([^,]+,\s*0,\s*16\s*,\s*[\"']AES[\"'])",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "AES-128",
        "key_group_indices": [],
        "default_key_size": 128,
        "criticality": Criticality.HIGH
    },
    {
        "name": "AES-256 Encryption",
        "pattern": r"(?:crypto\.createCipheriv\s*\(\s*[\"']aes-256-(?:gcm|cbc|ctr|ecb)[\"']|EVP_aes_256_(?:gcm|cbc|ctr|ecb)|aes256\.NewCipher|AesManaged.*?KeySize\s*=\s*256|Cipher\.getInstance\s*\(\s*[\"']AES/(?:CBC|ECB|GCM)/.*?[\"'].*?256|AES-256)",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "AES-256",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.MEDIUM
    },
    {
        "name": "DES / Triple-DES Legacy Cipher",
        "pattern": r"(?:DES\.new\b|DESede\b|TripleDES\.Create|Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede)[\"']|crypto\.createCipheriv\s*\(\s*[\"']des-[\w-]+[\"']|EVP_des_ede3_cbc|DES_set_key)",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "3DES",
        "key_group_indices": [],
        "default_key_size": 112,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "Blowfish Cipher",
        "pattern": r"(?:Blowfish\.new\b|Cipher\.getInstance\s*\(\s*[\"']Blowfish[\"']|crypto\.createCipheriv\s*\(\s*[\"']bf-[\w-]+[\"']|EVP_bf_cbc|BF_set_key)",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "BLOWFISH",
        "key_group_indices": [],
        "default_key_size": 128,
        "criticality": Criticality.HIGH
    },
    {
        "name": "RC4 Legacy Stream Cipher",
        "pattern": r"(?:ARC4\.new\b|Cipher\.getInstance\s*\(\s*[\"']RC4[\"']|crypto\.createCipheriv\s*\(\s*[\"']rc4[\"']|RC4_set_key|crypto/rc4)",
        "type": CryptoType.SYMMETRIC,
        "algo_default": "RC4",
        "key_group_indices": [],
        "default_key_size": 128,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "MD5 Hash Function",
        "pattern": r"(?:hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']|crypto\.createHash\s*\(\s*[\"']md5[\"']|MD5_Init\b|md5\.Sum\b|MD5CryptoServiceProvider)",
        "type": CryptoType.HASH,
        "algo_default": "MD5",
        "key_group_indices": [],
        "default_key_size": 128,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "SHA-1 Hash Function",
        "pattern": r"(?:hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']|crypto\.createHash\s*\(\s*[\"']sha1[\"']|SHA1_Init\b|sha1\.Sum\b|SHA1Managed)",
        "type": CryptoType.HASH,
        "algo_default": "SHA-1",
        "key_group_indices": [],
        "default_key_size": 160,
        "criticality": Criticality.HIGH
    },
    {
        "name": "SHA-256 Hash Function",
        "pattern": r"(?:hashlib\.sha256\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?256[\"']|crypto\.createHash\s*\(\s*[\"']sha256[\"']|SHA256_Init\b|sha256\.Sum256\b|SHA256Managed)",
        "type": CryptoType.HASH,
        "algo_default": "SHA-256",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.LOW
    },
    {
        "name": "SHA-384 / SHA-512 Hash Function",
        "pattern": r"(?:hashlib\.sha(?:384|512)\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?(?:384|512)[\"']|crypto\.createHash\s*\(\s*[\"']sha(?:384|512)[\"']|SHA512_Init\b|sha512\.Sum512\b)",
        "type": CryptoType.HASH,
        "algo_default": "SHA-512",
        "key_group_indices": [],
        "default_key_size": 512,
        "criticality": Criticality.LOW
    },
    {
        "name": "Legacy TLS 1.0 / 1.1 Protocol",
        "pattern": r"(?:ssl\.PROTOCOL_TLSv1(?:_1)?\b|TLSv1_(?:client|server)_method|tls\.VersionTLS10\b|tls\.VersionTLS11\b|SecurityProtocolType\.Tls11?\b|min_version\s*=\s*[\"']TLSv1[\"'])",
        "type": CryptoType.PROTOCOL,
        "algo_default": "TLS 1.0",
        "key_group_indices": [],
        "default_key_size": None,
        "criticality": Criticality.CRITICAL
    },
    {
        "name": "TLS 1.2 Protocol",
        "pattern": r"(?:ssl\.PROTOCOL_TLSv1_2\b|TLSv1_2_(?:client|server)_method|tls\.VersionTLS12\b|SecurityProtocolType\.Tls12\b|ssl_protocols.*?TLSv1\.2)",
        "type": CryptoType.PROTOCOL,
        "algo_default": "TLS 1.2",
        "key_group_indices": [],
        "default_key_size": None,
        "criticality": Criticality.HIGH
    },
    {
        "name": "NIST Post-Quantum ML-KEM / Kyber",
        "pattern": r"(?:ml[-_]?kem[-_]?\d*|Kyber(?:512|768|1024)?|OQS_KEM_kyber|X25519MLKEM768|X25519Kyber768Draft00|pqcrypto\.kem\.kyber)",
        "type": CryptoType.KEM,
        "algo_default": "ML-KEM-768",
        "key_group_indices": [],
        "default_key_size": 1184,
        "criticality": Criticality.LOW
    },
    {
        "name": "NIST Post-Quantum ML-DSA / Dilithium",
        "pattern": r"(?:ml[-_]?dsa[-_]?\d*|Dilithium(?:2|3|5)?|OQS_SIG_dilithium|pqcrypto\.sign\.dilithium|ML-DSA-65)",
        "type": CryptoType.SIGNATURE,
        "algo_default": "ML-DSA-65",
        "key_group_indices": [],
        "default_key_size": 1952,
        "criticality": Criticality.LOW
    },
    {
        "name": "NIST Post-Quantum SLH-DSA / SPHINCS+",
        "pattern": r"(?:slh_dsa_\w+|SPHINCS\+|OQS_SIG_sphincs|pqcrypto\.sign\.sphincs)",
        "type": CryptoType.SIGNATURE,
        "algo_default": "SLH-DSA",
        "key_group_indices": [],
        "default_key_size": 1024,
        "criticality": Criticality.LOW
    },
    {
        "name": "Cloud / HSM Cryptographic Key Service",
        "pattern": r"(?:boto3\.client\s*\(\s*['\"]kms['\"]|kms_client\.encrypt|SecretClient|KeyClient|CloudKmsClient|PKCS11_CTX_new|CK_MECHANISM)",
        "type": CryptoType.LIBRARY,
        "algo_default": "KMS-HSM-SERVICE",
        "key_group_indices": [],
        "default_key_size": 256,
        "criticality": Criticality.HIGH
    }
]

EXTENSIONS_TO_SCAN = {
    ".py", ".java", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".go", ".js", ".jsx", ".ts", ".tsx", ".rs", ".cs",
    ".php", ".rb", ".sh", ".yaml", ".yml", ".json", ".conf",
    ".properties", ".pem", ".crt", ".cer", ".der"
}

IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", "venv", ".venv",
    "__pycache__", ".idea", ".vscode", "vendor", "target", ".next"
}

# Comment-line prefixes to skip (avoids false positives from commented-out code)
COMMENT_PREFIXES = ("#", "//", "*", "/*", "*/", "\"\"\"", "'\"'")

def _is_comment_or_doc_line(line_clean: str) -> bool:
    """Return True if the line is a pure comment, docstring, or doc line."""
    stripped = line_clean.lstrip()
    for prefix in ("#", "//", "*", "/*", "*/"):
        if stripped.startswith(prefix):
            return True
    # Python docstring lines (inside triple-quote blocks)
    if stripped.startswith('"""') or stripped.startswith("'''"):
        return True
    return False

def scan_file_for_artefacts(file_path: str, base_dir: str) -> List[CryptographicArtefact]:
    artefacts = []
    rel_path = os.path.relpath(file_path, base_dir).replace("\\", "/")
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return artefacts

    # Per-file deduplication: track (algo, key_size) -> hit count
    # Allow at most MAX_HITS_PER_ALGO distinct hits per algo per file
    MAX_HITS_PER_ALGO = 2
    algo_hit_count: dict = {}

    for line_idx, line in enumerate(lines, start=1):
        line_clean = line.strip()
        if not line_clean or len(line_clean) > 800:
            continue

        # Skip pure comment / docstring lines to reduce false-positives
        if _is_comment_or_doc_line(line_clean):
            continue
            
        for rule in PATTERN_RULES:
            match = re.search(rule["pattern"], line, re.IGNORECASE)
            if match:
                key_size = rule["default_key_size"]
                for g_idx in rule["key_group_indices"]:
                    try:
                        extracted = match.group(g_idx)
                        if extracted and extracted.isdigit():
                            key_size = int(extracted)
                            break
                    except IndexError:
                        pass
                
                algo = rule["algo_default"]
                # Refine RSA key size from line content
                if "RSA" in algo:
                    if "1024" in line:
                        key_size = 1024
                    elif "4096" in line:
                        key_size = 4096
                    elif "3072" in line:
                        key_size = 3072
                    elif "2048" in line:
                        key_size = 2048

                # Refine AES key size from SecretKeySpec byte count (Java pattern)
                if "AES" in algo:
                    aes_key_match = re.search(r'SecretKeySpec\s*\([^,]+,\s*0,\s*(\d+)', line, re.IGNORECASE)
                    if aes_key_match:
                        byte_count = int(aes_key_match.group(1))
                        key_size = byte_count * 8  # bytes -> bits
                        if key_size == 128:
                            algo = "AES-128"
                        elif key_size == 192:
                            algo = "AES-192"
                        elif key_size == 256:
                            algo = "AES-256"

                # Enforce per-file dedup limit
                dedup_key = (algo, key_size)
                current_count = algo_hit_count.get(dedup_key, 0)
                if current_count >= MAX_HITS_PER_ALGO:
                    break  # Skip this algo — already captured enough occurrences in this file
                algo_hit_count[dedup_key] = current_count + 1

                q_status, q_threat, risk_score = evaluate_quantum_risk_for_artefact(
                    algo, key_size, rule["criticality"]
                )
                recommendation = get_pqc_recommendation(algo, key_size)
                
                art_id = f"art-{uuid.uuid4().hex[:10]}"
                artefact = CryptographicArtefact(
                    id=art_id,
                    name=rule["name"],
                    type=rule["type"],
                    algorithm=algo,
                    key_size=key_size,
                    file_path=rel_path,
                    line_number=line_idx,
                    code_snippet=line_clean[:200],
                    quantum_status=q_status,
                    quantum_threat=q_threat,
                    business_criticality=rule["criticality"],
                    quantum_risk_score=risk_score,
                    recommended_replacement=recommendation.recommended_pqc if recommendation else None,
                    recommendation_details=recommendation,
                    metadata={
                        "rule_matched": rule["name"],
                        "full_path": file_path.replace("\\", "/")
                    }
                )
                artefacts.append(artefact)
                break
                
    return artefacts

def scan_directory_for_crypto(
    target_path: str,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> List[CryptographicArtefact]:
    all_artefacts = []
    
    if not os.path.exists(target_path):
        return all_artefacts
        
    if os.path.isfile(target_path):
        return scan_file_for_artefacts(target_path, os.path.dirname(target_path))

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in EXTENSIONS_TO_SCAN:
                continue
                
            full_path = os.path.join(root, file)
            file_artefacts = scan_file_for_artefacts(full_path, target_path)
            all_artefacts.extend(file_artefacts)
            
    return all_artefacts
