from typing import Dict, Optional, Tuple
from ..models import PQCRecommendation, QuantumStatus, QuantumThreat, CryptoType

PQC_KNOWLEDGE_BASE = {
    "RSA-1024": {
        "replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "standard": "NIST FIPS 203 & 204",
        "category": 3,
        "classical_bits": 80,
        "quantum_bits": 0,
        "key_overhead": "+800% (1184 bytes public key vs 128 bytes)",
        "overhead": "+1088 bytes ciphertext",
        "computational": "Up to 5x faster key exchange, negligible latency delta",
        "urgency": "IMMEDIATE",
        "guide": "Replace RSA-1024 immediately. For TLS key exchange, use X25519Kyber768Draft00. For digital certificates, transition to ML-DSA-65 or hybrid ECDSA+ML-DSA."
    },
    "RSA-2048": {
        "replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "standard": "NIST FIPS 203 & 204",
        "category": 3,
        "classical_bits": 112,
        "quantum_bits": 0,
        "key_overhead": "+360% (1184 bytes public key vs 256 bytes)",
        "overhead": "+1088 bytes ciphertext, +2420 bytes signature",
        "computational": "3x faster encryption/verification, slightly larger MTU footprint",
        "urgency": "HIGH",
        "guide": "RSA-2048 is completely broken under Shor's algorithm on a ~4096 logical qubit CRQC. Upgrade to ML-KEM-768 for KEM and ML-DSA-65 for signing."
    },
    "RSA-3072": {
        "replacement": "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
        "standard": "NIST FIPS 203 & 204",
        "category": 3,
        "classical_bits": 128,
        "quantum_bits": 0,
        "key_overhead": "+208% (1184 bytes public key vs 384 bytes)",
        "overhead": "+1088 bytes ciphertext",
        "computational": "4x faster keygen and decapsulation than 3072-bit modular exponentiation",
        "urgency": "HIGH",
        "guide": "Transition to ML-KEM-768 (NIST Level 3) or hybrid X25519+ML-KEM-768 for forward secrecy against Harvest Now, Decrypt Later threats."
    },
    "RSA-4096": {
        "replacement": "ML-KEM-1024 (FIPS 203) / ML-DSA-87 (FIPS 204)",
        "standard": "NIST FIPS 203 & 204",
        "category": 5,
        "classical_bits": 140,
        "quantum_bits": 0,
        "key_overhead": "+200% (1568 bytes public key vs 512 bytes)",
        "overhead": "+1568 bytes ciphertext, +4595 bytes signature",
        "computational": "Significantly faster execution than 4096-bit RSA modular operations",
        "urgency": "HIGH",
        "guide": "Adopt ML-KEM-1024 (NIST Security Category 5 - matching AES-256 strength). Use SLH-DSA-256 for long-term document signing."
    },
    "ECDSA": {
        "replacement": "ML-DSA-65 (FIPS 204) / SLH-DSA-SHA2-128s (FIPS 205)",
        "standard": "NIST FIPS 204 & 205",
        "category": 3,
        "classical_bits": 128,
        "quantum_bits": 0,
        "key_overhead": "+1850% (1952 bytes public key vs 64 bytes)",
        "overhead": "+3293 bytes signature vs 64 bytes",
        "computational": "Comparable verification speed, increased transport packet size",
        "urgency": "HIGH",
        "guide": "Elliptic curve discrete logarithm breaks under Shor's algorithm with ~2330 qubits. Transition to ML-DSA-65 or hybrid ECDSA-P256+ML-DSA-44."
    },
    "ECDH": {
        "replacement": "ML-KEM-768 (FIPS 203) or Hybrid X25519+ML-KEM-768",
        "standard": "NIST FIPS 203 & RFC 9370",
        "category": 3,
        "classical_bits": 128,
        "quantum_bits": 0,
        "key_overhead": "+3600% (1184 bytes vs 32 bytes)",
        "overhead": "+1088 bytes encapsulation payload",
        "computational": "Sub-millisecond encapsulation and decapsulation",
        "urgency": "CRITICAL",
        "guide": "Vulnerable to Harvest Now, Decrypt Later (HNDL). Switch TLS key exchanges to Hybrid X25519+ML-KEM-768 immediately to protect high-confidentiality transit."
    },
    "DIFFIE-HELLMAN": {
        "replacement": "ML-KEM-768 (FIPS 203) or Hybrid ECDH+ML-KEM",
        "standard": "NIST FIPS 203",
        "category": 3,
        "classical_bits": 112,
        "quantum_bits": 0,
        "key_overhead": "+300% to +800% depending on DH group modulus",
        "overhead": "+1088 bytes ciphertext",
        "computational": "Substantially faster than finite-field modular exponentiation",
        "urgency": "HIGH",
        "guide": "Deprecate finite-field DH parameters. Migrate to lattice-based ML-KEM-768 key encapsulation."
    },
    "ED25519": {
        "replacement": "ML-DSA-44 (FIPS 204) / SLH-DSA-SHAKE-128f (FIPS 205)",
        "standard": "NIST FIPS 204",
        "category": 2,
        "classical_bits": 128,
        "quantum_bits": 0,
        "key_overhead": "+4000% (1312 bytes public key vs 32 bytes)",
        "overhead": "+2420 bytes signature vs 64 bytes",
        "computational": "Fast verification, verify network MTU fragmentation handling",
        "urgency": "HIGH",
        "guide": "Edwards-curve signatures are fully Shor-vulnerable. Transition to ML-DSA-44 or SLH-DSA for stateless hash-based assurance."
    },
    "AES-128": {
        "replacement": "AES-256-GCM / ChaCha20-Poly1305 (256-bit)",
        "standard": "NIST SP 800-38D / FIPS 197",
        "category": 5,
        "classical_bits": 128,
        "quantum_bits": 64,
        "key_overhead": "+100% (32-byte key vs 16-byte key)",
        "overhead": "0 bytes additional ciphertext overhead",
        "computational": "< 1% performance variation with AES-NI hardware acceleration",
        "urgency": "MEDIUM",
        "guide": "Grover's algorithm reduces 128-bit key search complexity to 2^64 operations. Double key size to AES-256 to guarantee 128 bits of post-quantum security."
    },
    "AES-192": {
        "replacement": "AES-256-GCM",
        "standard": "NIST SP 800-38D",
        "category": 5,
        "classical_bits": 192,
        "quantum_bits": 96,
        "key_overhead": "+33% (32-byte key vs 24-byte key)",
        "overhead": "0 bytes",
        "computational": "Negligible difference with AES-NI instructions",
        "urgency": "LOW",
        "guide": "Standardize on AES-256 across all symmetric encryption layers."
    },
    "3DES": {
        "replacement": "AES-256-GCM",
        "standard": "NIST SP 800-131A Rev 2",
        "category": 5,
        "classical_bits": 112,
        "quantum_bits": 0,
        "key_overhead": "+33% key size",
        "overhead": "No overhead, modern authenticated encryption",
        "computational": "6x faster than legacy software 3DES iterations",
        "urgency": "CRITICAL",
        "guide": "3DES is classically insecure (Sweet32 64-bit block collision) and completely quantum obsolete. Replace immediately with AES-256-GCM."
    },
    "DES": {
        "replacement": "AES-256-GCM",
        "standard": "NIST FIPS 197",
        "category": 5,
        "classical_bits": 56,
        "quantum_bits": 0,
        "key_overhead": "4x key size",
        "overhead": "Zero",
        "computational": "Significantly faster with hardware acceleration",
        "urgency": "CRITICAL",
        "guide": "DES has 56-bit key broken classically in hours. Replace with AES-256-GCM immediately."
    },
    "BLOWFISH": {
        "replacement": "AES-256-GCM / ChaCha20-Poly1305",
        "standard": "NIST FIPS 197",
        "category": 5,
        "classical_bits": 128,
        "quantum_bits": 64,
        "key_overhead": "Standard 256-bit key",
        "overhead": "Zero",
        "computational": "Modern SIMD acceleration",
        "urgency": "HIGH",
        "guide": "Blowfish suffers from 64-bit block size Sweet32 vulnerabilities and Grover weakening. Replace with AES-256-GCM."
    },
    "RC4": {
        "replacement": "AES-256-GCM / ChaCha20-Poly1305",
        "standard": "RFC 7465 / RFC 8439",
        "category": 5,
        "classical_bits": 0,
        "quantum_bits": 0,
        "key_overhead": "256-bit key",
        "overhead": "AEAD 16-byte authentication tag",
        "computational": "Hardware accelerated",
        "urgency": "CRITICAL",
        "guide": "RC4 is prohibited in RFC 7465. Replace with AES-256-GCM or ChaCha20-Poly1305."
    },
    "MD5": {
        "replacement": "SHA-384 / SHA3-384 / BLAKE3",
        "standard": "NIST FIPS 180-4 / FIPS 202",
        "category": 4,
        "classical_bits": 0,
        "quantum_bits": 0,
        "key_overhead": "48-byte hash output vs 16-byte",
        "overhead": "+32 bytes digest",
        "computational": "Hardware SHA acceleration",
        "urgency": "CRITICAL",
        "guide": "MD5 has practical collision attacks. Upgrade to SHA-384 or SHA3-384."
    },
    "SHA-1": {
        "replacement": "SHA-384 / SHA3-384",
        "standard": "NIST SP 800-131A Rev 2",
        "category": 4,
        "classical_bits": 0,
        "quantum_bits": 0,
        "key_overhead": "48-byte output vs 20-byte",
        "overhead": "+28 bytes digest",
        "computational": "Negligible overhead",
        "urgency": "CRITICAL",
        "guide": "SHA-1 collision resistance is broken (SHAttered attack). Migrate to SHA-384 or SHA-512."
    },
    "SHA-256": {
        "replacement": "SHA-384 / SHA-512 / SHA3-384",
        "standard": "NIST FIPS 180-4 / FIPS 202",
        "category": 4,
        "classical_bits": 256,
        "quantum_bits": 128,
        "key_overhead": "48-byte or 64-byte digest",
        "overhead": "+16 to +32 bytes digest",
        "computational": "64-bit architectures execute SHA-512 faster than SHA-256",
        "urgency": "LOW",
        "guide": "SHA-256 has 128 bits of preimage resistance against Grover. For long-term quantum security margin, use SHA-384 or SHA-512."
    },
    "TLS 1.0": {
        "replacement": "TLS 1.3 with Hybrid ML-KEM Key Exchange",
        "standard": "RFC 8446 & IETF Hybrid Draft",
        "category": 3,
        "classical_bits": 0,
        "quantum_bits": 0,
        "key_overhead": "Supports modern cipher suites and post-quantum extensions",
        "overhead": "Reduced handshake latency (1-RTT / 0-RTT)",
        "computational": "Significantly faster handshake than TLS 1.0/1.1",
        "urgency": "CRITICAL",
        "guide": "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST/POODLE attacks. Upgrade to TLS 1.3 configured with X25519Kyber768 draft key exchange groups."
    },
    "TLS 1.1": {
        "replacement": "TLS 1.3 with Hybrid ML-KEM Key Exchange",
        "standard": "RFC 8446 & IETF Hybrid Draft",
        "category": 3,
        "classical_bits": 0,
        "quantum_bits": 0,
        "key_overhead": "Modern cryptographic extensions",
        "overhead": "1-RTT handshake",
        "computational": "Faster negotiation",
        "urgency": "CRITICAL",
        "guide": "TLS 1.1 is deprecated (RFC 8996). Migrate directly to TLS 1.3 with post-quantum key encapsulation."
    },
    "TLS 1.2": {
        "replacement": "TLS 1.3 with Hybrid ML-KEM Key Exchange",
        "standard": "RFC 8446 & IETF Hybrid Draft",
        "category": 3,
        "classical_bits": 128,
        "quantum_bits": 0,
        "key_overhead": "PQC hybrid group negotiation",
        "overhead": "Reduced round trips",
        "computational": "0-RTT / 1-RTT handshake with modern AEAD ciphers",
        "urgency": "HIGH",
        "guide": "Upgrade TLS 1.2 connections to TLS 1.3 to leverage hybrid post-quantum key exchange groups such as X25519MLKEM768."
    }
}

def get_pqc_recommendation(algorithm_name: str, key_size: Optional[int] = None) -> Optional[PQCRecommendation]:
    algo_clean = algorithm_name.upper().strip()
    lookup_key = None
    
    if "RSA" in algo_clean:
        if key_size:
            if key_size <= 1024:
                lookup_key = "RSA-1024"
            elif key_size <= 2048:
                lookup_key = "RSA-2048"
            elif key_size <= 3072:
                lookup_key = "RSA-3072"
            else:
                lookup_key = "RSA-4096"
        else:
            if "1024" in algo_clean:
                lookup_key = "RSA-1024"
            elif "4096" in algo_clean:
                lookup_key = "RSA-4096"
            elif "3072" in algo_clean:
                lookup_key = "RSA-3072"
            else:
                lookup_key = "RSA-2048"
    elif "ECDSA" in algo_clean or "SECP" in algo_clean or "PRIME256" in algo_clean:
        lookup_key = "ECDSA"
    elif "ECDH" in algo_clean or "X25519" in algo_clean and "KYBER" not in algo_clean and "MLKEM" not in algo_clean:
        lookup_key = "ECDH"
    elif "ED25519" in algo_clean or "ED448" in algo_clean:
        lookup_key = "ED25519"
    elif "DIFFIE-HELLMAN" in algo_clean or "DH" == algo_clean or "DHE" in algo_clean:
        lookup_key = "DIFFIE-HELLMAN"
    elif "AES" in algo_clean:
        if key_size == 128 or "128" in algo_clean:
            lookup_key = "AES-128"
        elif key_size == 192 or "192" in algo_clean:
            lookup_key = "AES-192"
        else:
            return None
    elif "3DES" in algo_clean or "DES-EDE" in algo_clean or "TRIPLEDES" in algo_clean:
        lookup_key = "3DES"
    elif "DES" in algo_clean:
        lookup_key = "DES"
    elif "BLOWFISH" in algo_clean:
        lookup_key = "BLOWFISH"
    elif "RC4" in algo_clean or "ARCFOUR" in algo_clean:
        lookup_key = "RC4"
    elif "MD5" in algo_clean:
        lookup_key = "MD5"
    elif "SHA-1" in algo_clean or "SHA1" in algo_clean:
        lookup_key = "SHA-1"
    elif "SHA-256" in algo_clean or "SHA256" in algo_clean:
        lookup_key = "SHA-256"
    elif "TLS" in algo_clean:
        if "1.0" in algo_clean:
            lookup_key = "TLS 1.0"
        elif "1.1" in algo_clean:
            lookup_key = "TLS 1.1"
        elif "1.2" in algo_clean:
            lookup_key = "TLS 1.2"

    if lookup_key and lookup_key in PQC_KNOWLEDGE_BASE:
        data = PQC_KNOWLEDGE_BASE[lookup_key]
        return PQCRecommendation(
            legacy_algorithm=lookup_key,
            recommended_pqc=data["replacement"],
            nist_standard=data["standard"],
            security_category=data["category"],
            classical_security_bits=data["classical_bits"],
            quantum_security_bits=data["quantum_bits"],
            public_key_overhead=data["key_overhead"],
            ciphertext_or_sig_overhead=data["overhead"],
            computational_overhead=data["computational"],
            migration_urgency=data["urgency"],
            code_migration_guide=data["guide"]
        )
    return None
