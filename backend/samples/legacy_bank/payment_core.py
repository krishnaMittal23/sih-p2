"""
LEGACY BANK CORE — National Trust Reserve Bank
Payment Processing Infrastructure v1.4.2 (circa 2008)
⚠️ NTRO ECDAT Demo Target: Legacy Cryptographic Asset Repository
"""
import hashlib
import ssl
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, ARC4, PKCS1_v1_5, Blowfish
from Crypto.Signature import pkcs1_15

# ------------------------------------------------------------------
# Key Management: RSA-1024 (DEPRECATED — Shor's Algorithm Risk)
# ------------------------------------------------------------------
def init_legacy_identity_keys():
    """Generate RSA-1024 identity keypair for customer auth tokens."""
    key = RSA.generate(1024)
    public_key = key.publickey()
    return key, public_key

def init_intermediate_keys():
    """RSA-2048 for branch-to-clearing-house authentication."""
    key = RSA.generate(2048)
    return key

def sign_transaction_bundle(bundle: bytes, rsa_key):
    """PKCS1_v1_5 signature over transaction bundle."""
    h = hashlib.sha1()
    h.update(bundle)
    signer = PKCS1_v1_5.new(rsa_key)
    return signer.sign(h)

# ------------------------------------------------------------------
# Symmetric Encryption: DES / 3DES (DEPRECATED — Sweet32 + Quantum)
# ------------------------------------------------------------------
def encrypt_pin_block(pin_data: bytes, key_bytes: bytes) -> bytes:
    """DES-ECB PIN block encryption for ATM interface."""
    cipher = DES.new(key_bytes[:8], DES.MODE_ECB)
    return cipher.encrypt(pin_data.ljust(8, b'\0'))

def encrypt_interbank_payload(data: bytes, key_bytes: bytes) -> bytes:
    """3DES-CBC for inter-bank clearing messages (ISO 8583)."""
    from Crypto.Cipher import DES3
    cipher = DES3.new(key_bytes[:24], DES3.MODE_CBC)
    return cipher.encrypt(data.ljust(len(data) + (8 - len(data) % 8) % 8, b'\0'))

def encrypt_session_blowfish(data: bytes, key: bytes) -> bytes:
    """Blowfish session encryption for legacy teller terminals."""
    cipher = Blowfish.new(key[:16], Blowfish.MODE_CBC)
    return cipher.encrypt(data)

# ------------------------------------------------------------------
# Stream Cipher: RC4 (BANNED — RFC 7465)
# ------------------------------------------------------------------
def stream_session_encrypt(stream_data: bytes, session_key: bytes) -> bytes:
    """RC4 stream cipher for legacy terminal multiplexer."""
    cipher = ARC4.new(session_key)
    return cipher.encrypt(stream_data)

# ------------------------------------------------------------------
# Hash Functions: MD5 / SHA-1 (DEPRECATED — Collision Attacks)
# ------------------------------------------------------------------
def compute_legacy_checksum(payload: bytes) -> str:
    """MD5 checksum for batch transaction reconciliation."""
    h = hashlib.md5()
    h.update(payload)
    return h.hexdigest()

def compute_user_signature(payload: bytes) -> str:
    """SHA-1 digest for legacy digital envelope."""
    h = hashlib.sha1()
    h.update(payload)
    return h.hexdigest()

def compute_record_integrity(payload: bytes) -> str:
    """SHA-256 for transaction record hash (weakened under Grover)."""
    return hashlib.sha256(payload).hexdigest()

# ------------------------------------------------------------------
# TLS: Legacy Protocol Versions (DEPRECATED — RFC 8996)
# ------------------------------------------------------------------
def connect_legacy_payment_switch(host: str, port: int):
    """TLS 1.0 socket connection to core banking switch."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.set_ciphers('DES-CBC3-SHA:RC4-SHA')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))
    return tls_sock

def connect_interbank_clearing(host: str, port: int):
    """TLS 1.1 connection to interbank clearing network."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))
    return tls_sock
