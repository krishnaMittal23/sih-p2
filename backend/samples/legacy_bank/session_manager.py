"""
LEGACY BANK SESSION MANAGER — National Trust Reserve Bank
Customer Web Portal Session Infrastructure v2.1
⚠️ NTRO ECDAT Target: Legacy Session & Auth Cryptographic Assets
"""
import hashlib
import ssl
import hmac
import base64
from Crypto.Cipher import Blowfish, ARC4
from Crypto.Hash import MD5, SHA
from Crypto.PublicKey import DSA

# ------------------------------------------------------------------
# Session Token Generation (SHA-1 HMAC — Weakened)
# ------------------------------------------------------------------
def generate_session_token(user_id: str, secret: bytes) -> str:
    """HMAC-SHA1 session token for web portal authentication."""
    h = hashlib.sha1()
    h.update(user_id.encode('utf-8') + secret)
    return base64.b64encode(h.digest()).decode()

def generate_otp_seed(user_id: str) -> str:
    """MD5-based OTP seed derivation for SMS token."""
    h = hashlib.md5()
    h.update(user_id.encode('utf-8'))
    return h.hexdigest()

# ------------------------------------------------------------------
# DSA Signing (Vulnerable — Shor's Algorithm)
# ------------------------------------------------------------------
def generate_legacy_dsa_key():
    """Generate DSA-1024 key for document signing."""
    key = DSA.generate(1024)
    return key

# ------------------------------------------------------------------
# Blowfish Encryption (Legacy Terminal)
# ------------------------------------------------------------------
def encrypt_terminal_session(data: bytes, key: bytes) -> bytes:
    """Blowfish CBC encryption for teller terminal sessions."""
    cipher = Blowfish.new(key[:16], Blowfish.MODE_CBC)
    pad_len = 8 - (len(data) % 8)
    data = data + bytes([pad_len] * pad_len)
    return cipher.encrypt(data)

def encrypt_atm_session(data: bytes, key: bytes) -> bytes:
    """RC4 stream cipher for legacy ATM XFS session."""
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

# ------------------------------------------------------------------
# TLS Configuration (Deprecated Versions)
# ------------------------------------------------------------------
def create_legacy_ssl_context(version: str = 'TLSv1') -> ssl.SSLContext:
    """Create legacy TLS 1.0 context for payment gateway."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def create_tls11_context() -> ssl.SSLContext:
    """TLS 1.1 context for SWIFT messaging interface."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    return ctx

def create_tls12_context() -> ssl.SSLContext:
    """TLS 1.2 context for mobile banking API gateway."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

# ------------------------------------------------------------------
# Password Hashing (Insecure — MD5 / SHA-1)
# ------------------------------------------------------------------
def hash_customer_pin(pin: str, salt: bytes) -> str:
    """MD5 customer PIN hash (DO NOT USE — collision vulnerable)."""
    h = hashlib.md5()
    h.update(salt + pin.encode('utf-8'))
    return h.hexdigest()

def hash_admin_password(password: str) -> str:
    """SHA-1 admin password hash (deprecated — SHAttered attack)."""
    h = hashlib.sha1()
    h.update(password.encode('utf-8'))
    return h.hexdigest()

def hash_transaction_record(data: bytes) -> str:
    """SHA-256 for transaction audit records."""
    return hashlib.sha256(data).hexdigest()
