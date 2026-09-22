import hashlib
import ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, ARC4, PKCS1_v1_5
import socket

def init_legacy_keys():
    key = RSA.generate(1024)
    public_key = key.publickey()
    return key, public_key

def encrypt_pin_block(pin_data: bytes, key_bytes: bytes):
    cipher = DES.new(key_bytes[:8], DES.MODE_ECB)
    return cipher.encrypt(pin_data.ljust(8, b'\0'))

def stream_session_encrypt(stream_data: bytes, session_key: bytes):
    cipher = ARC4.new(session_key)
    return cipher.encrypt(stream_data)

def compute_legacy_checksum(payload: bytes):
    h = hashlib.md5()
    h.update(payload)
    return h.hexdigest()

def compute_user_signature(payload: bytes):
    h = hashlib.sha1()
    h.update(payload)
    return h.hexdigest()

def connect_legacy_payment_switch(host: str, port: int):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    tls_sock.connect((host, port))
    return tls_sock
