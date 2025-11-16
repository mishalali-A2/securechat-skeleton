from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

def load_private_key(pem: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem, password=password, backend=default_backend())

def load_public_key_from_cert(cert_pem: bytes):
    cert = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
    return cert.public_key()

def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

def verify_bytes(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def b64sig(sig: bytes) -> str:
    return base64.b64encode(sig).decode()

def b64desig(s: str) -> bytes:
    return base64.b64decode(s.encode())
