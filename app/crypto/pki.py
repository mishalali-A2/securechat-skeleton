from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import datetime

def load_cert(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem, backend=default_backend())

def verify_cert_chain(cert_pem: bytes, ca_cert_pem: bytes, expected_cn: str = None) -> bool:
    cert = load_cert(cert_pem)
    ca = load_cert(ca_cert_pem)
    # 1. check signature: verify cert signed by CA's public key
    ca_pub = ca.public_key()
    try:
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                      padding.PKCS1v15(), cert.signature_hash_algorithm)
    except Exception:
        return False
    # 2. check validity dates
    now = datetime.datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        return False
    # 3. check CN if provided
    if expected_cn:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            return False
    return True

def create_self_signed_ca(name_cn: str, key: rsa.RSAPrivateKey, days=3650):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name_cn)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
        .public_key(key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(key, hashes.SHA256(), default_backend())
    return cert

def issue_cert(subject_cn: str, subject_key: rsa.RSAPrivateKey, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate, days=365):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)\
        .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256(), default_backend())
    return cert
