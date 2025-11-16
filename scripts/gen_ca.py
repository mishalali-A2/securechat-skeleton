import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.crypto.pki import create_self_signed_ca
from cryptography.hazmat.backends import default_backend
import pathlib

p = pathlib.Path("certs")
p.mkdir(exist_ok=True)

def main(cn="SecureChat Root CA"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    cert = create_self_signed_ca(cn, key)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    (p / "ca.key").write_bytes(key_pem)
    (p / "ca.crt").write_bytes(cert_pem)
    print("Wrote certs/ca.key and certs/ca.crt")

if __name__ == "__main__":
    main()
