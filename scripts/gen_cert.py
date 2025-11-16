import argparse, pathlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.crypto.pki import issue_cert, load_cert
from cryptography.hazmat.backends import default_backend

p = pathlib.Path("certs")
p.mkdir(exist_ok=True)

def main(name, cn):
    ca_key = (p / "ca.key").read_bytes()
    ca_cert_pem = (p / "ca.crt").read_bytes()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    ca_key_obj = load_pem_private_key(ca_key, password=None, backend=default_backend())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    cert_obj = issue_cert(cn, key, ca_key_obj, load_cert(ca_cert_pem))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
    (p / f"{name}.key").write_bytes(key_pem)
    (p / f"{name}.crt").write_bytes(cert_pem)
    print(f"Wrote certs/{name}.key and certs/{name}.crt")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: python gen_cert.py <name> <cn>")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
