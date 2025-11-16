"""
RSA signing and verification utilities for message integrity and non-repudiation.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os


class RSASigning:
    """Handles RSA signing and verification operations."""
    
    CERTIFICATES_DIRECTORY = "certs"
    
    @classmethod
    def load_private_key(cls, key_type: str = "client") -> rsa.RSAPrivateKey:
        """
        Load RSA private key from file.
        
        Args:
            key_type: "client" or "server"
            
        Returns:
            RSA private key object
        """
        key_path = os.path.join(cls.CERTIFICATES_DIRECTORY, f"{key_type}_private_key.pem")
        try:
            with open(key_path, "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key not found at {key_path}")

    @staticmethod
    def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """
        Sign data using RSA private key.
        
        Args:
            private_key: RSA private key
            data: Data to sign
            
        Returns:
            RSA signature
        """
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
        """
        Verify RSA signature.
        
        Args:
            public_key: RSA public key
            data: Original data
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @classmethod
    def extract_public_key_from_certificate(cls, certificate_pem: bytes):
        """
        Extract public key from certificate.
        
        Args:
            certificate_pem: PEM encoded certificate
            
        Returns:
            Public key object
        """
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(certificate_pem, default_backend())
        return cert.public_key()