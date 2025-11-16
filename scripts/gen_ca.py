"""
Root Certificate Authority (CA) Generation Script.
Creates a self-signed root CA certificate and private key for PKI setup.
"""

import os
import argparse
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateAuthorityGenerator:
    """Handles generation of Root Certificate Authority."""
    
    CERTIFICATES_DIRECTORY = "certs"
    CA_PRIVATE_KEY_FILENAME = "root_ca_private_key.pem"
    CA_CERTIFICATE_FILENAME = "root_ca_certificate.pem"
    DEFAULT_EXPIRY_DAYS = 3650  # 10 years
    
    def __init__(self, common_name: str):
        """
        Initialize CA generator.
        
        Args:
            common_name: Common Name for the CA certificate
        """
        self.common_name = common_name
        self.private_key_path = os.path.join(self.CERTIFICATES_DIRECTORY, self.CA_PRIVATE_KEY_FILENAME)
        self.certificate_path = os.path.join(self.CERTIFICATES_DIRECTORY, self.CA_CERTIFICATE_FILENAME)

    def _ensure_certificates_directory(self):
        """Create certificates directory if it doesn't exist."""
        os.makedirs(self.CERTIFICATES_DIRECTORY, exist_ok=True)
        print(f"[*] Created/verified directory: {self.CERTIFICATES_DIRECTORY}")

    def _generate_rsa_private_key(self) -> rsa.RSAPrivateKey:
        """
        Generate RSA private key for the CA.
        
        Returns:
            RSA private key object
        """
        print("[*] Generating Root CA RSA private key (2048-bit)...")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def _create_ca_certificate(self, private_key: rsa.RSAPrivateKey) -> x509.Certificate:
        """
        Create self-signed CA certificate.
        
        Args:
            private_key: CA's private key for signing
            
        Returns:
            Self-signed CA certificate
        """
        print(f"[*] Creating self-signed Root CA certificate with CN: {self.common_name}")
        
        # Subject and issuer are the same for self-signed certificate
        certificate_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES Information Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(certificate_subject)
        certificate_builder = certificate_builder.issuer_name(certificate_subject)
        certificate_builder = certificate_builder.public_key(private_key.public_key())
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.utcnow())
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=self.DEFAULT_EXPIRY_DAYS)
        )
        certificate_builder = certificate_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), 
            critical=True
        )

        return certificate_builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

    def _save_private_key(self, private_key: rsa.RSAPrivateKey):
        """
        Save private key to file in PEM format.
        
        Args:
            private_key: Private key to save
        """
        print(f"[*] Writing CA private key to: {self.private_key_path}")
        with open(self.private_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def _save_certificate(self, certificate: x509.Certificate):
        """
        Save certificate to file in PEM format.
        
        Args:
            certificate: Certificate to save
        """
        print(f"[*] Writing CA certificate to: {self.certificate_path}")
        with open(self.certificate_path, "wb") as certificate_file:
            certificate_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    def generate_certificate_authority(self):
        """Execute complete CA generation process."""
        print("\n=== Root Certificate Authority Generation ===")
        
        self._ensure_certificates_directory()
        
        # Generate key material
        ca_private_key = self._generate_rsa_private_key()
        ca_certificate = self._create_ca_certificate(ca_private_key)
        
        # Persist to files
        self._save_private_key(ca_private_key)
        self._save_certificate(ca_certificate)
        
        print("\n[SUCCESS] Root CA setup completed successfully!")
        print(f"CA Certificate: {self.certificate_path}")
        print(f"CA Private Key: {self.private_key_path}")


def main():
    """Main execution function for CA generation script."""
    argument_parser = argparse.ArgumentParser(
        description="Generate Root Certificate Authority key and self-signed certificate."
    )
    argument_parser.add_argument(
        "--name", 
        required=True, 
        help="Common Name (CN) for the Root CA certificate"
    )
    
    command_line_args = argument_parser.parse_args()
    
    ca_generator = CertificateAuthorityGenerator(command_line_args.name)
    ca_generator.generate_certificate_authority()


if __name__ == "__main__":
    main()