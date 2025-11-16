"""
Certificate Issuance Script.
Generates entity keypairs and issues certificates signed by the Root CA.
"""

import os
import argparse
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateIssuer:
    """Handles issuance of certificates signed by the Root CA."""
    
    CERTIFICATES_DIRECTORY = "certs"
    CA_PRIVATE_KEY_FILENAME = "root_ca_private_key.pem"
    CA_CERTIFICATE_FILENAME = "root_ca_certificate.pem"
    DEFAULT_CERTIFICATE_EXPIRY_DAYS = 365  # 1 year
    
    def __init__(self):
        """Initialize certificate issuer with CA credentials."""
        self.ca_private_key = None
        self.ca_certificate = None
        self._load_ca_credentials()

    def _load_ca_credentials(self):
        """Load CA private key and certificate from files."""
        ca_key_path = os.path.join(self.CERTIFICATES_DIRECTORY, self.CA_PRIVATE_KEY_FILENAME)
        ca_cert_path = os.path.join(self.CERTIFICATES_DIRECTORY, self.CA_CERTIFICATE_FILENAME)
        
        try:
            with open(ca_key_path, "rb") as key_file:
                self.ca_private_key = serialization.load_pem_private_key(
                    key_file.read(), 
                    password=None, 
                    backend=default_backend()
                )
            with open(ca_cert_path, "rb") as cert_file:
                self.ca_certificate = x509.load_pem_x509_certificate(
                    cert_file.read(), 
                    default_backend()
                )
        except FileNotFoundError:
            print(f"[ERROR] CA files not found in {self.CERTIFICATES_DIRECTORY}/")
            print(f"Please run: python scripts/gen_ca.py --name \"Your CA Name\"")
            exit(1)

    def issue_certificate(self, common_name: str, output_base_path: str):
        """
        Issue a certificate signed by the Root CA.
        
        Args:
            common_name: Common Name for the certificate
            output_base_path: Base path for output files (e.g., 'certs/server')
        """
        entity_name = os.path.basename(output_base_path).capitalize()
        print(f"\n=== Issuing Certificate for {entity_name} (CN: {common_name}) ===")

        # Generate entity keypair
        entity_private_key = self._generate_entity_keypair(entity_name)
        entity_certificate = self._create_signed_certificate(
            entity_private_key, common_name, entity_name
        )
        
        # Save keypair and certificate
        self._save_entity_assets(entity_private_key, entity_certificate, output_base_path)
        
        print(f"[SUCCESS] {entity_name} certificate issued successfully!")

    def _generate_entity_keypair(self, entity_name: str) -> rsa.RSAPrivateKey:
        """
        Generate RSA keypair for the entity.
        
        Args:
            entity_name: Name of the entity for logging
            
        Returns:
            RSA private key
        """
        print(f"[*] Generating {entity_name} RSA private key (2048-bit)...")
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def _create_signed_certificate(
        self, 
        entity_private_key: rsa.RSAPrivateKey, 
        common_name: str,
        entity_name: str
    ) -> x509.Certificate:
        """
        Create and sign certificate for the entity.
        
        Args:
            entity_private_key: Entity's private key
            common_name: Common Name for the certificate
            entity_name: Entity name for logging
            
        Returns:
            Signed certificate
        """
        print(f"[*] Signing {entity_name} certificate with Root CA...")
        
        certificate_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat System"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(certificate_subject)
        certificate_builder = certificate_builder.issuer_name(self.ca_certificate.subject)
        certificate_builder = certificate_builder.public_key(entity_private_key.public_key())
        certificate_builder = certificate_builder.serial_number(x509.random_serial_number())
        certificate_builder = certificate_builder.not_valid_before(datetime.datetime.utcnow())
        certificate_builder = certificate_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=self.DEFAULT_CERTIFICATE_EXPIRY_DAYS)
        )
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False
        )

        return certificate_builder.sign(
            private_key=self.ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

    def _save_entity_assets(
        self, 
        private_key: rsa.RSAPrivateKey, 
        certificate: x509.Certificate, 
        output_base: str
    ):
        """
        Save entity's private key and certificate to files.
        
        Args:
            private_key: Entity's private key
            certificate: Entity's certificate
            output_base: Base path for output files
        """
        private_key_path = output_base + "_private_key.pem"
        certificate_path = output_base + "_certificate.pem"

        # Save private key
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"  → Private key: {private_key_path}")

        # Save certificate
        with open(certificate_path, "wb") as certificate_file:
            certificate_file.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"  → Certificate: {certificate_path}")


def main():
    """Main execution function for certificate issuance script."""
    argument_parser = argparse.ArgumentParser(
        description="Issue RSA X.509 certificates signed by the Root CA."
    )
    argument_parser.add_argument(
        "--cn", 
        required=True, 
        help="Common Name (CN) for certificate identity verification"
    )
    argument_parser.add_argument(
        "--out", 
        required=True, 
        help="Output base path (e.g., 'certs/server' for server_private_key.pem and server_certificate.pem)"
    )
    
    command_line_args = argument_parser.parse_args()
    
    certificate_issuer = CertificateIssuer()
    certificate_issuer.issue_certificate(command_line_args.cn, command_line_args.out)


if __name__ == "__main__":
    main()