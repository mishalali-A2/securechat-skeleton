"""
Public Key Infrastructure utilities for certificate handling and validation.
Provides certificate loading, parsing, and validation functions.
"""

import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


class CertificateValidationException(Exception):
    """Exception raised for certificate validation failures (BAD_CERT scenarios)."""
    pass


class CertificateManager:
    """Manages certificate operations including loading and validation."""
    
    CERTIFICATES_DIRECTORY = "certs"
    ROOT_CA_CERTIFICATE_FILENAME = "root_ca_certificate.pem"
    ROOT_CA_PATH = os.path.join(CERTIFICATES_DIRECTORY, ROOT_CA_CERTIFICATE_FILENAME)

    @staticmethod
    def load_certificate_from_pem(certificate_pem: bytes) -> x509.Certificate:
       
        try:
            return x509.load_pem_x509_certificate(
                certificate_pem, 
                default_backend()
            )
        except Exception as parsing_error:
            raise CertificateValidationException(
                f"Certificate parsing failed: {parsing_error}"
            )

    @classmethod
    def load_root_ca_certificate(cls) -> x509.Certificate:
       
        try:
            with open(cls.ROOT_CA_PATH, "rb") as certificate_file:
                return cls.load_certificate_from_pem(certificate_file.read())
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Root CA certificate not found at {cls.ROOT_CA_PATH}"
            )

    @staticmethod
    def extract_common_name(certificate: x509.Certificate) -> str:
       
        try:
            common_name_attributes = certificate.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )
            return common_name_attributes[0].value if common_name_attributes else ""
        except IndexError:
            return ""

    @classmethod
    def validate_certificate_chain(
        cls,
        certificate_pem: bytes,
        expected_common_name: str,
        trusted_ca_certificate: x509.Certificate
    ):
        
        certificate_to_validate = cls.load_certificate_from_pem(certificate_pem)
        
        # 1. Verify certificate chain (issuer matches CA subject)
        if certificate_to_validate.issuer != trusted_ca_certificate.subject:
            raise CertificateValidationException(
                "BAD_CERT: Certificate issuer does not match trusted CA (untrusted chain)."
            )

        # 2. Check validity period (using UTC to avoid deprecation warnings)
        current_time_utc = datetime.datetime.now(datetime.timezone.utc)
        valid_from = certificate_to_validate.not_valid_before_utc
        valid_until = certificate_to_validate.not_valid_after_utc
        
        if current_time_utc < valid_from or current_time_utc > valid_until:
            raise CertificateValidationException(
                "BAD_CERT: Certificate is either expired or not yet valid."
            )

        # 3. Verify Common Name matches expected value
        actual_common_name = cls.extract_common_name(certificate_to_validate)
        if actual_common_name != expected_common_name:
            raise CertificateValidationException(
                f"BAD_CERT: Common Name mismatch. Expected: '{expected_common_name}', "
                f"Actual: '{actual_common_name}'"
            )