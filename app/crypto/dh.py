"""
Diffie-Hellman key exchange implementation.
Manages DH parameters and key derivation for secure session establishment.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from ..common.utils import create_sha256_hash
import os


class DiffieHellmanKeyExchange:
    """Manages Diffie-Hellman key exchange operations."""
    
    CERTIFICATES_DIRECTORY = "certs"
    DH_PARAMETERS_FILENAME = "dh_parameters.pem"
    DH_PARAMETERS_PATH = os.path.join(CERTIFICATES_DIRECTORY, DH_PARAMETERS_FILENAME)
    
    # Load DH parameters at module import (ensures consistent p and g)
    try:
        with open(DH_PARAMETERS_PATH, "rb") as parameters_file:
            _DH_PARAMETERS = serialization.load_pem_parameters(
                parameters_file.read(), 
                backend=default_backend()
            )
    except FileNotFoundError:
        print(f"[ERROR] DH parameters file not found at {DH_PARAMETERS_PATH}.")
        print("Please execute 'python scripts/generate_dh_parameters.py' before starting server/client.")
        exit(1)

    @classmethod
    def get_dh_parameters_object(cls) -> dh.DHParameters:
       
        return cls._DH_PARAMETERS

    @classmethod
    def get_dh_parameters_values(cls) -> tuple[int, int]:
        
        parameter_numbers = cls._DH_PARAMETERS.parameter_numbers()
        return parameter_numbers.p, parameter_numbers.g

    @classmethod
    def generate_key_pair(cls) -> tuple:
        
        private_key = cls._DH_PARAMETERS.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    @classmethod
    def compute_shared_secret(
        cls, 
        local_private_key, 
        remote_public_value: int
    ) -> bytes:
       
        # Reconstruct remote public key from integer value
        remote_public_numbers = dh.DHPublicNumbers(
            remote_public_value,
            cls._DH_PARAMETERS.parameter_numbers()
        )
        remote_public_key = remote_public_numbers.public_key(default_backend())
        
        # Compute shared secret
        return local_private_key.exchange(remote_public_key)

    @staticmethod
    def derive_aes_key_from_shared_secret(shared_secret: bytes) -> bytes:
       
        # Hash the shared secret
        hash_output = create_sha256_hash(shared_secret)  # 32 bytes
        
        # Truncate to 16 bytes for AES-128
        return hash_output[:16]