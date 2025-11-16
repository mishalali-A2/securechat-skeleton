
import hashlib
import base64
import time
from typing import Union


class CryptographicUtilities:
    """Collection of cryptographic helper functions."""
    
    @staticmethod
    def compute_sha256_digest(data: bytes) -> bytes:
        hash_algorithm = hashlib.sha256()
        hash_algorithm.update(data)
        return hash_algorithm.digest()
    
    @staticmethod
    def compute_sha256_hex_string(data: bytes) -> str:
    
        hash_algorithm = hashlib.sha256()
        hash_algorithm.update(data)
        return hash_algorithm.hexdigest()
    
    @staticmethod
    def encode_base64(data: bytes) -> str:
     
        encoded_bytes = base64.b64encode(data)
        return encoded_bytes.decode('utf-8')
    
    @staticmethod
    def decode_base64(encoded_data: str) -> bytes:
       
        return base64.b64decode(encoded_data)
    
    @staticmethod
    def get_current_timestamp_ms() -> int:
      
        return int(time.time() * 1000)


# Create module-level instances for convenience
def create_sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 digest of input data."""
    return CryptographicUtilities.compute_sha256_digest(data)


def create_sha256_hex_hash(data: bytes) -> str:
    """Compute SHA-256 and return as hex string."""
    return CryptographicUtilities.compute_sha256_hex_string(data)


def encode_to_base64(data: bytes) -> str:
    """Encode binary data to base64 string."""
    return CryptographicUtilities.encode_base64(data)


def decode_from_base64(encoded_string: str) -> bytes:
    """Decode base64 string to binary data."""
    return CryptographicUtilities.decode_base64(encoded_string)


def get_current_time_milliseconds() -> int:
    """Get current timestamp in milliseconds."""
    return CryptographicUtilities.get_current_timestamp_ms()