"""
AES-128 ECB encryption implementation with PKCS#7 padding.
Provides symmetric encryption for secure chat messages.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class AES128Cipher:
    """AES-128 ECB cipher implementation with PKCS#7 padding."""
    
    # AES-128 uses 16-byte (128-bit) keys
    KEY_LENGTH_BYTES = 16
    BLOCK_SIZE_BITS = 128
    
    def __init__(self, encryption_key: bytes):
     
        if len(encryption_key) != self.KEY_LENGTH_BYTES:
            raise ValueError(
                f"AES-128 requires exactly {self.KEY_LENGTH_BYTES} byte key. "
                f"Provided: {len(encryption_key)} bytes"
            )
        
        self.encryption_key = encryption_key
        # Using ECB mode as specified in assignment requirements
        self.cipher_engine = Cipher(
            algorithms.AES(self.encryption_key),
            modes.ECB(),
            backend=default_backend()
        )

    def encrypt_data(self, plaintext_data: bytes) -> bytes:
       
        # Apply PKCS#7 padding to match AES block size
        padding_adder = padding.PKCS7(self.BLOCK_SIZE_BITS).padder()
        padded_data = (
            padding_adder.update(plaintext_data) + 
            padding_adder.finalize()
        )
        
        # Perform encryption
        encryptor = self.cipher_engine.encryptor()
        encrypted_result = (
            encryptor.update(padded_data) + 
            encryptor.finalize()
        )
        
        return encrypted_result

    def decrypt_data(self, ciphertext_data: bytes) -> bytes:
       
        # Perform decryption
        decryptor = self.cipher_engine.decryptor()
        decrypted_padded_data = (
            decryptor.update(ciphertext_data) + 
            decryptor.finalize()
        )
        
        # Remove PKCS#7 padding
        padding_remover = padding.PKCS7(self.BLOCK_SIZE_BITS).unpadder()
        original_plaintext = (
            padding_remover.update(decrypted_padded_data) + 
            padding_remover.finalize()
        )
        
        return original_plaintext