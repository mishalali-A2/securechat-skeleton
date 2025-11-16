from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK = 16

def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(8*BLOCK).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(padded: bytes) -> bytes:
    unpadder = padding.PKCS7(8*BLOCK).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)
