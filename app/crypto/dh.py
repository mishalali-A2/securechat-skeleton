import secrets
from hashlib import sha256

# Smallish safe primes could be used for testing; production would need larger primes.
# For assignment, allow user-specified p,g in messages; provide helper to generate private/public.
def gen_private_key(bits=256):
    return secrets.randbelow(1 << bits)

def pub_from_priv(g: int, p: int, priv: int) -> int:
    return pow(g, priv, p)

def shared_secret(A: int, priv: int, p: int) -> int:
    return pow(A, priv, p)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    # big-endian bytes of ks
    bs = ks_int.to_bytes((ks_int.bit_length()+7)//8 or 1, 'big')
    h = sha256(bs).digest()
    return h[:16]
