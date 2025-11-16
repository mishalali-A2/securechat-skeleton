import base64, time, hashlib, os
from typing import Tuple

def b64u(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def now_ms() -> int:
    return int(time.time() * 1000)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def rand_bytes(n: int) -> bytes:
    return os.urandom(n)
