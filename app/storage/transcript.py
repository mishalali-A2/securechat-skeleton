import os, threading, hashlib
from app.common.utils import b64u
LOCK = threading.Lock()

class Transcript:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # ensure file exists
        open(self.path, "a").close()

    def append_line(self, seqno:int, ts:int, ct:bytes, sig:bytes, peer_fingerprint:str):
        line = f"{seqno}|{ts}|{b64u(ct)}|{b64u(sig)}|{peer_fingerprint}\n"
        with LOCK:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def compute_hash(self) -> str:
        with LOCK:
            with open(self.path, "rb") as f:
                data = f.read()
        return hashlib.sha256(data).hexdigest()
