import socket, json, os, base64
from app.common.protocol import Hello, ServerHello, Register, Login, DHClient, DHServer, Msg, Receipt
from app.common.utils import b64u, b64d, now_ms, sha256_hex
from app.crypto.pki import load_cert, verify_cert_chain
from app.crypto.sign import load_private_key, load_public_key_from_cert, sign_bytes, b64sig, b64desig, verify_bytes
from app.crypto.dh import gen_private_key, pub_from_priv, shared_secret, derive_aes_key_from_ks
from app.crypto.aes import encrypt_ecb, decrypt_ecb
from app.storage import db, transcript
from dotenv import load_dotenv
load_dotenv()

CERTS_DIR = os.getenv("CERTS_DIR","certs")
CA_CERT = open(os.path.join(CERTS_DIR,"ca.crt"),"rb").read()
SERVER_CERT_PEM = open(os.path.join(CERTS_DIR,"server.crt"),"rb").read()
SERVER_KEY = open(os.path.join(CERTS_DIR,"server.key"),"rb").read()
SERVER_PRIV = load_private_key(SERVER_KEY)

HOST = "127.0.0.1"; PORT = 9000

db.init_schema()

def handle_client(conn, addr):
    # 1. receive client hello (cert + nonce)
    data = conn.recv(65536)
    hello = Hello.parse_raw(data)
    client_cert_pem = hello.cert.encode()
    # verify certificate is signed by CA and not expired
    ok = verify_cert_chain(client_cert_pem, CA_CERT)
    if not ok:
        conn.send(b'{"type":"error","msg":"BAD CERT"}')
        conn.close(); return
    # send server hello
    server_nonce = b64u(os.urandom(16))
    sh = ServerHello(cert=SERVER_CERT_PEM.decode(), nonce=server_nonce)
    conn.send(sh.json().encode())

    # 2. ephemeral DH for initial registration/login encryption
    # we accept a DHClient message
    raw = conn.recv(65536)
    dhc = DHClient.parse_raw(raw)
    # server chooses private
    b = gen_private_key(256)
    B = pub_from_priv(dhc.g, dhc.p, b)
    dhs = DHServer(B=B)
    conn.send(dhs.json().encode())
    Ks = shared_secret(dhc.A, b, dhc.p)
    aes_k = derive_aes_key_from_ks(Ks)

    # 3. receive register/login encrypted payload (JSON encrypted)
    enc_msg_raw = conn.recv(65536)
    # the message is JSON wrapper { "ct": base64 }
    j = json.loads(enc_msg_raw)
    ct = base64.b64decode(j["ct"])
    pt = decrypt_ecb(aes_k, ct)
    doc = json.loads(pt.decode())
    if doc["type"] == "register":
        reg = Register.parse_obj(doc)
        # ensure unique etc.
        if db.find_user_by_email(reg.email):
            conn.send(b'{"type":"error","msg":"EMAIL EXISTS"}'); conn.close(); return
        # salt & pwd hash are already base64/hex from client; server should recompute stored hash as described
        # Here we store salt (raw) and hash hex
        import base64 as _b
        salt = _b.b64decode(reg.salt)
        # client sent pwd field as base64(sha256(salt||pwd)) — but server recomputes after generating its own salt; assignment asked:
        # The assignment requires server to generate salt, compute hash = hex(sha256(salt || password)).
        # So to follow spec we accept plaintext (but our design earlier said client sends hashed). For compat: require client to send plaintext password encrypted.
        # For simplicity here assume client sent plaintext password in reg.pwd as base64 plaintext
        pwd_plain = base64.b64decode(reg.pwd).decode()
        db.create_user(reg.email, reg.username, pwd_plain)
        conn.send(b'{"type":"ok","msg":"REGISTERED"}')
    elif doc["type"] == "login":
        login = Login.parse_obj(doc)
        # assume login.pwd is base64 plaintext
        pwd_plain = base64.b64decode(login.pwd).decode()
        if db.verify_password(login.email, pwd_plain):
            conn.send(b'{"type":"ok","msg":"AUTH OK"}')
        else:
            conn.send(b'{"type":"error","msg":"AUTH FAIL"}'); conn.close(); return

    # 4. Now post-auth: perform session DH to establish session AES key
    # receive DHClient again (session)
    raw = conn.recv(65536)
    dhc2 = DHClient.parse_raw(raw)
    b2 = gen_private_key(256)
    B2 = pub_from_priv(dhc2.g, dhc2.p, b2)
    conn.send(DHServer(B=B2).json().encode())
    Ks2 = shared_secret(dhc2.A, b2, dhc2.p)
    session_key = derive_aes_key_from_ks(Ks2)

    # transcript
    tr = transcript.Transcript(os.path.join("transcripts", f"{addr[0]}_{addr[1]}.log"))
    seq_expected = 1
    client_pub = load_public_key_from_cert(client_cert_pem)

    # 5. message loop
    while True:
        raw = conn.recv(131072)
        if not raw:
            break
        try:
            msg = Msg.parse_raw(raw)
        except Exception:
            break
        # verify seq
        if msg.seqno != seq_expected:
            conn.send(b'{"type":"error","msg":"REPLAY"}'); break
        # verify signature over seq||ts||ct
        import hashlib
        h = hashlib.sha256()
        h.update(str(msg.seqno).encode()+str(msg.ts).encode()+msg.ct.encode())
        digest = h.digest()
        sig = b64desig(msg.sig)
        ok = verify_bytes(client_pub, sig, digest)
        if not ok:
            conn.send(b'{"type":"error","msg":"SIG FAIL"}'); break
        # decrypt
        ct = base64.b64decode(msg.ct)
        pt = decrypt_ecb(session_key, ct)
        print(f"[{msg.seqno}] client: {pt.decode()}")
        # append to transcript
        peer_fp = sha256_hex(client_cert_pem)[:16]
        tr.append_line(msg.seqno, msg.ts, ct, sig, peer_fp)
        seq_expected += 1
    # on teardown compute transcript hash and sign
    th = tr.compute_hash()
    receipt_sig = sign_bytes(SERVER_PRIV, th.encode())
    rec = Receipt(peer="server", first_seq=1, last_seq=seq_expected-1, transcript_sha256=th, sig=b64u(receipt_sig))
    # store receipt locally
    open(os.path.join("transcripts", f"{addr[0]}_{addr[1]}.receipt.json"), "w").write(rec.json())
    conn.close()

def run():
    s = socket.socket()
    s.bind((HOST, PORT)); s.listen(5)
    print("server listening", HOST, PORT)
    while True:
        conn, addr = s.accept()
        print("conn from", addr)
        handle_client(conn, addr)

if __name__ == "__main__":
    run()
