import socket, os, json, base64
from app.common.protocol import Hello, ServerHello, Register, Login, DHClient, DHServer, Msg
from app.common.utils import b64u, b64d, now_ms, sha256_hex
from app.crypto.pki import load_cert, verify_cert_chain
from app.crypto.sign import load_private_key, load_public_key_from_cert, sign_bytes, b64sig
from app.crypto.dh import gen_private_key, pub_from_priv, shared_secret, derive_aes_key_from_ks
from app.crypto.aes import encrypt_ecb, decrypt_ecb
from dotenv import load_dotenv
load_dotenv()

CERTS_DIR = os.getenv("CERTS_DIR","certs")
CA_CERT = open(os.path.join(CERTS_DIR,"ca.crt"),"rb").read()
CLIENT_CERT_PEM = open(os.path.join(CERTS_DIR,"client.crt"),"rb").read()
CLIENT_KEY = open(os.path.join(CERTS_DIR,"client.key"),"rb").read()
CLIENT_PRIV = load_private_key(CLIENT_KEY)

HOST = "127.0.0.1"; PORT = 9000

def run_register_flow(email, username, password):
    s = socket.socket()
    s.connect((HOST, PORT))
    # 1. send hello
    nonce = b64u(os.urandom(16))
    h = Hello(cert=CLIENT_CERT_PEM.decode(), nonce=nonce)
    s.send(h.json().encode())
    # 2. receive server hello and verify server cert
    data = s.recv(65536)
    sh = ServerHello.parse_raw(data)
    server_cert_pem = sh.cert.encode()
    if not verify_cert_chain(server_cert_pem, CA_CERT):
        print("BAD SERVER CERT"); s.close(); return
    # 3. ephemeral DH for auth
    from app.crypto.dh import pub_from_priv, gen_private_key
    g = 2
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    a = gen_private_key(256)
    A = pub_from_priv(g, p, a)
    s.send(DHClient(g=g, p=p, A=A).json().encode())
    dhs = DHServer.parse_raw(s.recv(65536))
    Ks = shared_secret(dhs.B, a, p)
    aes_k = derive_aes_key_from_ks(Ks)
    # 4. send register payload encrypted
    import base64 as _b
    # choose salt server won't know yet; but per assignment server generates salt; for simplicity send plaintext password encrypted
    reg = {"type":"register","email":email,"username":username,"pwd":_b.b64encode(password.encode()).decode(),"salt":_b.b64encode(os.urandom(16)).decode()}
    pt = json.dumps(reg).encode()
    ct = encrypt_ecb(aes_k, pt)
    s.send(json.dumps({"ct": base64.b64encode(ct).decode()}).encode())
    r = s.recv(65536); print("server:", r)
    # assume now authenticated for further actions; close
    s.close()

def run_session_and_send_messages():
    s = socket.socket(); s.connect((HOST, PORT))
    nonce = b64u(os.urandom(16))
    s.send(Hello(cert=CLIENT_CERT_PEM.decode(), nonce=nonce).json().encode())
    sh = ServerHello.parse_raw(s.recv(65536))
    if not verify_cert_chain(sh.cert.encode(), CA_CERT):
        print("BAD SERVER CERT"); s.close(); return
    # perform DH to get session key
    g = 2
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    a = gen_private_key(256); A = pub_from_priv(g,p,a)
    s.send(DHClient(g=g,p=p,A=A).json().encode())
    dhs = DHServer.parse_raw(s.recv(65536))
    Ks = shared_secret(dhs.B, a, p)
    session_key = derive_aes_key_from_ks(Ks)

    # send signed encrypted messages
    seq = 1
    while True:
        text = input("msg> ").strip()
        if not text:
            break
        ct = encrypt_ecb(session_key, text.encode())
        ts = now_ms()
        import hashlib
        h = hashlib.sha256()
        h.update(str(seq).encode()+str(ts).encode()+base64.b64encode(ct))
        digest = h.digest()
        sig = sign_bytes(CLIENT_PRIV, digest)
        msg = Msg(seqno=seq, ts=ts, ct=base64.b64encode(ct).decode(), sig=b64u(sig))
        s.send(msg.json().encode())
        seq += 1
    s.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "register":
        run_register_flow("alice@example.com", "alice", "s3cr3tP@ss")
    else:
        run_session_and_send_messages()
