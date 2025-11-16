
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

# Secure Chat Application

A secure, end-to-end encrypted chat application with PKI-based authentication, signed messages, and non-repudiation features.

## Features

- 🔐 **PKI Authentication** - Certificate-based mutual authentication
- 🤝 **Diffie-Hellman Key Exchange** - Secure session key establishment
- 📨 **Signed Messages** - RSA signatures for message integrity and non-repudiation
- 💬 **Secure Chat** - AES-128 encrypted real-time messaging
- 📄 **Session Receipts** - Cryptographic proof of conversation participation
- 🗄️ **MySQL Backend** - Secure user storage with salted password hashing

## Prerequisites

- Python 3.8+
- MySQL Server
- Required Python packages: `cryptography`, `mysql-connector-python`, `python-dotenv`

## Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/secure-chat-app.git
cd secure-chat-app
```

2. **Install dependencies**
```bash
pip install cryptography mysql-connector-python python-dotenv
```

3. **Database Setup**
```sql
CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
```

4. **Environment Configuration**
Create a `.env` file:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=scuser
DB_PASSWORD=scpass
DB_NAME=securechat
```

## Certificate Generation

### 1. Generate Root CA
```bash
python scripts/gen_ca.py --name "SecureChat Root CA"
```

### 2. Generate Server Certificate
```bash
python scripts/gen_cert.py --cn "server.local" --out "certs/server"
```

### 3. Generate Client Certificate  
```bash
python scripts/gen_cert.py --cn "client.local" --out "certs/client"
```

### 4. Generate DH Parameters
```bash
python scripts/gen_dh_params.py
```

### 5. Initialize Database Schema
```bash
python -m app.storage.db --init
```

## Usage

### Starting the Server
```bash
python server.py
```

### Client Operations

**User Registration**
```bash
python client.py --register --username "alice" --password "secret123" --email "alice@example.com"
```

**User Login**
```bash
python client.py --login --username "alice" --password "secret123"
```

## Protocol Flow

1. **Certificate Exchange** - Mutual TLS certificate validation
2. **Key Exchange** - Diffie-Hellman for session key derivation  
3. **Authentication** - Encrypted credential exchange
4. **Secure Chat** - Signed and encrypted messaging
5. **Session Receipt** - Non-repudiation proof generation

## Sample Output

### Server Startup
```
[SERVER] 🟢 Server listening on 127.0.0.1:8080
[SERVER] 🔐 Signed message enforcement: ENABLED
[SERVER] 📄 Non-repudiation receipts: ENABLED
```

### Client Authentication
```
[CLIENT] 🔗 Connecting to 127.0.0.1:8080...
[CLIENT] 🤝 Connected to server successfully.
[CLIENT] ✅ Server certificate validated successfully.
[CLIENT] 6. Successfully derived shared session key.
[CLIENT] 8. Authentication successful. Session established.
```

### Chat Session
```
[CLIENT] 💬 Secure chat session started as 'alice'
Type your messages below:
  /quit     - Exit chat and generate session receipt
  /receipt  - Generate session receipt without exiting
--------------------------------------------------
alice> Hello, world!
[CLIENT] 📨 Sent signed message (seq: 1)

[SERVER]: Hi there!
alice> 
```

### Session Receipt
```
============================================================
CLIENT SESSION RECEIPT (Non-Repudiation Proof)
============================================================
Peer: client
Message Range: 1 - 5
Transcript Hash: a1b2c3d4e5f6...
Signature: MEUCIQDxX5k4r4V2s8e9t0jKlMnOpqRsT...
============================================================
This receipt proves your participation in this conversation.
Receipt saved to client_receipt_1700000000.json
```

## Message Format

### Signed Chat Message
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1700000000000,
  "ct": "base64_encrypted_content",
  "sig": "base64_rsa_signature"
}
```

### Session Receipt
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 5,
  "transcript_sha256": "hash_value",
  "sig": "base64_signature"
}
```

## Security Features

- **Mutual Authentication** - Both client and server verify certificates
- **Perfect Forward Secrecy** - Ephemeral DH keys for each session
- **Message Integrity** - RSA signatures prevent tampering
- **Replay Protection** - Sequence numbers prevent message replay
- **Non-Repudiation** - Session receipts provide conversation proof
- **Salted Password Hashing** - Secure credential storage


## License

MIT License - See LICENSE file for details.verified offline  
