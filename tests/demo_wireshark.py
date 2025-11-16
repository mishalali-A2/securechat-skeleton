"""
Script to generate traffic for Wireshark capture demonstration
Run this while Wireshark is capturing
"""

import socket
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.common.utils import encode_to_base64
from app.common.protocol import CertificateExchangeMessage

def generate_wireshark_traffic():
    """Generate traffic that demonstrates security features in Wireshark"""
    print("WIRESHARK DEMONSTRATION TRAFFIC GENERATOR")
    print("=" * 60)
    print("Start Wireshark capture on loopback interface (port 8080)")
    print("Then press Enter to generate traffic...")
    input()
    
    # Load actual certificate for realistic traffic
    with open("certs/client_certificate.pem", "rb") as f:
        client_cert = f.read()
    
    demonstrations = [
        ("1. Certificate Exchange", generate_certificate_exchange),
        ("2. Normal Chat Messages", generate_chat_messages),
        ("3. Security Protocol Flow", generate_protocol_flow),
    ]
    
    for demo_name, demo_func in demonstrations:
        print(f"\n{demo_name}")
        print("-" * 40)
        demo_func(client_cert)
        time.sleep(2)  # Give time for Wireshark to capture
    
    print("\n✅ Traffic generation complete!")
    print("Check Wireshark for captured packets")

def generate_certificate_exchange(client_cert):
    """Generate certificate exchange traffic"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 8080))
        
        # Send client hello
        hello_msg = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(client_cert),
            nonce_data=encode_to_base64(b"wireshark_demo_nonce"),
            is_client=True
        )
        
        sock.sendall(hello_msg.to_json_string().encode())
        print("📨 Sent: CLIENT_HELLO with certificate")
        
        # Wait for server response
        response = sock.recv(4096)
        print(f"📨 Received: Server response ({len(response)} bytes)")
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

def generate_chat_messages(client_cert):
    """Generate encrypted chat message traffic"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 8080))
        
        # First, send client hello to establish protocol
        hello_msg = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(client_cert),
            nonce_data=encode_to_base64(b"chat_demo_nonce"),
            is_client=True
        )
        sock.sendall(hello_msg.to_json_string().encode())
        
        # Send some encrypted message structures
        demo_messages = [
            {"type": "msg", "seqno": 1, "ts": int(time.time()*1000), "ct": "aGVsbG8gd29ybGQ=", "sig": "fake_sig_1"},
            {"type": "msg", "seqno": 2, "ts": int(time.time()*1000)+100, "ct": "c2Vjb25kIG1lc3NhZ2U=", "sig": "fake_sig_2"},
            {"type": "msg", "seqno": 3, "ts": int(time.time()*1000)+200, "ct": "dGhpcmQgbWVzc2FnZQ==", "sig": "fake_sig_3"},
        ]
        
        for msg in demo_messages:
            sock.sendall(json.dumps(msg).encode())
            print(f"📨 Sent: Encrypted message seqno={msg['seqno']}")
            time.sleep(0.5)
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

def generate_protocol_flow(client_cert):
    """Generate complete protocol flow"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 8080))
        
        print("🔄 Demonstrating protocol flow...")
        
        # Simulate different message types
        protocol_steps = [
            ("CLIENT_HELLO", {"message_type": "client_hello", "certificate_data": "base64_cert_data", "nonce_value": "base64_nonce"}),
            ("SERVER_HELLO", {"message_type": "server_hello", "certificate_data": "base64_server_cert", "nonce_value": "base64_nonce"}),
            ("DH_INITIATION", {"message_type": "dh_initiation", "generator_value": 2, "prime_modulus": "0xABC123", "public_component": "0xDEF456"}),
            ("DH_RESPONSE", {"message_type": "dh_response", "generator_value": 2, "prime_modulus": "0xABC123", "public_component": "0x789012"}),
            ("ENCRYPTED_MSG", {"type": "msg", "seqno": 1, "ts": int(time.time()*1000), "ct": "encrypted_data_here", "sig": "signature_here"}),
        ]
        
        for step_name, step_data in protocol_steps:
            sock.sendall(json.dumps(step_data).encode())
            print(f"📨 Sent: {step_name}")
            time.sleep(0.3)
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    generate_wireshark_traffic()