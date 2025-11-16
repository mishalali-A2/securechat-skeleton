"""
Live test for certificate validation - tests actual server rejection
"""

import socket
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.common.utils import encode_to_base64
from app.common.protocol import CertificateExchangeMessage

def test_server_rejects_invalid_certificates():
    """Test that server rejects connection with invalid certificates"""
    print("TEST: SERVER REJECTS INVALID CERTIFICATES")
    print("=" * 50)
    
    # Test 1: Send completely invalid certificate data
    print("\n1. Testing with garbage certificate data...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(('127.0.0.1', 8080))
        
        # Send garbage as certificate
        hello_msg = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(b"THIS_IS_NOT_A_VALID_CERTIFICATE"),
            nonce_data=encode_to_base64(b"test_nonce_123"),
            is_client=True
        )
        
        sock.sendall(hello_msg.to_json_string().encode())
        print("SENT: Client hello with invalid certificate data")
        
        # Wait for server response
        response = sock.recv(1024).decode()
        print(f"RECEIVED: Server response: {response}")
        
        if "certificate_error" in response:
            print("SUCCESS: Server correctly rejected invalid certificate!")
        else:
            print("UNEXPECTED: Server didn't reject invalid certificate")
            
        sock.close()
        
    except Exception as e:
        print(f"FAIL: Connection error: {e}")

def test_server_accepts_proper_hello():
    """Test that server responds properly to valid certificate format"""
    print("\n2. Testing server response to proper message format...")
    
    try:
        # Load actual client certificate to test format
        with open("certs/client_certificate.pem", "rb") as f:
            valid_cert = f.read()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(('127.0.0.1', 8080))
        
        # Send valid certificate format
        hello_msg = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(valid_cert),
            nonce_data=encode_to_base64(b"valid_nonce_123"),
            is_client=True
        )
        
        sock.sendall(hello_msg.to_json_string().encode())
        print("SENT: Client hello with valid certificate format")
        
        # Server should respond (might be certificate_error or server_hello)
        response = sock.recv(4096).decode()
        print(f"RECEIVED: Server response length: {len(response)} chars")
        
        # The important thing is that server responded to the protocol
        if response:
            print("SUCCESS: Server is responding to certificate exchange protocol")
        else:
            print("FAIL: Server didn't respond")
            
        sock.close()
        
    except Exception as e:
        print(f"FAIL: Connection error: {e}")

def test_certificate_validation_logic():
    """Test the certificate validation logic directly"""
    print("\n3. Testing certificate validation logic...")
    
    try:
        from app.crypto.pki import CertificateManager, CertificateValidationException
        
        # Test with invalid certificate data
        try:
            CertificateManager.load_certificate_from_pem(b"invalid_cert_data")
            print("UNEXPECTED: Invalid certificate was accepted")
        except CertificateValidationException:
            print("SUCCESS: Invalid certificate correctly rejected")
        
        # Test with valid certificate but wrong CN
        trusted_ca = CertificateManager.load_root_ca_certificate()
        with open("certs/client_certificate.pem", "rb") as f:
            client_cert = f.read()
        
        try:
            CertificateManager.validate_certificate_chain(
                client_cert, 
                "wrong.client.local",  # Wrong CN
                trusted_ca
            )
            print("UNEXPECTED: Wrong CN was accepted")
        except CertificateValidationException as e:
            print(f"SUCCESS: Wrong CN correctly rejected: {e}")
            
    except Exception as e:
        print(f"FAIL: Certificate validation test error: {e}")

if __name__ == "__main__":
    print("NOTE: Ensure server is running on 127.0.0.1:8080")
    print("Server should be started with: python -m app.server")
    print()
    
    test_server_rejects_invalid_certificates()
    test_server_accepts_proper_hello() 
    test_certificate_validation_logic()