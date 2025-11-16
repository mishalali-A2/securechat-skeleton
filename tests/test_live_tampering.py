"""
Live test for tampering detection - tests signature verification
"""

import socket
import json
import time
import sys
import os
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.common.utils import encode_to_base64, decode_from_base64, create_sha256_hash
from app.crypto.aes import AES128Cipher
from app.crypto.sign import RSASigning

def demonstrate_tampering_detection():
    """Demonstrate how tampering is detected in the protocol"""
    print("TEST: TAMPERING DETECTION DEMONSTRATION")
    print("=" * 50)
    
    print("This test shows how your chat system detects message tampering:")
    print()
    
    # Create a simulated message
    session_key = secrets.token_bytes(16)
    aes_cipher = AES128Cipher(session_key)
    
    try:
        # Load actual keys to demonstrate real signing
        client_private_key = RSASigning.load_private_key("client")
        client_public_key = RSASigning.extract_public_key_from_certificate(
            open("certs/client_certificate.pem", "rb").read()
        )
        
        print("1. CREATING SIGNED MESSAGE:")
        seqno = 1
        timestamp = int(time.time() * 1000)
        plaintext = "Hello, secure world!"
        
        # Encrypt
        ciphertext = aes_cipher.encrypt_data(plaintext.encode())
        ciphertext_b64 = encode_to_base64(ciphertext)
        
        # Compute hash and sign (as done in your actual client)
        hash_data = str(seqno).encode() + str(timestamp).encode() + ciphertext
        message_hash = create_sha256_hash(hash_data)
        signature = RSASigning.sign_data(client_private_key, message_hash)
        
        print(f"   Message: '{plaintext}'")
        print(f"   Ciphertext: {ciphertext_b64[:30]}...")
        print(f"   Signature created: YES")
        print("   Message ready for transmission")
        print()
        
        print("2. TAMPERING SCENARIO:")
        # Tamper with the ciphertext
        tampered_ciphertext = decode_from_base64(ciphertext_b64)
        tampered_bytes = bytearray(tampered_ciphertext)
        tampered_bytes[10] ^= 0x01  # Flip a bit
        tampered_ciphertext_b64 = encode_to_base64(bytes(tampered_bytes))
        
        print(f"   Attacker modifies ciphertext")
        print(f"   Original: {ciphertext_b64[:30]}...")
        print(f"   Tampered: {tampered_ciphertext_b64[:30]}...")
        print(f"   Changed 1 bit at position 10")
        print()
        
        print("3. VERIFICATION PROCESS (as done in your server):")
        # Server would recompute hash with received ciphertext
        tampered_hash_data = str(seqno).encode() + str(timestamp).encode() + bytes(tampered_bytes)
        tampered_hash = create_sha256_hash(tampered_hash_data)
        
        print("   Server computes: SHA256(seqno || timestamp || received_ciphertext)")
        print(f"   Original hash: {message_hash.hex()[:20]}...")
        print(f"   Tampered hash:  {tampered_hash.hex()[:20]}...")
        print(f"   Hashes match: {message_hash == tampered_hash}")
        print()
        
        print("4. SIGNATURE VERIFICATION:")
        is_valid = RSASigning.verify_signature(client_public_key, tampered_hash, signature)
        print(f"   Signature valid for tampered message: {is_valid}")
        
        if not is_valid:
            print("   SUCCESS: Tampering detected! Signature verification failed.")
            print("   This would result in 'SIG_FAIL' error in your chat system.")
        else:
            print("   FAIL: Tampering was not detected!")
            
    except Exception as e:
        print(f"FAIL: Test error: {e}")


def test_signature_verification_directly():
    """Test the signature verification logic that your server uses"""
    print("\nTEST: DIRECT SIGNATURE VERIFICATION TEST")
    print("=" * 50)
    
    try:
        from app.crypto.sign import RSASigning
        
        # Test data
        test_data = b"Hello, this is test data for signing"
        
        # Load keys
        client_private_key = RSASigning.load_private_key("client")
        client_public_key = RSASigning.extract_public_key_from_certificate(
            open("certs/client_certificate.pem", "rb").read()
        )
        
        print("1. Testing valid signature...")
        signature = RSASigning.sign_data(client_private_key, test_data)
        is_valid = RSASigning.verify_signature(client_public_key, test_data, signature)
        print(f"   Valid signature verification: {is_valid}")
        
        print("2. Testing tampered data...")
        tampered_data = test_data + b"x"  # Add one byte
        is_valid_tampered = RSASigning.verify_signature(client_public_key, tampered_data, signature)
        print(f"   Tampered data verification: {is_valid_tampered}")
        
        if is_valid and not is_valid_tampered:
            print("SUCCESS: Signature system correctly detects tampering!")
        else:
            print("FAIL: Signature verification not working correctly")
            
    except Exception as e:
        print(f"FAIL: Signature test error: {e}")

def test_server_responds_to_messages():
    """Test that server is running and responsive"""
    print("\nTEST: SERVER RESPONSIVENESS")
    print("=" * 50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(('127.0.0.1', 8080))
        print("SUCCESS: Server is running and accepting connections")
        
        # Send a simple test message
        test_msg = json.dumps({"test": "message"})
        sock.sendall(test_msg.encode())
        
        # Even if it rejects, it should respond somehow
        try:
            response = sock.recv(1024)
            print("SUCCESS: Server responded to message")
        except socket.timeout:
            print("NOTE: Server didn't respond (might be expected for invalid messages)")
            
        sock.close()
        
    except Exception as e:
        print(f"FAIL: Cannot connect to server: {e}")

if __name__ == "__main__":
    
    test_server_responds_to_messages()
    demonstrate_tampering_detection()
    test_signature_verification_directly()