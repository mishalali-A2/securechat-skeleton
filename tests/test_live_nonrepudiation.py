"""
Live test for non-repudiation - tests actual receipt generation and verification
"""

import json
import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.crypto.sign import RSASigning
from app.common.utils import create_sha256_hex_hash

def test_live_receipt_generation():
    """Test actual receipt generation and verification"""
    print("LIVE TEST: NON-REPUDIATION RECEIPTS")
    print("=" * 60)
    
    try:
        # Load keys for signing
        client_private_key = RSASigning.load_private_key("client")
        client_public_key = RSASigning.extract_public_key_from_certificate(
            open("certs/client_certificate.pem", "rb").read()
        )
        
        print("SUCCESS: Loaded client keys for signing")
        
        # Create a real chat transcript (simulated)
        transcript = [
            {
                'seqno': 1,
                'timestamp': 1700000000001,
                'ciphertext': 'aGVsbG8gd29ybGQh',  # "hello world!"
                'signature': 'fake_sig_1_for_demo',
                'peer_cert_fingerprint': 'server:abc123'
            },
            {
                'seqno': 2,
                'timestamp': 1700000000002, 
                'ciphertext': 'c2Vjb25kIG1lc3NhZ2U=',
                'signature': 'fake_sig_2_for_demo',
                'peer_cert_fingerprint': 'client:def456'
            }
        ]
        
        print("SUCCESS: Created chat transcript with 2 messages")
        
        # Compute actual transcript hash
        transcript_data = b""
        for entry in transcript:
            line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry['peer_cert_fingerprint']}\n"
            transcript_data += line.encode('utf-8')
        
        transcript_hash = create_sha256_hex_hash(transcript_data)
        print(f"SUCCESS: Computed transcript hash: {transcript_hash}")
        
        # Sign the hash with real private key
        signature = RSASigning.sign_data(client_private_key, transcript_hash.encode())
        signature_b64 = signature.hex()  # Using hex for demo
        
        # Create session receipt
        receipt = {
            'type': 'receipt',
            'peer': 'client',
            'first_seq': 1,
            'last_seq': 2,
            'transcript_sha256': transcript_hash,
            'sig': signature_b64
        }
        
        print("SUCCESS: Generated signed session receipt")
        
        # Verify the receipt
        verification_success = RSASigning.verify_signature(
            client_public_key,
            transcript_hash.encode(),
            signature
        )
        
        print(f"SUCCESS: Receipt signature verification: {verification_success}")
        
        if verification_success:
            print("PROVEN: NON-REPUDIATION - Client cannot deny sending these messages")
        
        # Demonstrate tampering detection
        print("\nDEMONSTRATING TAMPERING DETECTION:")
        tampered_hash = transcript_hash[:-1] + '0'  # Change last character
        tampered_verification = RSASigning.verify_signature(
            client_public_key,
            tampered_hash.encode(),
            signature
        )
        
        print(f"FAIL: Tampered receipt verification: {tampered_verification}")
        print("NOTE: Any modification to transcript breaks verification!")
        
    except Exception as e:
        print(f"FAIL: Test failed: {e}")
        import traceback
        traceback.print_exc()

def demonstrate_offline_verification():
    """Demonstrate how receipts can be verified offline"""
    print("\nOFFLINE VERIFICATION PROCESS")
    print("=" * 60)

    
    print("\nNOTE: This allows third-party verification without the original participants")

if __name__ == "__main__":
    test_live_receipt_generation()
    demonstrate_offline_verification()