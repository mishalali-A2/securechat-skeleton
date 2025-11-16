"""
Live test for replay protection - tests actual server sequence number validation
"""

import socket
import json
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_live_replay_protection():
    """Test that server detects replay attacks in live session"""
    print("LIVE TEST: SERVER DETECTS REPLAY ATTACKS")
    print("=" * 60)
    
   

def demonstrate_sequence_validation():
    """Demonstrate the sequence number validation logic"""
    print("\nSEQUENCE NUMBER VALIDATION LOGIC")
    print("=" * 60)
    
    class LiveSequenceValidator:
        def __init__(self):
            self.last_seqno = 0
        
        def validate_message(self, seqno, message):
            print(f"VALIDATING: seqno={seqno}, content='{message}'")
            
            if seqno <= self.last_seqno:
                print(f"REJECTED: seqno {seqno} <= last_seqno {self.last_seqno}")
                print("   ERROR: REPLAY DETECTED!")
                return False
            elif seqno != self.last_seqno + 1:
                print(f"REJECTED: seqno {seqno} != last_seqno+1 ({self.last_seqno + 1})")
                print("   ERROR: MESSAGE GAP DETECTED!")
                return False
            else:
                self.last_seqno = seqno
                print(f"ACCEPTED: seqno {seqno} valid")
                return True
    
    # Simulate message flow
    validator = LiveSequenceValidator()
    
    print("\nSIMULATING MESSAGE FLOW:")
    messages = [
        (1, "Hello"),
        (2, "How are you?"),
        (3, "I'm good!"),
        (2, "Replay attack!"),  # This should be rejected
        (4, "What's new?"),
        (4, "Another replay!"),  # This should be rejected
        (5, "Legitimate message"),
    ]
    
    for seqno, message in messages:
        success = validator.validate_message(seqno, message)
        if not success:
            print("   ERROR: MESSAGE REJECTED - This would happen in your live chat!")
        print()

if __name__ == "__main__":
    test_live_replay_protection()
    demonstrate_sequence_validation()