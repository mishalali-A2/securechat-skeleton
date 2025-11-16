"""
Run all live integration tests against a running server
"""

import subprocess
import sys
import os
import time

def run_live_test(test_name, test_file):
    """Run a single live test and return success status"""
    print(f"\nRUNNING: {test_name}")
    print("=" * 50)
    
    try:
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:", result.stderr)
        
        # Check for success indicators in output
        success_indicators = [
            "SUCCESS:",
            "PROVEN:",
            "non-repudiation proven",
            "tampering detected", 
            "replay detected",
            "ACCEPTED:"
        ]
        
        has_success = any(indicator in result.stdout for indicator in success_indicators)
        
        return has_success and result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("FAIL: TEST TIMEOUT")
        return False
    except Exception as e:
        print(f"FAIL: TEST FAILED: {e}")
        return False

def main():
    print("LIVE SECURITY INTEGRATION TEST SUITE")
    print("=" * 70)
    print("IMPORTANT: These tests require a running server!")
    print("   Start server with: python -m app.server")
    print("=" * 70)
    
    input("Press Enter when server is running on 127.0.0.1:8080...")
    
    live_tests = [
        ("Certificate Validation", "tests/test_live_certificates.py"),
        ("Tampering Detection", "tests/test_live_tampering.py"),
        ("Replay Protection", "tests/test_live_replay.py"), 
        ("Non-Repudiation", "tests/test_live_nonrepudiation.py"),
    ]
    
    results = []
    
    for test_name, test_file in live_tests:
        if os.path.exists(test_file):
            success = run_live_test(test_name, test_file)
            results.append((test_name, success))
        else:
            print(f"FAIL: Test file not found: {test_file}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 70)
    print("LIVE TEST SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for test_name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"{status} {test_name}")
        if not success:
            all_passed = False
    
    print("\n" + "=" * 70)
    if all_passed:
        print("ALL LIVE TESTS PASSED!")
        print("Your security implementation is working correctly!")
    else:
        print("Some tests failed. Check server logs and test output.")
    
    print("=" * 70)

if __name__ == "__main__":
    main()