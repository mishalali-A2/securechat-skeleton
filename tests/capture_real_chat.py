"""
Create a real chat session for Wireshark capture
"""

import subprocess
import time
import sys
import os

def capture_real_chat_session():
    """Start a real client-server chat session for Wireshark"""
    print("REAL CHAT SESSION CAPTURE")
    print("=" * 50)
    print("This will start a server and client for realistic Wireshark capture")
    print()
    
    # Make sure we have a test user
    print("1. Creating test user...")
    try:
        subprocess.run([
            sys.executable, "-m", "app.client", "--register", 
            "--username", "wireshark_user", 
            "--password", "test123", 
            "--email", "test@wireshark.demo"
        ], capture_output=True, timeout=10)
    except:
        pass  # User might already exist
    
    print("2. Starting server...")
    server_process = subprocess.Popen([
        sys.executable, "-m", "app.server"
    ])
    
    # Wait for server to start
    time.sleep(3)
    
    print("3. Starting client (will run for 30 seconds)...")
    print("   Now start Wireshark capture on port 8080!")
    print("   Press Enter when ready...")
    input()
    
    # Start client in a way that sends messages
    client_process = subprocess.Popen([
        sys.executable, "-m", "app.client",
        "--login", "--username", "wireshark_user", "--password", "test123"
    ])
    
    print("4. Client running...")
    print("   Wireshark is capturing REAL encrypted chat traffic")
    print("   Client will auto-terminate after login")
    
    # Wait for capture
    time.sleep(30)
    
    print("5. Cleaning up...")
    client_process.terminate()
    server_process.terminate()
    
    print("✅ Capture complete! Check Wireshark for results.")

if __name__ == "__main__":
    capture_real_chat_session()