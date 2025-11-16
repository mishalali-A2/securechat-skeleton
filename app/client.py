"""
Secure Chat Client Implementation.
Handles client-side authentication, key exchange, and secure communication.
"""

import socket
import os
import sys
import argparse
import json
import secrets
import threading
import time
from typing import Optional
from app.common.utils import decode_from_base64, encode_to_base64, create_sha256_hash, create_sha256_hex_hash
from app.crypto.pki import CertificateManager, CertificateValidationException
from app.crypto.dh import DiffieHellmanKeyExchange
from app.crypto.aes import AES128Cipher
from app.crypto.sign import RSASigning
from app.common.protocol import (
    CertificateExchangeMessage, 
    KeyExchangeMessage, 
    AuthenticationData, 
    SecurePayloadMessage, 
    MessageType,
    SignedChatMessage,
    SessionReceipt
)


class SecureChatClient:
    """Main client class for secure chat operations."""
    
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 8080
    CERTIFICATES_DIRECTORY = "certs"
    
    def __init__(self):
        """Initialize client with required cryptographic assets."""
        self.server_address = (self.SERVER_HOST, self.SERVER_PORT)
        self.client_certificate = self._load_client_certificate()
        self.trusted_ca = CertificateManager.load_root_ca_certificate()
        self.session_key = None
        self.username = None
        self.running = False
        self.sequence_number = 0
        self.transcript = []
        
        # Load client's RSA private key for signing
        try:
            self.private_key = RSASigning.load_private_key("client")
            print("[CLIENT] ✅ Loaded client RSA private key for signing")
        except FileNotFoundError:
            print("[CLIENT] ❌ Failed to load client private key for signing")
            exit(1)

    def _load_client_certificate(self) -> bytes:
        """
        Load client certificate from file.
        
        Returns:
            Client certificate PEM data
            
        Raises:
            FileNotFoundError: If certificate file is missing
        """
        certificate_path = os.path.join(self.CERTIFICATES_DIRECTORY, "client_certificate.pem")
        try:
            with open(certificate_path, "rb") as cert_file:
                return cert_file.read()
        except FileNotFoundError as file_error:
            print(f"[CLIENT] ❌ Failed to load client certificate: {file_error}")
            exit(1)

    def _perform_key_exchange(self, connection: socket.socket) -> Optional[bytes]:
        """
        Execute Diffie-Hellman key exchange with server.
        
        Args:
            connection: Active socket connection
            
        Returns:
            Derived AES session key or None if failed
        """
        print("[CLIENT] 3. --- Initiating Diffie-Hellman Key Exchange ---")

        # Generate client key pair using global parameters
        client_private_key, client_public_key = DiffieHellmanKeyExchange.generate_key_pair()
        client_public_value = client_public_key.public_numbers().y
        
        # Get DH parameters for transmission
        prime_modulus, generator = DiffieHellmanKeyExchange.get_dh_parameters_values()
        
        # Send DH initiation message
        key_exchange_msg = KeyExchangeMessage(
            generator=generator,
            prime_modulus=prime_modulus,
            public_value=client_public_value,
            is_initiator=True
        )
        connection.sendall(key_exchange_msg.to_json_string().encode())
        print("[CLIENT] 4. Sent DH initiation message (g, p, A).")

        # Receive server's DH response
        server_response_data = connection.recv(4096).decode()
        if not server_response_data:
            return None
            
        server_response = json.loads(server_response_data)
        
        if server_response.get('message_type') != MessageType.DH_RESPONSE:
            print("[CLIENT] ❌ Expected DH response, received unexpected message.")
            return None
            
        server_public_value = server_response.get('public_component')
        print("[CLIENT] 5. Received DH response message (B).")

        # Compute shared secret and derive AES key
        shared_secret = DiffieHellmanKeyExchange.compute_shared_secret(
            client_private_key, 
            server_public_value
        )
        session_key = DiffieHellmanKeyExchange.derive_aes_key_from_shared_secret(shared_secret)
        
        print("[CLIENT] 6. Successfully derived shared session key.")
        return session_key

    def _execute_authentication_flow(
        self, 
        connection: socket.socket, 
        username: str, 
        password: str, 
        email: Optional[str] = None, 
        is_registration: bool = False
    ) -> Optional[bytes]:
        """
        Execute complete authentication protocol with server.
        
        Args:
            connection: Socket connection to server
            username: User's username
            password: User's password
            email: User's email (required for registration)
            is_registration: True for registration, False for login
            
        Returns:
            Session key if authentication successful, None otherwise
        """
        operation_type = "REGISTRATION" if is_registration else "LOGIN"
        print(f"\n[CLIENT] --- Starting Control Plane for {operation_type} ({username}) ---")

        # Phase 1: Certificate exchange and validation
        hello_message = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(self.client_certificate),
            nonce_data=encode_to_base64(secrets.token_bytes(16)),
            is_client=True
        )
        connection.sendall(hello_message.to_json_string().encode())
        print("[CLIENT] 1. Sent client hello with certificate.")

        # Receive and validate server response
        server_hello_data = connection.recv(4096)
        if server_hello_data == MessageType.CERTIFICATE_ERROR.encode():
            print("[CLIENT] ❌ Server rejected client certificate.")
            return None
            
        server_hello = json.loads(server_hello_data.decode())
        print("[CLIENT] 2. Received server hello message.")

        # Validate server certificate
        server_certificate_data = decode_from_base64(server_hello["certificate_data"])
        try:
            CertificateManager.validate_certificate_chain(
                server_certificate_data, 
                "server.local", 
                self.trusted_ca
            )
            print("[CLIENT] ✅ Server certificate validated successfully.")
        except CertificateValidationException as validation_error:
            print(f"[CLIENT] ❌ Server certificate validation failed: {validation_error}")
            return None

        # Extract server's public key for signature verification
        self.server_public_key = RSASigning.extract_public_key_from_certificate(server_certificate_data)
        print("[CLIENT] ✅ Extracted server public key for signature verification")

        # Phase 2: Key exchange
        session_key = self._perform_key_exchange(connection)
        if not session_key:
            return None
            
        aes_cipher = AES128Cipher(session_key)

        # Phase 3: Encrypt and send credentials
        auth_payload = AuthenticationData(
            user_email=email if email else "",
            user_name=username,
            user_password=password
        )
        
        plaintext_data = auth_payload.convert_to_json_bytes()
        encrypted_payload = aes_cipher.encrypt_data(plaintext_data)
        
        message_kind = MessageType.USER_REGISTRATION if is_registration else MessageType.USER_LOGIN
        secure_message = SecurePayloadMessage(
            message_kind=message_kind,
            encrypted_content=encode_to_base64(encrypted_payload)
        )
        
        connection.sendall(secure_message.to_json_string().encode())
        print(f"[CLIENT] 7. Sent encrypted {message_kind.upper()} payload.")

        # Phase 4: Receive authentication result
        auth_response = connection.recv(1024).decode()
        
        if auth_response == MessageType.OPERATION_SUCCESS:
            print(f"[CLIENT] 8. Authentication successful. Session established.")
            return session_key
        else:
            print(f"[CLIENT] 8. ❌ Authentication failed: {auth_response}")
            return None

    def _start_chat_session(self, connection: socket.socket, session_key: bytes, username: str):
        """Start interactive chat session with message signing."""
        self.session_key = session_key
        self.username = username
        self.running = True
        self.sequence_number = 0
        self.transcript = []
        
        aes_cipher = AES128Cipher(session_key)
        
        # Start thread for receiving messages
        receive_thread = threading.Thread(target=self._receive_messages, args=(connection, aes_cipher))
        receive_thread.daemon = True
        receive_thread.start()
        
        print(f"\n[CLIENT] 💬 Secure chat session started as '{username}'")
        print("🔐 All messages are now signed and verified for integrity")
        print("Type your messages below:")
        print("  /quit     - Exit chat and generate session receipt")
        print("  /receipt  - Generate session receipt without exiting")
        print("-" * 50)
        
        try:
            while self.running:
                try:
                    print(f"{self.username}> ", end='', flush=True)
                    message = input().strip()
                    
                    if message.lower() == '/quit':
                        self._generate_session_receipt(connection)
                        print("[CLIENT] 👋 Goodbye!")
                        self.running = False
                        break
                    elif message.lower() == '/receipt':
                        self._generate_session_receipt(connection)
                    elif message:
                        self._send_signed_message(connection, aes_cipher, message)
                        
                except KeyboardInterrupt:
                    self._generate_session_receipt(connection)
                    print("\n[CLIENT] 👋 Goodbye!")
                    self.running = False
                    break
                except EOFError:
                    break
                    
        except Exception as e:
            print(f"[CLIENT] ❌ Chat error: {e}")
        finally:
            self.running = False
            connection.close()

    def _send_signed_message(self, connection: socket.socket, aes_cipher: AES128Cipher, plaintext: str):
        """Send a signed and encrypted chat message."""
        # Increment sequence number
        self.sequence_number += 1
        timestamp = int(time.time() * 1000)  # Unix milliseconds
        
        # Encrypt the message
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aes_cipher.encrypt_data(plaintext_bytes)
        ciphertext_b64 = encode_to_base64(ciphertext)
        
        # Compute hash: SHA256(seqno || timestamp || ciphertext)
        hash_data = str(self.sequence_number).encode() + str(timestamp).encode() + ciphertext
        message_hash = create_sha256_hash(hash_data)
        
        # Sign the hash with client's private key
        signature = RSASigning.sign_data(self.private_key, message_hash)
        signature_b64 = encode_to_base64(signature)
        
        # Create signed message
        signed_msg = {
            'type': MessageType.CHAT_MESSAGE_SIGNED,
            'seqno': self.sequence_number,
            'ts': timestamp,
            'ct': ciphertext_b64,
            'sig': signature_b64
        }
        
        # Add to transcript
        self.transcript.append({
            'seqno': self.sequence_number,
            'timestamp': timestamp,
            'ciphertext': ciphertext_b64,
            'signature': signature_b64,
            'peer_cert_fingerprint': 'server'
        })
        
        # Send message
        connection.sendall(json.dumps(signed_msg).encode())
        print(f"[CLIENT] 📨 Sent signed message (seq: {self.sequence_number})")

    def _receive_messages(self, connection: socket.socket, aes_cipher: AES128Cipher):
        """Receive messages from server in a separate thread."""
        try:
            connection.settimeout(1.0)
            
            while self.running:
                try:
                    data = connection.recv(4096)
                    if data:
                        self._process_received_message(data, aes_cipher)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError):
                    if self.running:
                        print("\n[CLIENT] ❌ Connection lost with server")
                    self.running = False
                    break
                    
        except Exception as e:
            if self.running:
                print(f"\n[CLIENT] ❌ Error receiving messages: {e}")

    def _process_received_message(self, data: bytes, aes_cipher: AES128Cipher):
        """Process received signed message from server."""
        try:
            message_data = json.loads(data.decode())
            message_type = message_data.get('type')
            
            if message_type == MessageType.CHAT_MESSAGE_SIGNED:
                # Extract message components
                seqno = message_data.get('seqno')
                timestamp = message_data.get('ts')
                ciphertext_b64 = message_data.get('ct')
                signature_b64 = message_data.get('sig')
                
                # Verify sequence number (replay protection)
                if seqno <= self.sequence_number:
                    print(f"\n[CLIENT] ❌ Replay attack detected: seqno {seqno}")
                    return
                
                # Decode components
                ciphertext = decode_from_base64(ciphertext_b64)
                signature = decode_from_base64(signature_b64)
                
                # Compute hash for verification: SHA256(seqno || timestamp || ciphertext)
                hash_data = str(seqno).encode() + str(timestamp).encode() + ciphertext
                computed_hash = create_sha256_hash(hash_data)
                
                # Verify signature using server's public key
                if not RSASigning.verify_signature(self.server_public_key, computed_hash, signature):
                    print(f"\n[CLIENT] ❌ Server signature verification failed!")
                    return
                
                # Decrypt the message
                plaintext = aes_cipher.decrypt_data(ciphertext)
                message_content = plaintext.decode('utf-8')
                
                # Update sequence number
                self.sequence_number = seqno
                
                # Add to transcript
                self.transcript.append({
                    'seqno': seqno,
                    'timestamp': timestamp,
                    'ciphertext': ciphertext_b64,
                    'signature': signature_b64,
                    'peer_cert_fingerprint': 'server'
                })
                
                # Display message
                print(f"\n[SERVER]: {message_content}")
                print(f"{self.username}> ", end='', flush=True)
                
            elif message_type == MessageType.SESSION_RECEIPT:
                # Handle server's session receipt
                print(f"\n[CLIENT] 📄 Received session receipt from server")
                print(f"{self.username}> ", end='', flush=True)
                    
        except Exception as e:
            print(f"\n[CLIENT] ❌ Error processing message: {e}")

    def _generate_session_receipt(self, connection: socket.socket):
        """Generate and display session receipt for non-repudiation."""
        if not self.transcript:
            print("[CLIENT] No messages exchanged in this session")
            return
        
        # Compute transcript hash
        transcript_data = b""
        for entry in self.transcript:
            line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry['peer_cert_fingerprint']}\n"
            transcript_data += line.encode()
        
        transcript_hash = create_sha256_hex_hash(transcript_data)
        
        # Sign transcript hash with client's private key
        signature = RSASigning.sign_data(self.private_key, transcript_hash.encode())
        signature_b64 = encode_to_base64(signature)
        
        # Create session receipt
        receipt = {
            'type': MessageType.SESSION_RECEIPT,
            'peer': 'client',
            'first_seq': self.transcript[0]['seqno'],
            'last_seq': self.transcript[-1]['seqno'],
            'transcript_sha256': transcript_hash,
            'sig': signature_b64
        }
        
        print("\n" + "="*60)
        print("CLIENT SESSION RECEIPT (Non-Repudiation Proof)")
        print("="*60)
        print(f"Peer: {receipt['peer']}")
        print(f"Message Range: {receipt['first_seq']} - {receipt['last_seq']}")
        print(f"Transcript Hash: {receipt['transcript_sha256']}")
        print(f"Signature: {receipt['sig'][:50]}...")
        print("="*60)
        print("This receipt proves your participation in this conversation.")
        print("Any modification to the transcript will invalidate this signature.")
        
        # Save receipt to file
        receipt_filename = f"client_receipt_{int(time.time())}.json"
        with open(receipt_filename, "w") as f:
            json.dump(receipt, f, indent=2)
        print(f"Receipt saved to {receipt_filename}")

    def run_client_operation(self, command_line_args):
        """
        Execute client operation based on command line arguments.
        
        Args:
            command_line_args: Parsed command line arguments
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                print(f"[CLIENT] 🔗 Connecting to {self.SERVER_HOST}:{self.SERVER_PORT}...")
                client_socket.connect(self.server_address)
                print("[CLIENT] 🤝 Connected to server successfully.")

                is_registration_operation = command_line_args.register
                authentication_result = self._execute_authentication_flow(
                    client_socket, 
                    command_line_args.username, 
                    command_line_args.password, 
                    command_line_args.email, 
                    is_registration_operation
                )

                if authentication_result and isinstance(authentication_result, bytes):
                    print("[CLIENT] ✅ Authentication completed. Session key established.")
                    # Start chat session with signed messages
                    self._start_chat_session(client_socket, authentication_result, command_line_args.username)
                else:
                    print("[CLIENT] ❌ Authentication failed. Closing connection.")

            except ConnectionRefusedError:
                print(f"[CLIENT] ❌ Connection refused. Ensure server is running on {self.SERVER_HOST}:{self.SERVER_PORT}")
            except Exception as e:
                print(f"[CLIENT] ❌ Error: {e}")
            finally:
                self.running = False


def parse_command_line_arguments():
    """Parse and validate command line arguments."""
    argument_parser = argparse.ArgumentParser(description="Secure Chat Client")
    
    auth_mode_group = argument_parser.add_mutually_exclusive_group(required=True)
    auth_mode_group.add_argument('--register', action='store_true', help='Register new user')
    auth_mode_group.add_argument('--login', action='store_true', help='Login existing user')
    
    argument_parser.add_argument('--username', required=True, help='Username for authentication')
    argument_parser.add_argument('--password', required=True, help='Password for authentication')
    argument_parser.add_argument('--email', help='Email address (required for registration)')
    
    return argument_parser.parse_args()


if __name__ == '__main__':
    client_arguments = parse_command_line_arguments()
    chat_client = SecureChatClient()
    chat_client.run_client_operation(client_arguments)