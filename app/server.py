"""
Secure Chat Server Implementation.
Handles client connections, authentication, and secure session management.
"""

import socket
import os
import json
import sys
import secrets
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
from app.storage.db import UserDatabaseManager


class SecureChatServer:
    """Main server class for handling secure client connections."""
    
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 8080
    CERTIFICATES_DIRECTORY = "certs"
    
    def __init__(self):
        """Initialize server with required assets and database."""
        self.server_address = (self.SERVER_HOST, self.SERVER_PORT)
        self.server_certificate = self._load_server_certificate()
        self.trusted_ca = CertificateManager.load_root_ca_certificate()
        self.user_database = UserDatabaseManager()
        self.connected_users = {}  # Store connected users: username -> (socket, session_key, aes_cipher, client_cert, last_seqno, transcript)
        
        # Load server's RSA private key for signing
        try:
            self.server_private_key = RSASigning.load_private_key("server")
            print("[SERVER] ✅ Loaded server RSA private key for signing")
        except FileNotFoundError:
            print("[SERVER] ❌ Failed to load server private key for signing")
            exit(1)

    def _load_server_certificate(self) -> bytes:
        """
        Load server certificate from file.
        
        Returns:
            Server certificate PEM data
            
        Raises:
            FileNotFoundError: If certificate file is missing
        """
        certificate_path = os.path.join(self.CERTIFICATES_DIRECTORY, "server_certificate.pem")
        try:
            with open(certificate_path, "rb") as cert_file:
                return cert_file.read()
        except FileNotFoundError as file_error:
            print(f"[SERVER] ❌ Failed to load server certificate: {file_error}")
            exit(1)

    def _perform_key_exchange(self, client_connection: socket.socket) -> Optional[bytes]:
        """
        Execute Diffie-Hellman key exchange with client.
        
        Args:
            client_connection: Client socket connection
            
        Returns:
            Derived AES session key or None if failed
        """
        print("[SERVER] 4. --- Processing Diffie-Hellman Key Exchange ---")

        # Receive client's DH initiation
        client_message_data = client_connection.recv(4096).decode()
        if not client_message_data:
            return None
            
        client_message = json.loads(client_message_data)
        
        if client_message.get('message_type') != MessageType.DH_INITIATION:
            print("[SERVER] ❌ Expected DH initiation, received unexpected message.")
            return None

        # Extract client parameters
        prime_modulus = client_message.get('prime_modulus')
        generator = client_message.get('generator_value')
        client_public_value = client_message.get('public_component')
        
        # Generate server key pair
        server_private_key, server_public_key = DiffieHellmanKeyExchange.generate_key_pair()
        server_public_value = server_public_key.public_numbers().y
        
        # Send server's DH response
        server_response = KeyExchangeMessage(
            generator=generator,
            prime_modulus=prime_modulus,
            public_value=server_public_value,
            is_initiator=False
        )
        client_connection.sendall(server_response.to_json_string().encode())
        print("[SERVER] 5. Sent DH response message (B).")

        # Compute shared secret and derive AES key
        shared_secret = DiffieHellmanKeyExchange.compute_shared_secret(
            server_private_key, 
            client_public_value
        )
        session_key = DiffieHellmanKeyExchange.derive_aes_key_from_shared_secret(shared_secret)
        
        print("[SERVER] 6. Successfully derived shared session key.")
        return session_key

    def _handle_authentication_protocol(self, client_connection: socket.socket) -> tuple[bool, Optional[bytes], Optional[str], Optional[bytes]]:
        """
        Handle complete authentication protocol with client.
        
        Args:
            client_connection: Client socket connection
            
        Returns:
            Tuple of (success, session_key, username, client_certificate)
        """
        client_address = client_connection.getpeername()
        print(f"\n[SERVER] --- Starting Control Plane with {client_address} ---")

        # Phase 1: Certificate exchange and validation
        client_hello_data = json.loads(client_connection.recv(4096).decode())
        print("[SERVER] 1. Received client hello message.")

        # Validate client certificate
        try:
            client_certificate_data = decode_from_base64(client_hello_data["certificate_data"])
            print("[SERVER] 2. Validating client certificate...")
            CertificateManager.validate_certificate_chain(
                client_certificate_data, 
                "client.local", 
                self.trusted_ca
            )
            print("[SERVER] ✅ Client certificate validated successfully.")
            
        except CertificateValidationException:
            client_connection.sendall(MessageType.CERTIFICATE_ERROR.encode())
            return False, None, None, None

        # Send server hello after successful validation
        server_hello = CertificateExchangeMessage(
            certificate_pem=encode_to_base64(self.server_certificate),
            nonce_data=encode_to_base64(secrets.token_bytes(16)),
            is_client=False
        )
        client_connection.sendall(server_hello.to_json_string().encode())
        print("[SERVER] 3. Sent server hello message.")

        # Phase 2: Key exchange
        session_key = self._perform_key_exchange(client_connection)
        if not session_key:
            return False, None, None, None

        aes_cipher = AES128Cipher(session_key)

        # Phase 3: Process encrypted credentials
        encrypted_message_data = json.loads(client_connection.recv(4096).decode())
        authentication_type = encrypted_message_data["message_type"]
        print(f"[SERVER] 7. Received encrypted {authentication_type.upper()} message.")

        # Decrypt and parse authentication data
        encrypted_content = decode_from_base64(encrypted_message_data["encrypted_payload"])
        try:
            decrypted_content = aes_cipher.decrypt_data(encrypted_content)
            auth_data = json.loads(decrypted_content.decode())
            
            username = auth_data.get('username')
            password = auth_data.get('password_value')
            email = auth_data.get('email_address')
            
            print(f"[SERVER] 8. Successfully decrypted payload for user: {username}")
        except Exception as decryption_error:
            print(f"[SERVER] ❌ Decryption failed: {decryption_error}")
            client_connection.sendall(MessageType.OPERATION_FAILURE.encode())
            return False, None, None, None

        # Phase 4: Database authentication/registration
        operation_success = False
        if authentication_type == MessageType.USER_REGISTRATION:
            operation_success = self.user_database.register_new_user(email, username, password)
            status_message = "SUCCESS" if operation_success else "FAILED (user exists)"
            print(f"[SERVER] 9. Registration result: {status_message}")
        elif authentication_type == MessageType.USER_LOGIN:
            operation_success = self.user_database.authenticate_user(username, password)
            status_message = "SUCCESS" if operation_success else "FAILED (invalid credentials)"
            print(f"[SERVER] 9. Login result: {status_message}")

        # Send authentication result
        response_type = MessageType.OPERATION_SUCCESS if operation_success else MessageType.OPERATION_FAILURE
        client_connection.sendall(response_type.encode())
        
        if operation_success:
            print(f"[SERVER] ✅ Authentication completed. Sent {response_type}.")
            return True, session_key, username, client_certificate_data
        else:
            print(f"[SERVER] ❌ Authentication failed. Sent {response_type}.")
            return False, None, None, None

    def _handle_chat_session(self, client_connection: socket.socket, session_key: bytes, username: str, client_certificate: bytes):
        """Handle chat session for authenticated user with message signing."""
        aes_cipher = AES128Cipher(session_key)
        
        # Extract client's public key for signature verification
        client_public_key = RSASigning.extract_public_key_from_certificate(client_certificate)
        
        # Initialize user session state
        user_state = {
            'connection': client_connection,
            'session_key': session_key,
            'aes_cipher': aes_cipher,
            'client_cert': client_certificate,
            'last_seqno': 0,
            'transcript': [],
            'client_public_key': client_public_key
        }
        
        # Add user to connected users
        self.connected_users[username] = user_state
        print(f"[SERVER] 👤 User '{username}' joined the chat (signed messages enabled)")
        
        try:
            client_connection.settimeout(0.1)  # Non-blocking for chat
            
            while True:
                try:
                    # Check for incoming messages
                    data = client_connection.recv(4096)
                    if data:
                        self._process_signed_message(data, username)
                    time.sleep(0.1)
                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError):
                    break
                    
        except Exception as e:
            print(f"[SERVER] ❌ Chat session error for {username}: {e}")
        finally:
            # Generate session receipt before closing
            self._generate_session_receipt(username)
            # Remove user from connected users
            if username in self.connected_users:
                del self.connected_users[username]
            print(f"[SERVER] 👋 User '{username}' left the chat")
            client_connection.close()

    def _process_signed_message(self, data: bytes, username: str):
        """Process incoming signed chat message with integrity verification."""
        try:
            message_data = json.loads(data.decode())
            message_type = message_data.get('type')
            
            if message_type == MessageType.CHAT_MESSAGE_SIGNED:
                user_state = self.connected_users[username]
                
                # Extract message components
                seqno = message_data.get('seqno')
                timestamp = message_data.get('ts')
                ciphertext_b64 = message_data.get('ct')
                signature_b64 = message_data.get('sig')
                
                # Verify sequence number (replay protection)
                if seqno <= user_state['last_seqno']:
                    print(f"[SERVER] ❌ Replay attack detected from {username}: seqno {seqno} <= last {user_state['last_seqno']}")
                    return
                
                # Decode components
                ciphertext = decode_from_base64(ciphertext_b64)
                signature = decode_from_base64(signature_b64)
                
                # Compute hash for verification: SHA256(seqno || timestamp || ciphertext)
                hash_data = str(seqno).encode() + str(timestamp).encode() + ciphertext
                computed_hash = create_sha256_hash(hash_data)
                
                # Verify signature using client's public key
                if not RSASigning.verify_signature(user_state['client_public_key'], computed_hash, signature):
                    print(f"[SERVER] ❌ Signature verification failed for message from {username}")
                    return
                
                # Decrypt the message
                plaintext = user_state['aes_cipher'].decrypt_data(ciphertext)
                message_content = plaintext.decode('utf-8')
                
                print(f"[SERVER] ✅ Verified signed message from {username} (seq: {seqno}): {message_content}")
                
                # Update sequence number
                user_state['last_seqno'] = seqno
                
                # Add to transcript
                user_state['transcript'].append({
                    'seqno': seqno,
                    'timestamp': timestamp,
                    'ciphertext': ciphertext_b64,
                    'signature': signature_b64,
                    'peer_cert_fingerprint': 'client'  # This should be the actual fingerprint
                })
                
                # Broadcast signed message to other users
                self._broadcast_signed_message(username, seqno, timestamp, ciphertext_b64, message_content)
                
            elif message_type == MessageType.SESSION_RECEIPT:
                # Handle client's session receipt
                print(f"[SERVER] 📄 Received session receipt from {username}")
                
        except Exception as e:
            print(f"[SERVER] ❌ Error processing signed message from {username}: {e}")

    def _broadcast_signed_message(self, sender: str, seqno: int, timestamp: int, ciphertext_b64: str, plaintext: str):
        """Broadcast signed message to all connected users except sender."""
        for username, user_state in self.connected_users.items():
            if username != sender:
                try:
                    # Create signed message for the recipient
                    # For server-to-client messages, we need to sign them too
                    recipient_ciphertext = user_state['aes_cipher'].encrypt_data(plaintext.encode())
                    recipient_ciphertext_b64 = encode_to_base64(recipient_ciphertext)
                    
                    # Compute hash and sign for this recipient
                    hash_data = str(seqno).encode() + str(timestamp).encode() + recipient_ciphertext
                    message_hash = create_sha256_hash(hash_data)
                    signature = RSASigning.sign_data(self.server_private_key, message_hash)
                    signature_b64 = encode_to_base64(signature)
                    
                    # Create signed message
                    signed_msg = {
                        'type': MessageType.CHAT_MESSAGE_SIGNED,
                        'seqno': seqno,
                        'ts': timestamp,
                        'ct': recipient_ciphertext_b64,
                        'sig': signature_b64
                    }
                    
                    # Send to recipient
                    user_state['connection'].sendall(json.dumps(signed_msg).encode())
                    
                    # Add to recipient's transcript
                    user_state['transcript'].append({
                        'seqno': seqno,
                        'timestamp': timestamp,
                        'ciphertext': recipient_ciphertext_b64,
                        'signature': signature_b64,
                        'peer_cert_fingerprint': 'server'
                    })
                    
                except Exception as e:
                    print(f"[SERVER] ❌ Failed to send to {username}: {e}")

    def _generate_session_receipt(self, username: str):
        """Generate session receipt for non-repudiation proof."""
        if username not in self.connected_users:
            return
            
        user_state = self.connected_users[username]
        transcript = user_state.get('transcript', [])
        
        if not transcript:
            print(f"[SERVER] No messages exchanged with {username}")
            return
        
        # Compute transcript hash
        transcript_data = b""
        for entry in transcript:
            line = f"{entry['seqno']}|{entry['timestamp']}|{entry['ciphertext']}|{entry['signature']}|{entry['peer_cert_fingerprint']}\n"
            transcript_data += line.encode()
        
        transcript_hash = create_sha256_hex_hash(transcript_data)
        
        # Sign transcript hash with server's private key
        signature = RSASigning.sign_data(self.server_private_key, transcript_hash.encode())
        signature_b64 = encode_to_base64(signature)
        
        # Create session receipt
        receipt = {
            'type': MessageType.SESSION_RECEIPT,
            'peer': 'server',
            'first_seq': transcript[0]['seqno'],
            'last_seq': transcript[-1]['seqno'],
            'transcript_sha256': transcript_hash,
            'sig': signature_b64
        }
        
        print("\n" + "="*60)
        print(f"SERVER SESSION RECEIPT for {username}")
        print("="*60)
        print(f"Peer: {receipt['peer']}")
        print(f"Message Range: {receipt['first_seq']} - {receipt['last_seq']}")
        print(f"Transcript Hash: {receipt['transcript_sha256']}")
        print(f"Signature: {receipt['sig'][:50]}...")
        print("="*60)
        print("This receipt proves server's participation in this conversation.")
        
        # Save receipt to file
        receipt_filename = f"server_receipt_{username}_{int(time.time())}.json"
        with open(receipt_filename, "w") as f:
            json.dump(receipt, f, indent=2)
        print(f"Server receipt saved to {receipt_filename}")

    def start_server(self):
        """Start the secure chat server and handle client connections."""
        if not self.user_database.connection:
            print("[SERVER] ❌ Database connection failed. Server cannot start.")
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            try:
                server_socket.bind(self.server_address)
                server_socket.listen(5)
                print(f"[SERVER] 🟢 Server listening on {self.SERVER_HOST}:{self.SERVER_PORT}")
                print(f"[SERVER] 🔐 Signed message enforcement: ENABLED")
                print(f"[SERVER] 📄 Non-repudiation receipts: ENABLED")
                
                while True:
                    client_connection, client_address = server_socket.accept()
                    print(f"[SERVER] 🔄 New connection from {client_address}")
                    
                    # Handle authentication
                    auth_success, session_key, username, client_certificate = self._handle_authentication_protocol(client_connection)
                    
                    if auth_success and session_key and username and client_certificate:
                        print(f"[SERVER] ✅ Client {client_address} authenticated successfully.")
                        # Start chat session with signed messages
                        self._handle_chat_session(client_connection, session_key, username, client_certificate)
                    else:
                        print(f"[SERVER] ❌ Client {client_address} authentication failed.")
                        client_connection.close()
                        
            except KeyboardInterrupt:
                print("\n[SERVER] 🛑 Server shutdown initiated...")
            finally:
                # Close all connections and generate final receipts
                for username, user_state in self.connected_users.items():
                    try:
                        self._generate_session_receipt(username)
                        user_state['connection'].close()
                    except:
                        pass
                self.connected_users.clear()
                self.user_database.close_connection()
                server_socket.close()
                print("[SERVER] 🛑 Server shutdown complete.")


if __name__ == '__main__':
    chat_server = SecureChatServer()
    chat_server.start_server()