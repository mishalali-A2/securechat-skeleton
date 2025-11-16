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
from app.common.utils import decode_from_base64, encode_to_base64
from app.crypto.pki import CertificateManager, CertificateValidationException
from app.crypto.dh import DiffieHellmanKeyExchange
from app.crypto.aes import AES128Cipher
from app.common.protocol import (
    CertificateExchangeMessage, 
    KeyExchangeMessage, 
    AuthenticationData, 
    SecurePayloadMessage, 
    MessageType
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
        self.connected_users = {}  # Store connected users: username -> (socket, session_key, aes_cipher)

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

    def _handle_authentication_protocol(self, client_connection: socket.socket) -> tuple[bool, Optional[bytes], Optional[str]]:
        """
        Handle complete authentication protocol with client.
        
        Args:
            client_connection: Client socket connection
            
        Returns:
            Tuple of (success, session_key, username)
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
            return False, None, None

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
            return False, None, None

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
            return False, None, None

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
            return True, session_key, username
        else:
            print(f"[SERVER] ❌ Authentication failed. Sent {response_type}.")
            return False, None, None

    def _handle_chat_session(self, client_connection: socket.socket, session_key: bytes, username: str):
        """Handle chat session for authenticated user."""
        aes_cipher = AES128Cipher(session_key)
        
        # Add user to connected users
        self.connected_users[username] = (client_connection, session_key, aes_cipher)
        print(f"[SERVER] 👤 User '{username}' joined the chat")
        
        try:
            client_connection.settimeout(0.1)  # Non-blocking for chat
            
            while True:
                try:
                    # Check for incoming messages
                    data = client_connection.recv(4096)
                    if data:
                        self._process_chat_message(data, aes_cipher, username)
                    # You can add a small delay to prevent high CPU usage
                    time.sleep(0.1)
                except socket.timeout:
                    # No data, continue listening
                    continue
                except (ConnectionResetError, ConnectionAbortedError):
                    break
                    
        except Exception as e:
            print(f"[SERVER] ❌ Chat session error for {username}: {e}")
        finally:
            # Remove user from connected users
            if username in self.connected_users:
                del self.connected_users[username]
            print(f"[SERVER] 👋 User '{username}' left the chat")
            client_connection.close()

    def _process_chat_message(self, data: bytes, aes_cipher: AES128Cipher, username: str):
        """Process incoming chat message."""
        try:
            message_data = json.loads(data.decode())
            message_type = message_data.get('message_type')
            
            if message_type == MessageType.CHAT_MESSAGE:
                encrypted_content = decode_from_base64(message_data['encrypted_payload'])
                decrypted = aes_cipher.decrypt_data(encrypted_content)
                chat_data = json.loads(decrypted.decode())
                
                message_content = chat_data.get('content', '')
                print(f"[SERVER] 💬 {username}: {message_content}")
                
                # Broadcast to other users
                self._broadcast_message(username, message_content)
                
        except Exception as e:
            print(f"[SERVER] ❌ Error processing chat message: {e}")

    def _broadcast_message(self, sender: str, message: str):
        """Broadcast message to all connected users except sender."""
        chat_msg = {
            'message_type': MessageType.CHAT_MESSAGE,
            'sender': sender,
            'content': message,
            'timestamp': int(time.time())
        }
        
        for username, (user_conn, user_key, user_cipher) in self.connected_users.items():
            if username != sender:
                try:
                    plaintext = json.dumps(chat_msg).encode()
                    encrypted = user_cipher.encrypt_data(plaintext)
                    
                    secure_msg = SecurePayloadMessage(
                        message_kind=MessageType.CHAT_MESSAGE,
                        encrypted_content=encode_to_base64(encrypted)
                    )
                    user_conn.sendall(secure_msg.to_json_string().encode())
                except Exception as e:
                    print(f"[SERVER] ❌ Failed to send to {username}: {e}")

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
                
                while True:
                    client_connection, client_address = server_socket.accept()
                    print(f"[SERVER] 🔄 New connection from {client_address}")
                    
                    # Handle authentication
                    auth_success, session_key, username = self._handle_authentication_protocol(client_connection)
                    
                    if auth_success and session_key and username:
                        print(f"[SERVER] ✅ Client {client_address} authenticated successfully.")
                        # Start chat session
                        self._handle_chat_session(client_connection, session_key, username)
                    else:
                        print(f"[SERVER] ❌ Client {client_address} authentication failed.")
                        client_connection.close()
                        
            except KeyboardInterrupt:
                print("\n[SERVER] 🛑 Server shutdown initiated...")
            finally:
                # Close all connections
                for username, (conn, key, cipher) in self.connected_users.items():
                    try:
                        conn.close()
                    except:
                        pass
                self.connected_users.clear()
                self.user_database.close_connection()
                server_socket.close()
                print("[SERVER] 🛑 Server shutdown complete.")


if __name__ == '__main__':
    chat_server = SecureChatServer()
    chat_server.start_server()