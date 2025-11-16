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
        """Start interactive chat session."""
        self.session_key = session_key
        self.username = username
        self.running = True
        
        aes_cipher = AES128Cipher(session_key)
        
        # Start thread for receiving messages
        receive_thread = threading.Thread(target=self._receive_messages, args=(connection, aes_cipher))
        receive_thread.daemon = True
        receive_thread.start()
        
        print(f"\n[CLIENT] 💬 Chat session started as '{username}'")
        print("Type your messages below (type '/quit' to exit):")
        print("-" * 50)
        
        try:
            while self.running:
                try:
                    # Show prompt
                    print(f"{self.username}> ", end='', flush=True)
                    message = input().strip()
                    
                    if message.lower() == '/quit':
                        print("[CLIENT] 👋 Goodbye!")
                        self.running = False
                        break
                    elif message:
                        # Send chat message - use the correct message type
                        chat_data = {
                            'content': message,
                            'timestamp': int(time.time())
                        }
                        
                        plaintext = json.dumps(chat_data).encode()
                        encrypted = aes_cipher.encrypt_data(plaintext)
                        
                        # Use SecurePayloadMessage with CHAT_MESSAGE type
                        secure_msg = SecurePayloadMessage(
                            message_kind=MessageType.CHAT_MESSAGE,
                            encrypted_content=encode_to_base64(encrypted)
                        )
                        connection.sendall(secure_msg.to_json_string().encode())
                        
                except KeyboardInterrupt:
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
        """Process received message from server."""
        try:
            message_data = json.loads(data.decode())
            message_type = message_data.get('message_type')
            
            if message_type == MessageType.CHAT_MESSAGE:
                encrypted_content = decode_from_base64(message_data['encrypted_payload'])
                decrypted = aes_cipher.decrypt_data(encrypted_content)
                chat_data = json.loads(decrypted.decode())
                
                sender = chat_data.get('sender', 'Unknown')
                content = chat_data.get('content', '')
                
                # Only show messages from other users
                if sender != self.username:
                    print(f"\n[{sender}]: {content}")
                    print(f"{self.username}> ", end='', flush=True)
                    
        except Exception as e:
            print(f"\n[CLIENT] ❌ Error processing message: {e}")

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
                    # Start chat session
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