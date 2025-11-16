"""
Protocol message definitions for secure chat system.
Defines message formats and types for client-server communication.
"""

import json
from time import time
from typing import Optional, Dict, Any


class MessageType:
    # Authentication messages
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    DH_INITIATION = "dh_initiation"
    DH_RESPONSE = "dh_response"
    USER_REGISTRATION = "registration"
    USER_LOGIN = "login"
    OPERATION_SUCCESS = "success"
    OPERATION_FAILURE = "failure"
    CERTIFICATE_ERROR = "certificate_error"
    CHAT_MESSAGE_SIGNED = "msg"  # Signed chat message
    SESSION_RECEIPT = "receipt"
    
    # Chat messages (ADD THESE)
    CHAT_MESSAGE = "chat_message"
    CHAT_BROADCAST = "chat_broadcast"
    USER_LIST = "user_list"
    PRIVATE_MESSAGE = "private_message"


class ProtocolMessage:
    def to_serializable_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary, excluding None values."""
        return {
            key: value 
            for key, value in self.__dict__.items() 
            if value is not None
        }
    
    def to_json_string(self) -> str:
        return json.dumps(self.to_serializable_dict())


class CertificateExchangeMessage(ProtocolMessage):
    def __init__(self, certificate_pem: str, nonce_data: str, is_client: bool = True):
        self.message_type = (
            MessageType.CLIENT_HELLO 
            if is_client 
            else MessageType.SERVER_HELLO
        )
        self.certificate_data = certificate_pem  # Base64 PEM certificate
        self.nonce_value = nonce_data           # Base64 encoded nonce


class KeyExchangeMessage(ProtocolMessage):
    def __init__(
        self, 
        generator: int, 
        prime_modulus: int, 
        public_value: Optional[int] = None,
        is_initiator: bool = True
    ):
        self.message_type = (
            MessageType.DH_INITIATION 
            if is_initiator 
            else MessageType.DH_RESPONSE
        )
        self.generator_value = generator
        self.prime_modulus = prime_modulus
        self.public_component = public_value


class AuthenticationData(ProtocolMessage):
    def __init__(self, user_email: str, user_name: str, user_password: str):
        self.email_address = user_email
        self.username = user_name
        self.password_value = user_password
    
    def convert_to_json_bytes(self) -> bytes:
        return json.dumps(self.to_serializable_dict()).encode('utf-8')


class SecurePayloadMessage(ProtocolMessage):
    """Encrypted message container for authentication data."""
    
    def __init__(self, message_kind: str, encrypted_content: str):
        self.message_type = message_kind
        self.encrypted_payload = encrypted_content  # Base64 encoded ciphertext

class ChatMessage(ProtocolMessage):
    """Chat message for secure communication."""
    
    def __init__(self, sender: str, content: str, recipient: str = None):
        self.message_type = MessageType.PRIVATE_MESSAGE if recipient else MessageType.CHAT_MESSAGE
        self.sender = sender
        self.content = content
        self.recipient = recipient
        self.timestamp = int(time.time())


class UserListMessage(ProtocolMessage):
    """Message containing list of online users."""
    
    def __init__(self, users: list):
        self.message_type = MessageType.USER_LIST
        self.users = users

class SignedChatMessage(ProtocolMessage):
    def __init__(self, seqno: int, timestamp: int, ciphertext: str, signature: str):
        self.type = MessageType.CHAT_MESSAGE_SIGNED
        self.seqno = seqno
        self.ts = timestamp
        self.ct = ciphertext  # Base64 encoded ciphertext
        self.sig = signature  # Base64 encoded RSA signature

class SessionReceipt(ProtocolMessage):
    def __init__(self, peer: str, first_seq: int, last_seq: int, 
                 transcript_hash: str, signature: str):
        self.type = MessageType.SESSION_RECEIPT
        self.peer = peer
        self.first_seq = first_seq
        self.last_seq = last_seq
        self.transcript_sha256 = transcript_hash
        self.sig = signature  # Base