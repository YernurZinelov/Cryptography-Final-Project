"""Message encryption using AES-256-GCM."""
import os
import json
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessageEncryption:
    """
    AES-256-GCM authenticated encryption for messages.
    
    Features:
    - Authenticated encryption (confidentiality + integrity)
    - Unique nonce per message
    - Associated data support
    """
    
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    
    def __init__(self, key: bytes = None):
        """
        Initialize with encryption key.
        
        Args:
            key: 32-byte encryption key or None to generate
        """
        if key is None:
            key = os.urandom(self.KEY_SIZE)
        
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        
        self._key = key
        self._aesgcm = AESGCM(key)
    
    @property
    def key(self) -> bytes:
        """Get encryption key."""
        return self._key
    
    def encrypt(self, plaintext: str | bytes, 
                associated_data: bytes = None) -> dict:
        """
        Encrypt message with AES-256-GCM.
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data (not encrypted)
            
        Returns:
            Dictionary with nonce, ciphertext, and tag
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate unique nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt (GCM combines ciphertext and tag)
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Split ciphertext and tag (tag is last 16 bytes)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        return {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }
    
    def decrypt(self, encrypted: dict, 
                associated_data: bytes = None) -> bytes:
        """
        Decrypt message with AES-256-GCM.
        
        Args:
            encrypted: Dictionary from encrypt()
            associated_data: Must match data used during encryption
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            ValueError: If authentication fails (tampered data)
        """
        nonce = bytes.fromhex(encrypted['nonce'])
        ciphertext = bytes.fromhex(encrypted['ciphertext'])
        tag = bytes.fromhex(encrypted['tag'])
        
        # Combine ciphertext and tag for decryption
        ciphertext_with_tag = ciphertext + tag
        
        try:
            return self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except Exception as e:
            raise ValueError("Decryption failed: authentication error") from e
    
    def decrypt_to_string(self, encrypted: dict,
                          associated_data: bytes = None) -> str:
        """Decrypt and decode to UTF-8 string."""
        return self.decrypt(encrypted, associated_data).decode('utf-8')
    
    @staticmethod
    def pack_message(nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Pack encrypted message into single bytes object.
        Format: [nonce (12) | ciphertext (variable) | tag (16)]
        
        Args:
            nonce: 12-byte nonce
            ciphertext: Encrypted data
            tag: 16-byte authentication tag
            
        Returns:
            Packed message bytes
        """
        return nonce + ciphertext + tag
    
    @classmethod
    def unpack_message(cls, packed: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Unpack message into components.
        
        Args:
            packed: Packed message from pack_message()
            
        Returns:
            Tuple of (nonce, ciphertext, tag)
        """
        if len(packed) < cls.NONCE_SIZE + 16:
            raise ValueError("Packed message too short")
        
        nonce = packed[:cls.NONCE_SIZE]
        tag = packed[-16:]
        ciphertext = packed[cls.NONCE_SIZE:-16]
        
        return nonce, ciphertext, tag