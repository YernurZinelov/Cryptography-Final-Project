"""ECDSA Digital Signatures for message authentication."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class MessageSignature:
    """
    ECDSA digital signatures for message authentication.
    
    Provides:
    - Non-repudiation: sender cannot deny sending
    - Integrity: message cannot be modified
    - Authentication: verifies sender identity
    """
    
    CURVE = ec.SECP256R1()  # P-256
    
    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        """
        Initialize with signing key.
        
        Args:
            private_key: ECDSA private key or None to generate
        """
        if private_key is None:
            self.private_key = ec.generate_private_key(self.CURVE, default_backend())
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    @classmethod
    def generate_keypair(cls) -> 'MessageSignature':
        """Generate new ECDSA keypair."""
        return cls()
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as DER bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_private_key_bytes(self, password: bytes = None) -> bytes:
        """Get private key as DER bytes."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    
    @classmethod
    def load_public_key(cls, key_bytes: bytes) -> ec.EllipticCurvePublicKey:
        """Load public key from DER bytes."""
        return serialization.load_der_public_key(key_bytes, default_backend())
    
    @classmethod
    def load_private_key(cls, key_bytes: bytes, 
                         password: bytes = None) -> 'MessageSignature':
        """Load private key and create instance."""
        private_key = serialization.load_der_private_key(
            key_bytes, password, default_backend()
        )
        return cls(private_key)
    
    def sign(self, message: bytes | str) -> bytes:
        """
        Sign a message with ECDSA.
        
        Args:
            message: Message to sign
            
        Returns:
            Signature bytes
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Sign the SHA-256 hash of the message
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def sign_hex(self, message: bytes | str) -> str:
        """Sign message and return signature as hex string."""
        return self.sign(message).hex()
    
    @classmethod
    def verify(cls, public_key: bytes | ec.EllipticCurvePublicKey,
               message: bytes | str, signature: bytes | str) -> bool:
        """
        Verify a message signature.
        
        Args:
            public_key: Signer's public key
            message: Original message
            signature: Signature to verify
            
        Returns:
            True if signature is valid
        """
        if isinstance(public_key, bytes):
            public_key = cls.load_public_key(public_key)
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        if isinstance(signature, str):
            signature = bytes.fromhex(signature)
        
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    def sign_message_package(self, message: bytes | str) -> dict:
        """
        Create signed message package.
        
        Args:
            message: Message to sign
            
        Returns:
            Dictionary with message, signature, and public key
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return {
            'message': message.hex(),
            'signature': self.sign(message).hex(),
            'public_key': self.get_public_key_bytes().hex()
        }
    
    @classmethod
    def verify_message_package(cls, package: dict) -> tuple[bool, bytes]:
        """
        Verify a signed message package.
        
        Args:
            package: Dictionary from sign_message_package()
            
        Returns:
            Tuple of (is_valid, message_bytes)
        """
        message = bytes.fromhex(package['message'])
        signature = bytes.fromhex(package['signature'])
        public_key = bytes.fromhex(package['public_key'])
        
        is_valid = cls.verify(public_key, message, signature)
        return is_valid, message