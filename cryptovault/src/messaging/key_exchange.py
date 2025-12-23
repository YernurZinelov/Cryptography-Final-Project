"""ECDH Key Exchange implementation."""
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class KeyExchange:
    """
    Elliptic Curve Diffie-Hellman (ECDH) key exchange using P-256.
    
    Provides secure key agreement between two parties without
    transmitting the shared secret.
    """
    
    CURVE = ec.SECP256R1()  # P-256
    
    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        """
        Initialize with existing key or generate new one.
        
        Args:
            private_key: Existing private key or None to generate new
        """
        if private_key is None:
            self.private_key = ec.generate_private_key(self.CURVE, default_backend())
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    @classmethod
    def generate_keypair(cls) -> 'KeyExchange':
        """Generate a new ECDH keypair."""
        return cls()
    
    def get_public_key_bytes(self) -> bytes:
        """
        Get public key as bytes for transmission.
        
        Returns:
            Public key in X.509 SubjectPublicKeyInfo format
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_public_key_pem(self) -> str:
        """Get public key as PEM string."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def get_private_key_bytes(self, password: bytes = None) -> bytes:
        """
        Get private key as bytes.
        
        Args:
            password: Optional password for encryption
            
        Returns:
            Private key in PKCS8 format
        """
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
        """
        Load public key from bytes.
        
        Args:
            key_bytes: DER-encoded public key
            
        Returns:
            Public key object
        """
        return serialization.load_der_public_key(key_bytes, default_backend())
    
    @classmethod
    def load_private_key(cls, key_bytes: bytes, 
                         password: bytes = None) -> 'KeyExchange':
        """
        Load private key from bytes.
        
        Args:
            key_bytes: DER-encoded private key
            password: Password if encrypted
            
        Returns:
            KeyExchange instance
        """
        private_key = serialization.load_der_private_key(
            key_bytes, password, default_backend()
        )
        return cls(private_key)
    
    def derive_shared_key(self, peer_public_key: bytes | ec.EllipticCurvePublicKey,
                          salt: bytes = None, info: bytes = b"message_key",
                          key_length: int = 32) -> bytes:
        """
        Derive shared secret using ECDH + HKDF.
        
        Args:
            peer_public_key: Peer's public key (bytes or key object)
            salt: Optional salt for HKDF (random if not provided)
            info: Context info for HKDF
            key_length: Desired key length in bytes
            
        Returns:
            Derived key bytes
        """
        if isinstance(peer_public_key, bytes):
            peer_public_key = self.load_public_key(peer_public_key)
        
        # Perform ECDH exchange
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive key using HKDF
        if salt is None:
            salt = os.urandom(16)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        return hkdf.derive(shared_secret)
    
    def derive_shared_key_with_salt(self, peer_public_key: bytes,
                                    info: bytes = b"message_key",
                                    key_length: int = 32) -> tuple[bytes, bytes]:
        """
        Derive shared key and return with salt.
        
        Args:
            peer_public_key: Peer's public key bytes
            info: Context info for HKDF
            key_length: Desired key length
            
        Returns:
            Tuple of (derived_key, salt)
        """
        salt = os.urandom(16)
        key = self.derive_shared_key(peer_public_key, salt, info, key_length)
        return key, salt