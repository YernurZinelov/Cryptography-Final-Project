"""Tests for messaging module."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from messaging import KeyExchange, MessageEncryption, MessageSignature


class TestKeyExchange:
    """Tests for ECDH key exchange."""
    
    def test_keypair_generation(self):
        """Test keypair generation."""
        kx = KeyExchange.generate_keypair()
        
        assert kx.private_key is not None
        assert kx.public_key is not None
    
    def test_public_key_export(self):
        """Test public key export."""
        kx = KeyExchange.generate_keypair()
        pubkey_bytes = kx.get_public_key_bytes()
        
        assert len(pubkey_bytes) > 0
        assert isinstance(pubkey_bytes, bytes)
    
    def test_shared_key_derivation(self):
        """Test two parties derive same shared key."""
        alice = KeyExchange.generate_keypair()
        bob = KeyExchange.generate_keypair()
        
        # Both derive with same salt
        salt = b"shared_salt_1234"
        
        alice_shared = alice.derive_shared_key(bob.get_public_key_bytes(), salt)
        bob_shared = bob.derive_shared_key(alice.get_public_key_bytes(), salt)
        
        assert alice_shared == bob_shared
    
    def test_different_sessions_different_keys(self):
        """Test different salts produce different keys."""
        alice = KeyExchange.generate_keypair()
        bob = KeyExchange.generate_keypair()
        
        key1 = alice.derive_shared_key(bob.get_public_key_bytes(), b"salt1")
        key2 = alice.derive_shared_key(bob.get_public_key_bytes(), b"salt2")
        
        assert key1 != key2


class TestMessageEncryption:
    """Tests for AES-GCM message encryption."""
    
    def test_encrypt_decrypt(self):
        """Test basic encrypt/decrypt cycle."""
        encryptor = MessageEncryption()
        message = "Hello, World!"
        
        encrypted = encryptor.encrypt(message)
        decrypted = encryptor.decrypt_to_string(encrypted)
        
        assert decrypted == message
    
    def test_unique_nonces(self):
        """Test each encryption uses unique nonce."""
        encryptor = MessageEncryption()
        
        enc1 = encryptor.encrypt("message1")
        enc2 = encryptor.encrypt("message2")
        
        assert enc1['nonce'] != enc2['nonce']
    
    def test_tamper_detection(self):
        """Test tampering is detected."""
        encryptor = MessageEncryption()
        
        encrypted = encryptor.encrypt("secret message")
        
        # Tamper with ciphertext
        tampered = encrypted.copy()
        ct = bytearray.fromhex(tampered['ciphertext'])
        ct[0] ^= 0xFF
        tampered['ciphertext'] = ct.hex()
        
        with pytest.raises(ValueError):
            encryptor.decrypt(tampered)
    
    def test_associated_data(self):
        """Test associated data authentication."""
        encryptor = MessageEncryption()
        ad = b"metadata"
        
        encrypted = encryptor.encrypt("message", ad)
        
        # Correct AD works
        decrypted = encryptor.decrypt_to_string(encrypted, ad)
        assert decrypted == "message"
        
        # Wrong AD fails
        with pytest.raises(ValueError):
            encryptor.decrypt(encrypted, b"wrong_ad")


class TestMessageSignature:
    """Tests for ECDSA signatures."""
    
    def test_sign_verify(self):
        """Test signing and verification."""
        signer = MessageSignature.generate_keypair()
        message = "Important message"
        
        signature = signer.sign(message)
        
        assert MessageSignature.verify(
            signer.get_public_key_bytes(),
            message,
            signature
        )
    
    def test_invalid_signature(self):
        """Test invalid signature is rejected."""
        signer = MessageSignature.generate_keypair()
        
        signature = signer.sign("original message")
        
        assert not MessageSignature.verify(
            signer.get_public_key_bytes(),
            "different message",
            signature
        )
    
    def test_wrong_key_verification(self):
        """Test signature fails with wrong key."""
        signer1 = MessageSignature.generate_keypair()
        signer2 = MessageSignature.generate_keypair()
        
        signature = signer1.sign("message")
        
        assert not MessageSignature.verify(
            signer2.get_public_key_bytes(),
            "message",
            signature
        )
    
    def test_message_package(self):
        """Test signed message package."""
        signer = MessageSignature.generate_keypair()
        
        package = signer.sign_message_package("test message")
        is_valid, message = MessageSignature.verify_message_package(package)
        
        assert is_valid
        assert message == b"test message"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])