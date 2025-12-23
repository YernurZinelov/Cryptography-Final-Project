"""Tests for file encryption module."""
import pytest
import os
import tempfile
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from files import FileEncryption, KeyDerivation, IntegrityVerification


class TestKeyDerivation:
    """Tests for key derivation."""
    
    def test_argon2_derivation(self):
        """Test Argon2id key derivation."""
        password = "test_password"
        
        key, salt = KeyDerivation.derive_key_argon2(password)
        
        assert len(key) == 32
        assert len(salt) == 32
    
    def test_same_password_same_salt(self):
        """Test same password and salt produce same key."""
        password = "test_password"
        salt = b"fixed_salt_12345678901234567890"
        
        key1, _ = KeyDerivation.derive_key_argon2(password, salt)
        key2, _ = KeyDerivation.derive_key_argon2(password, salt)
        
        assert key1 == key2
    
    def test_different_passwords(self):
        """Test different passwords produce different keys."""
        salt = b"fixed_salt_12345678901234567890"
        
        key1, _ = KeyDerivation.derive_key_argon2("password1", salt)
        key2, _ = KeyDerivation.derive_key_argon2("password2", salt)
        
        assert key1 != key2
    
    def test_pbkdf2_derivation(self):
        """Test PBKDF2 key derivation."""
        password = "test_password"
        
        key, salt = KeyDerivation.derive_key_pbkdf2(password)
        
        assert len(key) == 32
        assert len(salt) == 32


class TestIntegrityVerification:
    """Tests for integrity verification."""
    
    def test_hash_bytes(self):
        """Test SHA-256 hash of bytes."""
        data = b"test data"
        hash1 = IntegrityVerification.hash_bytes(data)
        hash2 = IntegrityVerification.hash_bytes(data)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # Hex string
    
    def test_hmac_bytes(self):
        """Test HMAC-SHA256 of bytes."""
        data = b"test data"
        key = b"secret_key"
        
        hmac = IntegrityVerification.hmac_bytes(data, key)
        
        assert len(hmac) == 64
    
    def test_hmac_different_keys(self):
        """Test different keys produce different HMACs."""
        data = b"test data"
        
        hmac1 = IntegrityVerification.hmac_bytes(data, b"key1")
        hmac2 = IntegrityVerification.hmac_bytes(data, b"key2")
        
        assert hmac1 != hmac2
    
    def test_verify_hmac(self):
        """Test HMAC verification."""
        data = b"test data"
        key = b"secret_key"
        
        hmac = IntegrityVerification.hmac_bytes(data, key)
        
        assert IntegrityVerification.verify_bytes_hmac(data, key, hmac)
        assert not IntegrityVerification.verify_bytes_hmac(data, key, "wrong_hmac")


class TestFileEncryption:
    """Tests for file encryption."""
    
    def test_encrypt_decrypt_file(self):
        """Test file encryption and decryption."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Secret file content for testing encryption.")
            input_path = f.name
        
        encrypted_path = input_path + ".enc"
        decrypted_path = input_path + ".dec"
        
        try:
            # Encrypt
            result = FileEncryption.encrypt_file(
                input_path, encrypted_path, "password123"
            )
            
            assert os.path.exists(encrypted_path)
            assert result['original_hash']
            
            # Decrypt
            result = FileEncryption.decrypt_file(
                encrypted_path, decrypted_path, "password123"
            )
            
            assert result['verified']
            
            # Verify content
            with open(input_path, 'rb') as f:
                original = f.read()
            with open(decrypted_path, 'rb') as f:
                decrypted = f.read()
            
            assert original == decrypted
            
        finally:
            for path in [input_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.remove(path)
    
    def test_wrong_password_fails(self):
        """Test decryption with wrong password fails."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Secret content")
            input_path = f.name
        
        encrypted_path = input_path + ".enc"
        decrypted_path = input_path + ".dec"
        
        try:
            FileEncryption.encrypt_file(input_path, encrypted_path, "correct")
            
            with pytest.raises(ValueError):
                FileEncryption.decrypt_file(encrypted_path, decrypted_path, "wrong")
            
        finally:
            for path in [input_path, encrypted_path]:
                if os.path.exists(path):
                    os.remove(path)
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
    
    def test_encrypt_decrypt_bytes(self):
        """Test bytes encryption and decryption."""
        data = b"Test data for encryption"
        password = "secure_password"
        
        encrypted = FileEncryption.encrypt_bytes(data, password)
        decrypted = FileEncryption.decrypt_bytes(encrypted, password)
        
        assert decrypted == data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])