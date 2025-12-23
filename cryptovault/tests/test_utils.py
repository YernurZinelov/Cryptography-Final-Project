"""Tests for crypto utilities."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto_core.utils import (
    secure_random_bytes,
    secure_random_hex,
    constant_time_compare,
    hmac_sha256,
    hmac_sha256_hex
)


class TestCryptoUtils:
    """Tests for crypto utilities."""
    
    def test_secure_random_bytes_length(self):
        """Test random bytes has correct length."""
        result = secure_random_bytes(32)
        assert len(result) == 32
    
    def test_secure_random_bytes_unique(self):
        """Test random bytes are unique."""
        result1 = secure_random_bytes(32)
        result2 = secure_random_bytes(32)
        assert result1 != result2
    
    def test_secure_random_hex_length(self):
        """Test random hex has correct length."""
        result = secure_random_hex(16)
        assert len(result) == 32  # 16 bytes = 32 hex chars
    
    def test_secure_random_hex_unique(self):
        """Test random hex are unique."""
        result1 = secure_random_hex(16)
        result2 = secure_random_hex(16)
        assert result1 != result2
    
    def test_constant_time_compare_equal_bytes(self):
        """Test constant time compare with equal bytes."""
        assert constant_time_compare(b"hello", b"hello") == True
    
    def test_constant_time_compare_unequal_bytes(self):
        """Test constant time compare with unequal bytes."""
        assert constant_time_compare(b"hello", b"world") == False
    
    def test_constant_time_compare_equal_strings(self):
        """Test constant time compare with equal strings."""
        assert constant_time_compare("hello", "hello") == True
    
    def test_constant_time_compare_unequal_strings(self):
        """Test constant time compare with unequal strings."""
        assert constant_time_compare("hello", "world") == False
    
    def test_hmac_sha256(self):
        """Test HMAC-SHA256."""
        key = b"secret_key"
        message = b"hello world"
        result = hmac_sha256(key, message)
        assert len(result) == 32  # 256 bits = 32 bytes
    
    def test_hmac_sha256_consistent(self):
        """Test HMAC-SHA256 is consistent."""
        key = b"secret_key"
        message = b"hello world"
        result1 = hmac_sha256(key, message)
        result2 = hmac_sha256(key, message)
        assert result1 == result2
    
    def test_hmac_sha256_different_keys(self):
        """Test different keys produce different HMACs."""
        message = b"hello world"
        result1 = hmac_sha256(b"key1", message)
        result2 = hmac_sha256(b"key2", message)
        assert result1 != result2
    
    def test_hmac_sha256_hex(self):
        """Test HMAC-SHA256 hex output."""
        key = b"secret_key"
        message = b"hello world"
        result = hmac_sha256_hex(key, message)
        assert len(result) == 64  # 32 bytes = 64 hex chars
        assert all(c in '0123456789abcdef' for c in result)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])