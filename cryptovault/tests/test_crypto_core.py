"""Tests for crypto_core module."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto_core import SHA256, MerkleTree, CaesarCipher, VigenereCipher


class TestSHA256:
    """Tests for SHA-256 implementation."""
    
    def test_empty_string(self):
        """Test hash of empty string."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert SHA256.hash("") == expected
    
    def test_hello_world(self):
        """Test hash of 'hello world'."""
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert SHA256.hash("hello world") == expected
    
    def test_bytes_input(self):
        """Test hash with bytes input."""
        assert SHA256.hash(b"test") == SHA256.hash("test")
    
    def test_hash_bytes_output(self):
        """Test hash_bytes returns correct length."""
        result = SHA256.hash_bytes("test")
        assert len(result) == 32
        assert isinstance(result, bytes)
    
    def test_long_message(self):
        """Test hash of message longer than one block."""
        long_msg = "a" * 1000
        result = SHA256.hash(long_msg)
        assert len(result) == 64  # 256 bits = 64 hex chars


class TestMerkleTree:
    """Tests for Merkle tree implementation."""
    
    def test_single_item(self):
        """Test tree with single item."""
        tree = MerkleTree(["item1"])
        assert tree.get_root() is not None
    
    def test_two_items(self):
        """Test tree with two items."""
        tree = MerkleTree(["item1", "item2"])
        root = tree.get_root()
        assert len(root) == 64
    
    def test_odd_items(self):
        """Test tree with odd number of items."""
        tree = MerkleTree(["a", "b", "c"])
        assert tree.get_root() is not None
    
    def test_proof_generation(self):
        """Test Merkle proof generation."""
        tree = MerkleTree(["a", "b", "c", "d"])
        proof = tree.get_proof(0)
        assert len(proof) > 0
    
    def test_proof_verification(self):
        """Test Merkle proof verification."""
        items = ["tx1", "tx2", "tx3", "tx4"]
        tree = MerkleTree(items)
        root = tree.get_root()
        
        for i, item in enumerate(items):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(item, proof, root)
    
    def test_invalid_proof(self):
        """Test that modified data fails verification."""
        tree = MerkleTree(["a", "b", "c", "d"])
        root = tree.get_root()
        proof = tree.get_proof(0)
        
        # Verify with wrong data
        assert not MerkleTree.verify_proof("wrong", proof, root)
    
    def test_empty_tree_raises(self):
        """Test that empty data raises error."""
        with pytest.raises(ValueError):
            MerkleTree([])


class TestCaesarCipher:
    """Tests for Caesar cipher implementation."""
    
    def test_encrypt_decrypt(self):
        """Test basic encrypt/decrypt cycle."""
        plaintext = "HELLO WORLD"
        shift = 3
        
        encrypted = CaesarCipher.encrypt(plaintext, shift)
        decrypted = CaesarCipher.decrypt(encrypted, shift)
        
        assert decrypted == plaintext
    
    def test_preserves_case(self):
        """Test that case is preserved."""
        result = CaesarCipher.encrypt("Hello World", 1)
        assert result[0].isupper()
        assert result[6].isupper()
    
    def test_preserves_non_alpha(self):
        """Test that non-alphabetic chars are preserved."""
        result = CaesarCipher.encrypt("Hello, World! 123", 5)
        assert "," in result
        assert "!" in result
        assert "123" in result
    
    def test_frequency_analysis(self):
        """Test frequency analysis."""
        text = "aaabbc"
        freq = CaesarCipher.frequency_analysis(text)
        assert freq['a'] == pytest.approx(50.0)
        assert freq['b'] == pytest.approx(33.33, rel=0.1)
    
    def test_break_cipher(self):
        """Test cipher breaking with frequency analysis."""
        original = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = CaesarCipher.encrypt(original, 7)
        
        results = CaesarCipher.break_cipher(encrypted)
        
        # Best result should have shift 7
        assert results[0][0] == 7


class TestVigenereCipher:
    """Tests for Vigenère cipher implementation."""
    
    def test_encrypt_decrypt(self):
        """Test basic encrypt/decrypt cycle."""
        plaintext = "HELLO WORLD"
        key = "KEY"
        
        encrypted = VigenereCipher.encrypt(plaintext, key)
        decrypted = VigenereCipher.decrypt(encrypted, key)
        
        assert decrypted == plaintext
    
    def test_invalid_key_raises(self):
        """Test that non-alpha key raises error."""
        with pytest.raises(ValueError):
            VigenereCipher.encrypt("test", "key123")
    
    def test_kasiski_examination(self):
        """Test Kasiski examination finds key length."""
        # Encrypt with known key
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 5
        key = "SECRET"
        encrypted = VigenereCipher.encrypt(plaintext, key)
        
        key_lengths = VigenereCipher.kasiski_examination(encrypted)
        
        # Should find 6 (length of "SECRET") or factor
        assert any(len(key) % kl == 0 or kl % len(key) == 0 
                   for kl in key_lengths[:3])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])