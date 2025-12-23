"""File integrity verification using SHA-256 and HMAC."""
import os
import hmac
import hashlib
from typing import BinaryIO


class IntegrityVerification:
    """
    File integrity verification using cryptographic hashes.
    
    Provides:
    - SHA-256 for file checksums
    - HMAC-SHA256 for authenticated integrity
    """
    
    CHUNK_SIZE = 64 * 1024  # 64 KB chunks for streaming
    
    @classmethod
    def hash_file(cls, filepath: str) -> str:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            filepath: Path to file
            
        Returns:
            Hex-encoded hash
        """
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(cls.CHUNK_SIZE):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    @classmethod
    def hash_bytes(cls, data: bytes) -> str:
        """Calculate SHA-256 hash of bytes."""
        return hashlib.sha256(data).hexdigest()
    
    @classmethod
    def hash_file_object(cls, file_obj: BinaryIO) -> str:
        """
        Calculate SHA-256 hash from file object.
        
        Args:
            file_obj: Open file object in binary mode
            
        Returns:
            Hex-encoded hash
        """
        sha256 = hashlib.sha256()
        
        while chunk := file_obj.read(cls.CHUNK_SIZE):
            sha256.update(chunk)
        
        return sha256.hexdigest()
    
    @classmethod
    def hmac_file(cls, filepath: str, key: bytes) -> str:
        """
        Calculate HMAC-SHA256 of a file.
        
        Args:
            filepath: Path to file
            key: HMAC key
            
        Returns:
            Hex-encoded HMAC
        """
        h = hmac.new(key, digestmod=hashlib.sha256)
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(cls.CHUNK_SIZE):
                h.update(chunk)
        
        return h.hexdigest()
    
    @classmethod
    def hmac_bytes(cls, data: bytes, key: bytes) -> str:
        """Calculate HMAC-SHA256 of bytes."""
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    @classmethod
    def verify_file_hash(cls, filepath: str, expected_hash: str) -> bool:
        """
        Verify file hash matches expected value.
        
        Args:
            filepath: Path to file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            True if hash matches
        """
        actual_hash = cls.hash_file(filepath)
        return hmac.compare_digest(actual_hash, expected_hash)
    
    @classmethod
    def verify_file_hmac(cls, filepath: str, key: bytes, 
                         expected_hmac: str) -> bool:
        """
        Verify file HMAC matches expected value.
        
        Args:
            filepath: Path to file
            key: HMAC key
            expected_hmac: Expected HMAC value
            
        Returns:
            True if HMAC matches
        """
        actual_hmac = cls.hmac_file(filepath, key)
        return hmac.compare_digest(actual_hmac, expected_hmac)
    
    @classmethod
    def verify_bytes_hmac(cls, data: bytes, key: bytes,
                          expected_hmac: str) -> bool:
        """Verify HMAC of bytes data."""
        actual_hmac = cls.hmac_bytes(data, key)
        return hmac.compare_digest(actual_hmac, expected_hmac)