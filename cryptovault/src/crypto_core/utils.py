"""Shared cryptographic utilities."""
import secrets
import hmac
import hashlib


def secure_random_bytes(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return secrets.token_bytes(n)


def secure_random_hex(n: int) -> str:
    """Generate n cryptographically secure random bytes as hex."""
    return secrets.token_hex(n)


def constant_time_compare(a: bytes | str, b: bytes | str) -> bool:
    """
    Compare two values in constant time to prevent timing attacks.
    
    Args:
        a: First value
        b: Second value
        
    Returns:
        True if values are equal
    """
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256 and return as hex string."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()