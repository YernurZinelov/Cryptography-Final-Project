"""Key derivation from passwords using Argon2."""
import os
import hashlib
from argon2.low_level import hash_secret_raw, Type


class KeyDerivation:
    """
    Derive encryption keys from passwords using Argon2id.
    
    Argon2id is resistant to:
    - GPU attacks (memory-hard)
    - Side-channel attacks (hybrid approach)
    - Time-memory tradeoffs
    """
    
    # Argon2id parameters (OWASP recommendations)
    TIME_COST = 3          # Iterations
    MEMORY_COST = 65536    # 64 MB
    PARALLELISM = 4        # Threads
    HASH_LEN = 32          # 256 bits
    SALT_LEN = 32          # 256 bits
    
    # Alternative: PBKDF2 parameters (if Argon2 unavailable)
    PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation
    
    @classmethod
    def derive_key_argon2(cls, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive key using Argon2id.
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(cls.SALT_LEN)
        
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=cls.TIME_COST,
            memory_cost=cls.MEMORY_COST,
            parallelism=cls.PARALLELISM,
            hash_len=cls.HASH_LEN,
            type=Type.ID  # Argon2id
        )
        
        return key, salt
    
    @classmethod
    def derive_key_pbkdf2(cls, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive key using PBKDF2-HMAC-SHA256.
        
        Args:
            password: User password
            salt: Optional salt
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(cls.SALT_LEN)
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations=cls.PBKDF2_ITERATIONS,
            dklen=cls.HASH_LEN
        )
        
        return key, salt
    
    @classmethod
    def derive_key(cls, password: str, salt: bytes = None,
                   method: str = 'argon2') -> tuple[bytes, bytes]:
        """
        Derive key using specified method.
        
        Args:
            password: User password
            salt: Optional salt
            method: 'argon2' or 'pbkdf2'
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if method == 'argon2':
            return cls.derive_key_argon2(password, salt)
        elif method == 'pbkdf2':
            return cls.derive_key_pbkdf2(password, salt)
        else:
            raise ValueError(f"Unknown method: {method}")
    
    @classmethod
    def get_parameters_info(cls, method: str = 'argon2') -> dict:
        """Get information about KDF parameters for documentation."""
        if method == 'argon2':
            return {
                'algorithm': 'Argon2id',
                'time_cost': cls.TIME_COST,
                'memory_cost_kb': cls.MEMORY_COST,
                'parallelism': cls.PARALLELISM,
                'output_length': cls.HASH_LEN,
                'salt_length': cls.SALT_LEN
            }
        else:
            return {
                'algorithm': 'PBKDF2-HMAC-SHA256',
                'iterations': cls.PBKDF2_ITERATIONS,
                'output_length': cls.HASH_LEN,
                'salt_length': cls.SALT_LEN
            }