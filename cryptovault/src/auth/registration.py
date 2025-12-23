"""User registration with secure password hashing."""
import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import HashingError


class PasswordStrengthError(Exception):
    """Raised when password doesn't meet strength requirements."""
    pass


class RegistrationService:
    """
    Handle user registration with secure password hashing.
    
    Uses Argon2id for password hashing (winner of Password Hashing Competition).
    """
    
    # Argon2id parameters (OWASP recommendations)
    ph = PasswordHasher(
        time_cost=3,          # Number of iterations
        memory_cost=65536,    # 64 MB
        parallelism=4,        # Parallel threads
        hash_len=32,          # Output length
        salt_len=32           # Salt length
    )
    
    # Password requirements
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    
    @classmethod
    def validate_password_strength(cls, password: str) -> tuple[bool, list[str]]:
        """
        Validate password meets strength requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if cls.REQUIRE_DIGIT and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if cls.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash password using Argon2id.
        
        Args:
            password: Plain text password
            
        Returns:
            Argon2id hash string (includes salt, parameters)
        """
        try:
            return cls.ph.hash(password)
        except HashingError as e:
            raise ValueError(f"Failed to hash password: {e}")
    
    @classmethod
    def verify_password(cls, password_hash: str, password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password_hash: Stored Argon2id hash
            password: Password to verify
            
        Returns:
            True if password matches
        """
        try:
            cls.ph.verify(password_hash, password)
            return True
        except Exception:
            return False
    
    @classmethod
    def needs_rehash(cls, password_hash: str) -> bool:
        """Check if password hash needs to be updated with new parameters."""
        return cls.ph.check_needs_rehash(password_hash)
    
    @classmethod
    def generate_backup_codes(cls, count: int = 10) -> list[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Format: XXXX-XXXX-XXXX
            code = '-'.join(
                secrets.token_hex(2).upper()
                for _ in range(3)
            )
            codes.append(code)
        return codes
    
    @classmethod
    def hash_backup_code(cls, code: str) -> str:
        """Hash a backup code for storage."""
        # Normalize: remove dashes, uppercase
        normalized = code.replace('-', '').upper()
        return cls.ph.hash(normalized)
    
    @classmethod
    def verify_backup_code(cls, code_hash: str, code: str) -> bool:
        """Verify a backup code."""
        normalized = code.replace('-', '').upper()
        return cls.verify_password(code_hash, normalized)