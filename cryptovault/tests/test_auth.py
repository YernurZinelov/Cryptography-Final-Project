"""Tests for authentication module."""
import pytest
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from auth import RegistrationService, LoginService, TOTPService


class TestRegistrationService:
    """Tests for registration service."""
    
    def test_password_strength_valid(self):
        """Test valid password passes validation."""
        password = "SecurePass123!"
        is_valid, errors = RegistrationService.validate_password_strength(password)
        assert is_valid
        assert len(errors) == 0
    
    def test_password_strength_too_short(self):
        """Test short password fails."""
        password = "Short1!"
        is_valid, errors = RegistrationService.validate_password_strength(password)
        assert not is_valid
        assert any("12 characters" in e for e in errors)
    
    def test_password_strength_no_uppercase(self):
        """Test password without uppercase fails."""
        password = "nouppercase123!"
        is_valid, errors = RegistrationService.validate_password_strength(password)
        assert not is_valid
    
    def test_password_hash_and_verify(self):
        """Test password hashing and verification."""
        password = "TestPassword123!"
        
        hashed = RegistrationService.hash_password(password)
        
        assert RegistrationService.verify_password(hashed, password)
        assert not RegistrationService.verify_password(hashed, "wrong")
    
    def test_backup_codes_generation(self):
        """Test backup code generation."""
        codes = RegistrationService.generate_backup_codes(10)
        
        assert len(codes) == 10
        assert all('-' in code for code in codes)
    
    def test_backup_code_verification(self):
        """Test backup code hashing and verification."""
        code = "ABCD-1234-EFGH"
        hashed = RegistrationService.hash_backup_code(code)
        
        assert RegistrationService.verify_backup_code(hashed, code)
        assert RegistrationService.verify_backup_code(hashed, "abcd-1234-efgh")  # Case insensitive


class TestLoginService:
    """Tests for login service."""
    
    def test_rate_limiting(self):
        """Test rate limiting after failed attempts."""
        service = LoginService()
        service.MAX_ATTEMPTS = 3
        
        # First attempts should be allowed
        for _ in range(3):
            allowed, _ = service.check_rate_limit("testuser")
            assert allowed
            service.record_failed_attempt("testuser")
        
        # Next attempt should be blocked
        allowed, wait_time = service.check_rate_limit("testuser")
        assert not allowed
        assert wait_time > 0
    
    def test_successful_login_resets_limit(self):
        """Test successful login resets rate limit."""
        service = LoginService()
        
        service.record_failed_attempt("testuser")
        service.record_failed_attempt("testuser")
        service.record_successful_login("testuser")
        
        allowed, _ = service.check_rate_limit("testuser")
        assert allowed
    
    def test_session_generation(self):
        """Test session token generation."""
        service = LoginService()
        
        session = service.generate_session_token("testuser")
        
        assert session.token
        assert session.user_id == "testuser"
        assert session.expires_at > time.time()
    
    def test_session_validation(self):
        """Test session validation."""
        service = LoginService()
        
        session = service.generate_session_token("testuser")
        
        validated = service.validate_session(session.token)
        assert validated is not None
        assert validated.user_id == "testuser"
    
    def test_session_invalidation(self):
        """Test session invalidation (logout)."""
        service = LoginService()
        
        session = service.generate_session_token("testuser")
        service.invalidate_session(session.token)
        
        assert service.validate_session(session.token) is None


class TestTOTPService:
    """Tests for TOTP service."""
    
    def test_secret_generation(self):
        """Test TOTP secret generation."""
        secret = TOTPService.generate_secret()
        
        assert len(secret) == 32  # Base32 encoded
        assert secret.isalnum()
    
    def test_code_generation(self):
        """Test TOTP code generation."""
        secret = TOTPService.generate_secret()
        code = TOTPService.generate_code(secret)
        
        assert len(code) == 6
        assert code.isdigit()
    
    def test_code_verification(self):
        """Test TOTP code verification."""
        secret = TOTPService.generate_secret()
        code = TOTPService.generate_code(secret)
        
        assert TOTPService.verify_code(secret, code)
    
    def test_invalid_code_rejection(self):
        """Test invalid TOTP codes are rejected."""
        secret = TOTPService.generate_secret()
        
        assert not TOTPService.verify_code(secret, "000000")
        assert not TOTPService.verify_code(secret, "invalid")
        assert not TOTPService.verify_code(secret, "")
    
    def test_provisioning_uri(self):
        """Test provisioning URI generation."""
        secret = TOTPService.generate_secret()
        uri = TOTPService.get_provisioning_uri(secret, "testuser")
        
        assert uri.startswith("otpauth://totp/")
        assert "testuser" in uri
        assert "CryptoVault" in uri


if __name__ == "__main__":
    pytest.main([__file__, "-v"])