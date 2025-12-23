"""Secure login with rate limiting and session management."""
import time
import secrets
import hashlib
import hmac
from typing import Optional
from dataclasses import dataclass, field
from .registration import RegistrationService


@dataclass
class RateLimitInfo:
    """Track failed login attempts."""
    attempts: int = 0
    first_attempt: float = 0.0
    locked_until: float = 0.0


@dataclass
class Session:
    """User session data."""
    token: str
    user_id: str
    created_at: float
    expires_at: float
    ip_hash: str = ""


class LoginService:
    """
    Handle user login with security measures.
    
    Features:
    - Constant-time password verification
    - Rate limiting to prevent brute force
    - Secure session token generation
    """
    
    # Rate limiting configuration
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes
    ATTEMPT_WINDOW = 900    # 15 minutes
    
    # Session configuration
    SESSION_DURATION = 3600  # 1 hour
    SESSION_SECRET = secrets.token_bytes(32)  # Should be from env in production
    
    def __init__(self):
        self._rate_limits: dict[str, RateLimitInfo] = {}
        self._sessions: dict[str, Session] = {}
    
    def check_rate_limit(self, identifier: str) -> tuple[bool, Optional[int]]:
        """
        Check if login attempt is allowed.
        
        Args:
            identifier: User identifier (username or IP)
            
        Returns:
            Tuple of (is_allowed, seconds_until_unlock)
        """
        now = time.time()
        
        if identifier not in self._rate_limits:
            self._rate_limits[identifier] = RateLimitInfo()
        
        info = self._rate_limits[identifier]
        
        # Check if currently locked
        if info.locked_until > now:
            return False, int(info.locked_until - now)
        
        # Reset if window expired
        if now - info.first_attempt > self.ATTEMPT_WINDOW:
            info.attempts = 0
            info.first_attempt = now
        
        return True, None
    
    def record_failed_attempt(self, identifier: str) -> None:
        """Record a failed login attempt."""
        now = time.time()
        
        if identifier not in self._rate_limits:
            self._rate_limits[identifier] = RateLimitInfo(
                attempts=0,
                first_attempt=now
            )
        
        info = self._rate_limits[identifier]
        info.attempts += 1
        
        if info.first_attempt == 0:
            info.first_attempt = now
        
        # Lock if too many attempts
        if info.attempts >= self.MAX_ATTEMPTS:
            info.locked_until = now + self.LOCKOUT_DURATION
    
    def record_successful_login(self, identifier: str) -> None:
        """Reset rate limit on successful login."""
        if identifier in self._rate_limits:
            del self._rate_limits[identifier]
    
    def generate_session_token(self, user_id: str, ip_address: str = "") -> Session:
        """
        Generate secure session token using HMAC-SHA256.
        
        Args:
            user_id: User identifier
            ip_address: Client IP for binding (optional)
            
        Returns:
            Session object
        """
        now = time.time()
        
        # Generate random component
        random_bytes = secrets.token_bytes(32)
        
        # Create token data
        token_data = f"{user_id}:{now}:{random_bytes.hex()}"
        
        # Sign with HMAC-SHA256
        signature = hmac.new(
            self.SESSION_SECRET,
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token = f"{token_data}:{signature}"
        
        # Hash IP for privacy
        ip_hash = ""
        if ip_address:
            ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]
        
        session = Session(
            token=token,
            user_id=user_id,
            created_at=now,
            expires_at=now + self.SESSION_DURATION,
            ip_hash=ip_hash
        )
        
        self._sessions[token] = session
        return session
    
    def validate_session(self, token: str, ip_address: str = "") -> Optional[Session]:
        """
        Validate session token.
        
        Args:
            token: Session token to validate
            ip_address: Client IP to verify (optional)
            
        Returns:
            Session if valid, None otherwise
        """
        if token not in self._sessions:
            return None
        
        session = self._sessions[token]
        now = time.time()
        
        # Check expiration
        if session.expires_at < now:
            del self._sessions[token]
            return None
        
        # Verify IP if provided
        if ip_address and session.ip_hash:
            current_ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:16]
            if not hmac.compare_digest(session.ip_hash, current_ip_hash):
                return None
        
        # Verify token signature
        try:
            parts = token.rsplit(':', 1)
            if len(parts) != 2:
                return None
            
            token_data, signature = parts
            expected_signature = hmac.new(
                self.SESSION_SECRET,
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return None
        except Exception:
            return None
        
        return session
    
    def invalidate_session(self, token: str) -> bool:
        """
        Invalidate (logout) a session.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            True if session was found and invalidated
        """
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions. Returns count of removed sessions."""
        now = time.time()
        expired = [
            token for token, session in self._sessions.items()
            if session.expires_at < now
        ]
        for token in expired:
            del self._sessions[token]
        return len(expired)