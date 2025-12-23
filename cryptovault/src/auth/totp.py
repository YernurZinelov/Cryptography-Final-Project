"""Time-based One-Time Password (TOTP) implementation."""
import io
import base64
import secrets
import time
from typing import Optional
import pyotp
import qrcode
import qrcode.image.svg


class TOTPService:
    """
    TOTP (RFC 6238) implementation for multi-factor authentication.
    
    Features:
    - Secret generation
    - QR code generation for authenticator apps
    - TOTP verification with time window tolerance
    - Backup codes
    """
    
    # Allow ±1 time step for clock drift
    VALID_WINDOW = 1
    
    # TOTP parameters
    INTERVAL = 30  # seconds
    DIGITS = 6
    
    @staticmethod
    def generate_secret() -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32-encoded secret
        """
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp(secret: str) -> pyotp.TOTP:
        """Get TOTP instance for a secret."""
        return pyotp.TOTP(secret)
    
    @classmethod
    def generate_code(cls, secret: str) -> str:
        """
        Generate current TOTP code.
        
        Args:
            secret: Base32-encoded secret
            
        Returns:
            6-digit TOTP code
        """
        totp = cls.get_totp(secret)
        return totp.now()
    
    @classmethod
    def verify_code(cls, secret: str, code: str) -> bool:
        """
        Verify TOTP code with time window tolerance.
        
        Args:
            secret: Base32-encoded secret
            code: Code to verify
            
        Returns:
            True if code is valid
        """
        if not code or not code.isdigit() or len(code) != cls.DIGITS:
            return False
        
        totp = cls.get_totp(secret)
        return totp.verify(code, valid_window=cls.VALID_WINDOW)
    
    @classmethod
    def get_provisioning_uri(cls, secret: str, username: str, 
                             issuer: str = "CryptoVault") -> str:
        """
        Get provisioning URI for QR code.
        
        Args:
            secret: Base32-encoded secret
            username: User identifier
            issuer: Service name
            
        Returns:
            otpauth:// URI
        """
        totp = cls.get_totp(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    @classmethod
    def generate_qr_code(cls, secret: str, username: str,
                         issuer: str = "CryptoVault") -> str:
        """
        Generate QR code as base64-encoded PNG.
        
        Args:
            secret: Base32-encoded secret
            username: User identifier
            issuer: Service name
            
        Returns:
            Base64-encoded PNG image
        """
        uri = cls.get_provisioning_uri(secret, username, issuer)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()
    
    @classmethod
    def generate_qr_code_ascii(cls, secret: str, username: str,
                               issuer: str = "CryptoVault") -> str:
        """
        Generate QR code as ASCII art for terminal display.
        
        Args:
            secret: Base32-encoded secret
            username: User identifier
            issuer: Service name
            
        Returns:
            ASCII representation of QR code
        """
        uri = cls.get_provisioning_uri(secret, username, issuer)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Generate ASCII representation
        lines = []
        for row in qr.modules:
            line = ""
            for cell in row:
                line += "██" if cell else "  "
            lines.append(line)
        
        return "\n".join(lines)
    
    @classmethod
    def get_remaining_seconds(cls) -> int:
        """Get seconds remaining until current code expires."""
        return cls.INTERVAL - (int(time.time()) % cls.INTERVAL)