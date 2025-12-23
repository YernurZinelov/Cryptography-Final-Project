"""
SHA-256 Implementation from Scratch
Following FIPS 180-4 specification
"""
import struct


class SHA256:
    """SHA-256 hash function implemented from scratch."""
    
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    @staticmethod
    def _rotr(x: int, n: int) -> int:
        """Right rotate a 32-bit integer."""
        return ((x >> n) | (x << (32 - n))) & 0xffffffff

    @staticmethod
    def _shr(x: int, n: int) -> int:
        """Right shift a 32-bit integer."""
        return x >> n

    @classmethod
    def _ch(cls, x: int, y: int, z: int) -> int:
        """Choice function."""
        return (x & y) ^ (~x & z)

    @classmethod
    def _maj(cls, x: int, y: int, z: int) -> int:
        """Majority function."""
        return (x & y) ^ (x & z) ^ (y & z)

    @classmethod
    def _sigma0(cls, x: int) -> int:
        """Σ0 function."""
        return cls._rotr(x, 2) ^ cls._rotr(x, 13) ^ cls._rotr(x, 22)

    @classmethod
    def _sigma1(cls, x: int) -> int:
        """Σ1 function."""
        return cls._rotr(x, 6) ^ cls._rotr(x, 11) ^ cls._rotr(x, 25)

    @classmethod
    def _gamma0(cls, x: int) -> int:
        """σ0 function."""
        return cls._rotr(x, 7) ^ cls._rotr(x, 18) ^ cls._shr(x, 3)

    @classmethod
    def _gamma1(cls, x: int) -> int:
        """σ1 function."""
        return cls._rotr(x, 17) ^ cls._rotr(x, 19) ^ cls._shr(x, 10)

    @classmethod
    def _pad_message(cls, message: bytes) -> bytes:
        """
        Pad message according to SHA-256 specification.
        
        Args:
            message: Input message bytes
            
        Returns:
            Padded message as bytes
        """
        msg_len = len(message)
        # Append bit '1' to message (0x80 = 10000000)
        message += b'\x80'
        
        # Append zeros until message length ≡ 448 (mod 512)
        # In bytes: length ≡ 56 (mod 64)
        while (len(message) % 64) != 56:
            message += b'\x00'
        
        # Append original length in bits as 64-bit big-endian integer
        message += struct.pack('>Q', msg_len * 8)
        
        return message

    @classmethod
    def _process_block(cls, block: bytes, h: list) -> list:
        """
        Process a single 512-bit block.
        
        Args:
            block: 64-byte block to process
            h: Current hash values
            
        Returns:
            Updated hash values
        """
        # Prepare message schedule (64 words)
        w = list(struct.unpack('>16I', block))
        
        for i in range(16, 64):
            w.append(
                (cls._gamma1(w[i-2]) + w[i-7] + cls._gamma0(w[i-15]) + w[i-16]) & 0xffffffff
            )
        
        # Initialize working variables
        a, b, c, d, e, f, g, hh = h
        
        # 64 rounds
        for i in range(64):
            t1 = (hh + cls._sigma1(e) + cls._ch(e, f, g) + cls.K[i] + w[i]) & 0xffffffff
            t2 = (cls._sigma0(a) + cls._maj(a, b, c)) & 0xffffffff
            
            hh = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        
        # Compute intermediate hash value
        return [
            (h[0] + a) & 0xffffffff,
            (h[1] + b) & 0xffffffff,
            (h[2] + c) & 0xffffffff,
            (h[3] + d) & 0xffffffff,
            (h[4] + e) & 0xffffffff,
            (h[5] + f) & 0xffffffff,
            (h[6] + g) & 0xffffffff,
            (h[7] + hh) & 0xffffffff,
        ]

    @classmethod
    def hash(cls, message: bytes | str) -> str:
        """
        Compute SHA-256 hash of message.
        
        Args:
            message: Input message (bytes or string)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Initialize hash values
        h = cls.H.copy()
        
        # Pad message
        padded = cls._pad_message(message)
        
        # Process each 512-bit (64-byte) block
        for i in range(0, len(padded), 64):
            block = padded[i:i+64]
            h = cls._process_block(block, h)
        
        # Produce final hash value
        return ''.join(f'{x:08x}' for x in h)

    @classmethod
    def hash_bytes(cls, message: bytes | str) -> bytes:
        """
        Compute SHA-256 hash and return as bytes.
        
        Args:
            message: Input message (bytes or string)
            
        Returns:
            Hash as bytes
        """
        return bytes.fromhex(cls.hash(message))


def sha256(data: bytes | str) -> str:
    """Convenience function for SHA-256 hashing."""
    return SHA256.hash(data)


def sha256_bytes(data: bytes | str) -> bytes:
    """Convenience function for SHA-256 hashing returning bytes."""
    return SHA256.hash_bytes(data)