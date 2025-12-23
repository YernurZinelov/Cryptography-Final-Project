"""
Classical Cipher Implementations from Scratch
Includes Caesar and Vigenère ciphers with cryptanalysis
"""
import string
from collections import Counter


class CaesarCipher:
    """
    Caesar cipher implementation with frequency analysis breaker.
    
    The Caesar cipher shifts each letter by a fixed amount.
    """
    
    # English letter frequency (approximate)
    ENGLISH_FREQ = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
        'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
        'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
        'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
        'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10,
        'z': 0.07
    }
    
    @staticmethod
    def encrypt(plaintext: str, shift: int) -> str:
        """
        Encrypt plaintext using Caesar cipher.
        
        Args:
            plaintext: Text to encrypt
            shift: Number of positions to shift (0-25)
            
        Returns:
            Encrypted ciphertext
        """
        shift = shift % 26
        result = []
        
        for char in plaintext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, shift: int) -> str:
        """
        Decrypt ciphertext using Caesar cipher.
        
        Args:
            ciphertext: Text to decrypt
            shift: Shift value used for encryption
            
        Returns:
            Decrypted plaintext
        """
        return CaesarCipher.encrypt(ciphertext, -shift)
    
    @classmethod
    def frequency_analysis(cls, ciphertext: str) -> dict:
        """
        Perform frequency analysis on ciphertext.
        
        Args:
            ciphertext: Text to analyze
            
        Returns:
            Dictionary of letter frequencies
        """
        letters_only = [c.lower() for c in ciphertext if c.isalpha()]
        total = len(letters_only)
        
        if total == 0:
            return {}
        
        counts = Counter(letters_only)
        return {char: (count / total) * 100 for char, count in counts.items()}
    
    @classmethod
    def break_cipher(cls, ciphertext: str) -> list[tuple[int, str, float]]:
        """
        Break Caesar cipher using frequency analysis.
        
        Args:
            ciphertext: Encrypted text to break
            
        Returns:
            List of (shift, decrypted_text, score) tuples, sorted by score
        """
        results = []
        
        for shift in range(26):
            decrypted = cls.decrypt(ciphertext, shift)
            score = cls._score_text(decrypted)
            results.append((shift, decrypted, score))
        
        # Sort by score (higher is better)
        results.sort(key=lambda x: x[2], reverse=True)
        return results
    
    @classmethod
    def _score_text(cls, text: str) -> float:
        """Score text based on English letter frequency."""
        freq = cls.frequency_analysis(text)
        score = 0.0
        
        for char, expected in cls.ENGLISH_FREQ.items():
            actual = freq.get(char, 0)
            # Lower difference = better score
            score -= abs(expected - actual)
        
        return score


class VigenereCipher:
    """
    Vigenère cipher implementation with Kasiski examination.
    
    The Vigenère cipher uses a keyword to shift each letter.
    """
    
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt plaintext using Vigenère cipher.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key (letters only)
            
        Returns:
            Encrypted ciphertext
        """
        if not key or not key.isalpha():
            raise ValueError("Key must contain only letters")
        
        key = key.lower()
        result = []
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('a')
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt ciphertext using Vigenère cipher.
        
        Args:
            ciphertext: Text to decrypt
            key: Decryption key
            
        Returns:
            Decrypted plaintext
        """
        if not key or not key.isalpha():
            raise ValueError("Key must contain only letters")
        
        key = key.lower()
        result = []
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('a')
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base - shift) % 26
                result.append(chr(base + shifted))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @classmethod
    def kasiski_examination(cls, ciphertext: str, min_length: int = 3) -> list[int]:
        """
        Perform Kasiski examination to find probable key lengths.
        
        Args:
            ciphertext: Text to analyze
            min_length: Minimum repeated sequence length to consider
            
        Returns:
            List of probable key lengths, sorted by likelihood
        """
        # Extract only letters
        letters = ''.join(c.lower() for c in ciphertext if c.isalpha())
        
        if len(letters) < min_length * 2:
            return []
        
        # Find repeated sequences and their positions
        sequences = {}
        for length in range(min_length, min(10, len(letters) // 2)):
            for i in range(len(letters) - length):
                seq = letters[i:i + length]
                if seq not in sequences:
                    sequences[seq] = []
                sequences[seq].append(i)
        
        # Calculate distances between repeated sequences
        distances = []
        for seq, positions in sequences.items():
            if len(positions) > 1:
                for i in range(len(positions) - 1):
                    for j in range(i + 1, len(positions)):
                        distances.append(positions[j] - positions[i])
        
        if not distances:
            return []
        
        # Find GCD factors
        factors = Counter()
        for d in distances:
            for i in range(2, min(d + 1, 20)):
                if d % i == 0:
                    factors[i] += 1
        
        # Return most common factors as probable key lengths
        return [f for f, _ in factors.most_common(5)]
    
    @classmethod
    def break_cipher(cls, ciphertext: str, key_length: int) -> tuple[str, str]:
        """
        Break Vigenère cipher with known key length.
        
        Args:
            ciphertext: Text to break
            key_length: Known or guessed key length
            
        Returns:
            Tuple of (key, decrypted_text)
        """
        letters = ''.join(c.lower() for c in ciphertext if c.isalpha())
        
        # Split into columns based on key length
        columns = ['' for _ in range(key_length)]
        for i, char in enumerate(letters):
            columns[i % key_length] += char
        
        # Break each column as Caesar cipher
        key = ''
        for column in columns:
            results = CaesarCipher.break_cipher(column)
            if results:
                best_shift = results[0][0]
                key += chr(ord('a') + best_shift)
        
        decrypted = cls.decrypt(ciphertext, key)
        return key, decrypted