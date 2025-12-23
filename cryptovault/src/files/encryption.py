"""File encryption using AES-256-GCM with streaming support."""
import os
import json
import struct
from typing import BinaryIO
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_derivation import KeyDerivation
from .integrity import IntegrityVerification


class FileEncryption:
    """
    File encryption with AES-256-GCM.
    
    Features:
    - Streaming encryption for large files
    - Password-based key derivation
    - Integrity verification
    - Encrypted metadata
    
    File format:
    [header_len (4 bytes)] [header_json] [encrypted_chunks...]
    
    Header contains: salt, nonce, original_hash, hmac
    """
    
    KEY_SIZE = 32
    NONCE_SIZE = 12
    CHUNK_SIZE = 64 * 1024  # 64 KB
    
    @classmethod
    def encrypt_file(cls, input_path: str, output_path: str,
                     password: str) -> dict:
        """
        Encrypt a file with password.
        
        Args:
            input_path: Source file path
            output_path: Destination for encrypted file
            password: Encryption password
            
        Returns:
            Metadata dictionary
        """
        # Calculate original file hash
        original_hash = IntegrityVerification.hash_file(input_path)
        
        # Derive key from password
        master_key, salt = KeyDerivation.derive_key(password)
        
        # Generate file encryption key (FEK)
        fek = os.urandom(cls.KEY_SIZE)
        
        # Encrypt FEK with master key
        fek_nonce = os.urandom(cls.NONCE_SIZE)
        fek_cipher = AESGCM(master_key)
        encrypted_fek = fek_cipher.encrypt(fek_nonce, fek, None)
        
        # Nonce for file content
        content_nonce = os.urandom(cls.NONCE_SIZE)
        
        # Prepare header
        header = {
            'version': 1,
            'salt': salt.hex(),
            'fek_nonce': fek_nonce.hex(),
            'encrypted_fek': encrypted_fek.hex(),
            'content_nonce': content_nonce.hex(),
            'original_hash': original_hash,
            'chunk_size': cls.CHUNK_SIZE
        }
        
        header_json = json.dumps(header).encode()
        header_len = struct.pack('>I', len(header_json))
        
        # Encrypt file content
        file_cipher = AESGCM(fek)
        
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write header
            fout.write(header_len)
            fout.write(header_json)
            
            # Encrypt and write chunks
            chunk_index = 0
            while chunk := fin.read(cls.CHUNK_SIZE):
                # Use unique nonce per chunk
                chunk_nonce = cls._derive_chunk_nonce(content_nonce, chunk_index)
                encrypted_chunk = file_cipher.encrypt(chunk_nonce, chunk, None)
                
                # Write chunk length and data
                fout.write(struct.pack('>I', len(encrypted_chunk)))
                fout.write(encrypted_chunk)
                
                chunk_index += 1
        
        # Calculate HMAC of encrypted file
        hmac_key = master_key[:16]  # Use part of master key for HMAC
        file_hmac = IntegrityVerification.hmac_file(output_path, hmac_key)
        
        return {
            'original_hash': original_hash,
            'file_hmac': file_hmac,
            'output_path': output_path
        }
    
    @classmethod
    def decrypt_file(cls, input_path: str, output_path: str,
                     password: str) -> dict:
        """
        Decrypt an encrypted file.
        
        Args:
            input_path: Encrypted file path
            output_path: Destination for decrypted file
            password: Decryption password
            
        Returns:
            Metadata dictionary
            
        Raises:
            ValueError: If decryption or verification fails
        """
        with open(input_path, 'rb') as fin:
            # Read header
            header_len = struct.unpack('>I', fin.read(4))[0]
            header_json = fin.read(header_len)
            header = json.loads(header_json)
            
            # Derive key from password
            salt = bytes.fromhex(header['salt'])
            master_key, _ = KeyDerivation.derive_key(password, salt)
            
            # Decrypt FEK
            fek_nonce = bytes.fromhex(header['fek_nonce'])
            encrypted_fek = bytes.fromhex(header['encrypted_fek'])
            
            try:
                fek_cipher = AESGCM(master_key)
                fek = fek_cipher.decrypt(fek_nonce, encrypted_fek, None)
            except Exception:
                raise ValueError("Decryption failed: wrong password or corrupted file")
            
            # Decrypt file content
            content_nonce = bytes.fromhex(header['content_nonce'])
            file_cipher = AESGCM(fek)
            
            with open(output_path, 'wb') as fout:
                chunk_index = 0
                while True:
                    # Read chunk length
                    chunk_len_bytes = fin.read(4)
                    if not chunk_len_bytes:
                        break
                    
                    chunk_len = struct.unpack('>I', chunk_len_bytes)[0]
                    encrypted_chunk = fin.read(chunk_len)
                    
                    # Decrypt chunk
                    chunk_nonce = cls._derive_chunk_nonce(content_nonce, chunk_index)
                    
                    try:
                        decrypted_chunk = file_cipher.decrypt(
                            chunk_nonce, encrypted_chunk, None
                        )
                        fout.write(decrypted_chunk)
                    except Exception:
                        raise ValueError(f"Chunk {chunk_index} tampered or corrupted")
                    
                    chunk_index += 1
        
        # Verify integrity
        decrypted_hash = IntegrityVerification.hash_file(output_path)
        expected_hash = header['original_hash']
        
        if decrypted_hash != expected_hash:
            os.remove(output_path)  # Remove corrupted output
            raise ValueError("Integrity check failed: file was tampered")
        
        return {
            'original_hash': decrypted_hash,
            'verified': True,
            'output_path': output_path
        }
    
    @classmethod
    def _derive_chunk_nonce(cls, base_nonce: bytes, chunk_index: int) -> bytes:
        """Derive unique nonce for each chunk."""
        # XOR chunk index into nonce
        index_bytes = chunk_index.to_bytes(4, 'big')
        nonce = bytearray(base_nonce)
        for i in range(4):
            nonce[i] ^= index_bytes[i]
        return bytes(nonce)
    
    @classmethod
    def encrypt_bytes(cls, data: bytes, password: str) -> bytes:
        """
        Encrypt bytes data with password.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted bytes with header
        """
        # Calculate hash
        original_hash = IntegrityVerification.hash_bytes(data)
        
        # Derive key
        master_key, salt = KeyDerivation.derive_key(password)
        
        # Generate nonce and encrypt
        nonce = os.urandom(cls.NONCE_SIZE)
        cipher = AESGCM(master_key)
        encrypted = cipher.encrypt(nonce, data, None)
        
        # Pack result
        header = {
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'original_hash': original_hash
        }
        header_json = json.dumps(header).encode()
        header_len = struct.pack('>I', len(header_json))
        
        return header_len + header_json + encrypted
    
    @classmethod
    def decrypt_bytes(cls, encrypted: bytes, password: str) -> bytes:
        """
        Decrypt bytes data with password.
        
        Args:
            encrypted: Encrypted data from encrypt_bytes()
            password: Decryption password
            
        Returns:
            Decrypted bytes
        """
        # Parse header
        header_len = struct.unpack('>I', encrypted[:4])[0]
        header_json = encrypted[4:4+header_len]
        header = json.loads(header_json)
        ciphertext = encrypted[4+header_len:]
        
        # Derive key
        salt = bytes.fromhex(header['salt'])
        master_key, _ = KeyDerivation.derive_key(password, salt)
        
        # Decrypt
        nonce = bytes.fromhex(header['nonce'])
        cipher = AESGCM(master_key)
        
        try:
            decrypted = cipher.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed")
        
        # Verify integrity
        if IntegrityVerification.hash_bytes(decrypted) != header['original_hash']:
            raise ValueError("Integrity check failed")
        
        return decrypted