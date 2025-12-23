"""CryptoVault CLI - Main entry point."""
import os
import sys
import time
import json
import hashlib
import getpass
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from crypto_core import SHA256, MerkleTree, CaesarCipher, VigenereCipher
from auth import RegistrationService, LoginService, TOTPService
from messaging import KeyExchange, MessageEncryption, MessageSignature
from files import FileEncryption, KeyDerivation, IntegrityVerification
from blockchain import Blockchain, Block, MerkleAuditTree
from storage import Database


class CryptoVault:
    """
    CryptoVault Suite - Integrated cryptographic security application.
    
    Modules:
    - Authentication (registration, login, TOTP)
    - Secure Messaging (ECDH, AES-GCM, signatures)
    - File Encryption (AES-GCM, key derivation)
    - Blockchain Audit Ledger (PoW, Merkle trees)
    """
    
    def __init__(self, db_path: str = "cryptovault_data.json"):
        """Initialize CryptoVault with all modules."""
        self.db = Database(db_path)
        self.login_service = LoginService()
        self.current_user = None
        self.current_session = None
        
        # Load or create blockchain
        blockchain_data = self.db.load_blockchain()
        if blockchain_data:
            self.blockchain = Blockchain.from_dict(blockchain_data)
        else:
            self.blockchain = Blockchain(difficulty=4)
            self._save_blockchain()
    
    def _save_blockchain(self) -> None:
        """Save blockchain to database."""
        self.db.save_blockchain(self.blockchain.to_dict())
    
    def _log_event(self, event_type: str, details: dict) -> None:
        """Log event to blockchain."""
        event = {
            'type': event_type,
            'timestamp': int(time.time()),
            'user_hash': hashlib.sha256(
                (self.current_user or 'anonymous').encode()
            ).hexdigest()[:16],
            **details
        }
        self.blockchain.add_transaction(event)
        
        # Mine block if enough transactions
        if len(self.blockchain.pending_transactions) >= 5:
            self.blockchain.mine_pending_transactions()
            self._save_blockchain()
    
    # === Authentication Module ===
    
    def register(self, username: str, password: str) -> dict:
        """
        Register a new user.
        
        Args:
            username: Desired username
            password: User password
            
        Returns:
            Result dictionary with status and TOTP setup info
        """
        # Check if user exists
        if self.db.get_user(username):
            return {'success': False, 'error': 'Username already exists'}
        
        # Validate password
        is_valid, errors = RegistrationService.validate_password_strength(password)
        if not is_valid:
            return {'success': False, 'error': errors}
        
        # Hash password
        password_hash = RegistrationService.hash_password(password)
        
        # Generate TOTP secret
        totp_secret = TOTPService.generate_secret()
        
        # Generate backup codes
        backup_codes = RegistrationService.generate_backup_codes(10)
        hashed_codes = [RegistrationService.hash_backup_code(c) for c in backup_codes]
        
        # Generate user keypair for messaging
        key_exchange = KeyExchange.generate_keypair()
        signature_key = MessageSignature.generate_keypair()
        
        # Store user
        user_data = {
            'username': username,
            'password_hash': password_hash,
            'totp_secret': totp_secret,
            'backup_codes': hashed_codes,
            'public_key': key_exchange.get_public_key_bytes().hex(),
            'private_key': key_exchange.get_private_key_bytes().hex(),
            'signing_public_key': signature_key.get_public_key_bytes().hex(),
            'signing_private_key': signature_key.get_private_key_bytes().hex(),
            'created_at': int(time.time())
        }
        
        self.db.create_user(username, user_data)
        
        # Log event
        self.current_user = username
        self._log_event('AUTH_REGISTER', {'success': True})
        self.current_user = None
        
        # Generate QR code
        qr_ascii = TOTPService.generate_qr_code_ascii(totp_secret, username)
        provisioning_uri = TOTPService.get_provisioning_uri(totp_secret, username)
        
        return {
            'success': True,
            'message': 'Registration successful',
            'totp_secret': totp_secret,
            'qr_code': qr_ascii,
            'provisioning_uri': provisioning_uri,
            'backup_codes': backup_codes
        }
    
    def login(self, username: str, password: str, totp_code: str) -> dict:
        """
        Login with username, password, and TOTP.
        
        Args:
            username: Username
            password: Password
            totp_code: 6-digit TOTP code
            
        Returns:
            Result dictionary with session token
        """
        # Check rate limit
        allowed, wait_time = self.login_service.check_rate_limit(username)
        if not allowed:
            return {
                'success': False,
                'error': f'Account locked. Try again in {wait_time} seconds'
            }
        
        # Get user
        user = self.db.get_user(username)
        if not user:
            self.login_service.record_failed_attempt(username)
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Verify password (constant-time)
        if not RegistrationService.verify_password(user['password_hash'], password):
            self.login_service.record_failed_attempt(username)
            self._log_event('AUTH_LOGIN', {'success': False, 'reason': 'password'})
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Verify TOTP
        if not TOTPService.verify_code(user['totp_secret'], totp_code):
            self.login_service.record_failed_attempt(username)
            self._log_event('AUTH_LOGIN', {'success': False, 'reason': 'totp'})
            return {'success': False, 'error': 'Invalid TOTP code'}
        
        # Generate session
        session = self.login_service.generate_session_token(username)
        self.login_service.record_successful_login(username)
        
        self.current_user = username
        self.current_session = session
        
        # Log success
        self._log_event('AUTH_LOGIN', {'success': True})
        
        return {
            'success': True,
            'message': 'Login successful',
            'session_token': session.token,
            'expires_at': session.expires_at
        }
    
    def logout(self) -> dict:
        """Logout current user."""
        if not self.current_session:
            return {'success': False, 'error': 'Not logged in'}
        
        self.login_service.invalidate_session(self.current_session.token)
        self._log_event('AUTH_LOGOUT', {'success': True})
        
        self.current_user = None
        self.current_session = None
        
        return {'success': True, 'message': 'Logged out'}
    
    def verify_backup_code(self, username: str, code: str) -> bool:
        """Verify and consume a backup code."""
        user = self.db.get_user(username)
        if not user:
            return False
        
        for i, hashed_code in enumerate(user['backup_codes']):
            if RegistrationService.verify_backup_code(hashed_code, code):
                # Remove used code
                user['backup_codes'].pop(i)
                self.db.update_user(username, {'backup_codes': user['backup_codes']})
                return True
        
        return False
    
    # === Messaging Module ===
    
    def send_message(self, recipient: str, message: str) -> dict:
        """
        Send encrypted message to another user.
        
        Args:
            recipient: Recipient username
            message: Message content
            
        Returns:
            Result dictionary
        """
        if not self.current_user:
            return {'success': False, 'error': 'Not logged in'}
        
        # Get recipient's public key
        recipient_data = self.db.get_user(recipient)
        if not recipient_data:
            return {'success': False, 'error': 'Recipient not found'}
        
        # Get sender's keys
        sender_data = self.db.get_user(self.current_user)
        
        # Load keys
        sender_key = KeyExchange.load_private_key(
            bytes.fromhex(sender_data['private_key'])
        )
        recipient_pubkey = bytes.fromhex(recipient_data['public_key'])
        
        # Derive shared key
        shared_key, salt = sender_key.derive_shared_key_with_salt(recipient_pubkey)
        
        # Encrypt message
        encryptor = MessageEncryption(shared_key)
        encrypted = encryptor.encrypt(message)
        
        # Sign message
        signer = MessageSignature.load_private_key(
            bytes.fromhex(sender_data['signing_private_key'])
        )
        signature = signer.sign_hex(message)
        
        # Store message
        msg_id = hashlib.sha256(
            f"{self.current_user}{recipient}{time.time()}".encode()
        ).hexdigest()[:16]
        
        msg_data = {
            'id': msg_id,
            'sender': self.current_user,
            'recipient': recipient,
            'encrypted': encrypted,
            'salt': salt.hex(),
            'signature': signature,
            'sender_pubkey': sender_data['signing_public_key'],
            'timestamp': int(time.time())
        }
        
        self.db.store_message(msg_id, msg_data)
        
        # Log event
        self._log_event('MESSAGE_SEND', {
            'recipient_hash': hashlib.sha256(recipient.encode()).hexdigest()[:16],
            'msg_hash': hashlib.sha256(message.encode()).hexdigest()[:16]
        })
        
        return {
            'success': True,
            'message': 'Message sent',
            'msg_id': msg_id
        }
    
    def receive_messages(self) -> dict:
        """
        Get and decrypt messages for current user.
        
        Returns:
            Dictionary with messages
        """
        if not self.current_user:
            return {'success': False, 'error': 'Not logged in'}
        
        messages = self.db.get_user_messages(self.current_user)
        decrypted_messages = []
        
        user_data = self.db.get_user(self.current_user)
        user_key = KeyExchange.load_private_key(
            bytes.fromhex(user_data['private_key'])
        )
        
        for msg in messages:
            if msg['recipient'] != self.current_user:
                continue  # Skip sent messages
            
            try:
                # Get sender's public key
                sender_data = self.db.get_user(msg['sender'])
                sender_pubkey = bytes.fromhex(sender_data['public_key'])
                
                # Derive shared key
                salt = bytes.fromhex(msg['salt'])
                shared_key = user_key.derive_shared_key(sender_pubkey, salt)
                
                # Decrypt
                decryptor = MessageEncryption(shared_key)
                plaintext = decryptor.decrypt_to_string(msg['encrypted'])
                
                # Verify signature
                sender_signing_key = bytes.fromhex(msg['sender_pubkey'])
                is_valid = MessageSignature.verify(
                    sender_signing_key, plaintext, msg['signature']
                )
                
                decrypted_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'message': plaintext,
                    'timestamp': msg['timestamp'],
                    'signature_valid': is_valid
                })
                
                # Log event
                self._log_event('MESSAGE_RECEIVE', {
                    'msg_id': msg['id'],
                    'verified': is_valid
                })
                
            except Exception as e:
                decrypted_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'error': str(e),
                    'timestamp': msg['timestamp']
                })
        
        return {
            'success': True,
            'messages': decrypted_messages
        }
    
    # === File Encryption Module ===
    
    def encrypt_file(self, input_path: str, output_path: str, 
                     password: str) -> dict:
        """
        Encrypt a file with password.
        
        Args:
            input_path: Source file
            output_path: Destination for encrypted file
            password: Encryption password
            
        Returns:
            Result dictionary
        """
        if not self.current_user:
            return {'success': False, 'error': 'Not logged in'}
        
        if not os.path.exists(input_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            result = FileEncryption.encrypt_file(input_path, output_path, password)
            
            # Log event
            self._log_event('FILE_ENCRYPT', {
                'file_hash': result['original_hash'][:16],
                'encrypted_hash': result['file_hmac'][:16]
            })
            
            return {
                'success': True,
                'message': 'File encrypted successfully',
                'original_hash': result['original_hash'],
                'output_path': result['output_path']
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def decrypt_file(self, input_path: str, output_path: str,
                     password: str) -> dict:
        """
        Decrypt a file with password.
        
        Args:
            input_path: Encrypted file
            output_path: Destination for decrypted file
            password: Decryption password
            
        Returns:
            Result dictionary
        """
        if not self.current_user:
            return {'success': False, 'error': 'Not logged in'}
        
        if not os.path.exists(input_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            result = FileEncryption.decrypt_file(input_path, output_path, password)
            
            # Log event
            self._log_event('FILE_DECRYPT', {
                'file_hash': result['original_hash'][:16],
                'verified': result['verified']
            })
            
            return {
                'success': True,
                'message': 'File decrypted successfully',
                'verified': result['verified'],
                'output_path': result['output_path']
            }
        except ValueError as e:
            return {'success': False, 'error': str(e)}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # === Blockchain Module ===
    
    def get_blockchain_status(self) -> dict:
        """Get blockchain status and statistics."""
        is_valid, error = self.blockchain.is_chain_valid()
        
        return {
            'blocks': len(self.blockchain),
            'difficulty': self.blockchain.difficulty,
            'pending_transactions': len(self.blockchain.pending_transactions),
            'is_valid': is_valid,
            'validation_error': error,
            'last_block_hash': self.blockchain.last_block.hash[:16] + '...'
        }
    
    def mine_block(self) -> dict:
        """Mine pending transactions into a new block."""
        if not self.blockchain.pending_transactions:
            return {'success': False, 'error': 'No pending transactions'}
        
        block = self.blockchain.mine_pending_transactions()
        self._save_blockchain()
        
        return {
            'success': True,
            'message': 'Block mined',
            'block_index': block.index,
            'block_hash': block.hash,
            'transactions': len(block.transactions)
        }
    
    def get_block(self, index: int) -> dict:
        """Get block by index."""
        if index >= len(self.blockchain):
            return {'success': False, 'error': 'Block not found'}
        
        block = self.blockchain.chain[index]
        return {
            'success': True,
            'block': block.to_dict()
        }
    
    def verify_transaction(self, block_index: int, tx_index: int) -> dict:
        """
        Verify a transaction with Merkle proof.
        
        Args:
            block_index: Block containing transaction
            tx_index: Transaction index in block
            
        Returns:
            Verification result
        """
        proof = self.blockchain.get_transaction_proof(block_index, tx_index)
        
        if not proof:
            return {'success': False, 'error': 'Transaction not found'}
        
        is_valid = self.blockchain.verify_transaction_proof(proof)
        
        return {
            'success': True,
            'transaction': proof['transaction'],
            'merkle_proof': proof['merkle_proof'],
            'merkle_root': proof['merkle_root'],
            'verified': is_valid
        }
    
    # === Classical Ciphers Demo ===
    
    @staticmethod
    def caesar_encrypt(plaintext: str, shift: int) -> str:
        """Encrypt with Caesar cipher."""
        return CaesarCipher.encrypt(plaintext, shift)
    
    @staticmethod
    def caesar_decrypt(ciphertext: str, shift: int) -> str:
        """Decrypt Caesar cipher."""
        return CaesarCipher.decrypt(ciphertext, shift)
    
    @staticmethod
    def caesar_break(ciphertext: str) -> list:
        """Break Caesar cipher with frequency analysis."""
        return CaesarCipher.break_cipher(ciphertext)[:3]
    
    @staticmethod
    def vigenere_encrypt(plaintext: str, key: str) -> str:
        """Encrypt with Vigenère cipher."""
        return VigenereCipher.encrypt(plaintext, key)
    
    @staticmethod
    def vigenere_decrypt(ciphertext: str, key: str) -> str:
        """Decrypt Vigenère cipher."""
        return VigenereCipher.decrypt(ciphertext, key)
    
    @staticmethod
    def vigenere_break(ciphertext: str) -> dict:
        """Break Vigenère cipher with Kasiski examination."""
        key_lengths = VigenereCipher.kasiski_examination(ciphertext)
        
        if not key_lengths:
            return {'error': 'Could not determine key length'}
        
        best_length = key_lengths[0]
        key, plaintext = VigenereCipher.break_cipher(ciphertext, best_length)
        
        return {
            'probable_key_lengths': key_lengths,
            'best_key': key,
            'decrypted': plaintext[:200] + '...' if len(plaintext) > 200 else plaintext
        }


def print_menu():
    """Print CLI menu."""
    print("\n" + "=" * 50)
    print("       CryptoVault Security Suite")
    print("=" * 50)
    print("1.  Register")
    print("2.  Login")
    print("3.  Send Message")
    print("4.  Read Messages")
    print("5.  Encrypt File")
    print("6.  Decrypt File")
    print("7.  View Blockchain Status")
    print("8.  Mine Block")
    print("9.  View Block")
    print("10. Verify Transaction (Merkle Proof)")
    print("11. Classical Ciphers Demo")
    print("12. Logout")
    print("0.  Exit")
    print("=" * 50)


def classical_ciphers_menu(vault: CryptoVault):
    """Sub-menu for classical ciphers."""
    while True:
        print("\n--- Classical Ciphers ---")
        print("1. Caesar Encrypt")
        print("2. Caesar Decrypt")
        print("3. Caesar Break (Frequency Analysis)")
        print("4. Vigenère Encrypt")
        print("5. Vigenère Decrypt")
        print("6. Vigenère Break (Kasiski)")
        print("0. Back")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '0':
            break
        elif choice == '1':
            text = input("Plaintext: ")
            shift = int(input("Shift (0-25): "))
            print(f"Ciphertext: {vault.caesar_encrypt(text, shift)}")
        elif choice == '2':
            text = input("Ciphertext: ")
            shift = int(input("Shift: "))
            print(f"Plaintext: {vault.caesar_decrypt(text, shift)}")
        elif choice == '3':
            text = input("Ciphertext: ")
            results = vault.caesar_break(text)
            print("\nTop 3 candidates:")
            for shift, plaintext, score in results:
                print(f"  Shift {shift}: {plaintext[:50]}... (score: {score:.2f})")
        elif choice == '4':
            text = input("Plaintext: ")
            key = input("Key: ")
            print(f"Ciphertext: {vault.vigenere_encrypt(text, key)}")
        elif choice == '5':
            text = input("Ciphertext: ")
            key = input("Key: ")
            print(f"Plaintext: {vault.vigenere_decrypt(text, key)}")
        elif choice == '6':
            text = input("Ciphertext: ")
            result = vault.vigenere_break(text)
            if 'error' in result:
                print(f"Error: {result['error']}")
            else:
                print(f"Probable key lengths: {result['probable_key_lengths']}")
                print(f"Best key: {result['best_key']}")
                print(f"Decrypted: {result['decrypted']}")


def main():
    """Main CLI loop."""
    vault = CryptoVault()
    
    print("\nWelcome to CryptoVault!")
    print("A comprehensive cryptographic security suite.")
    
    while True:
        print_menu()
        
        if vault.current_user:
            print(f"[Logged in as: {vault.current_user}]")
        
        choice = input("\nChoice: ").strip()
        
        try:
            if choice == '0':
                print("Goodbye!")
                # Save blockchain before exit
                vault._save_blockchain()
                break
            
            elif choice == '1':  # Register
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                result = vault.register(username, password)
                
                if result['success']:
                    print("\n✓ Registration successful!")
                    print("\n--- TOTP Setup ---")
                    print("Scan this QR code with your authenticator app:")
                    print(result['qr_code'])
                    print(f"\nOr enter manually: {result['totp_secret']}")
                    print("\n--- Backup Codes (save these!) ---")
                    for code in result['backup_codes']:
                        print(f"  {code}")
                else:
                    print(f"\n✗ Error: {result['error']}")
            
            elif choice == '2':  # Login
                username = input("Username: ").strip()
                password = getpass.getpass("Password: ")
                totp = input("TOTP Code: ").strip()
                
                result = vault.login(username, password, totp)
                
                if result['success']:
                    print(f"\n✓ {result['message']}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '3':  # Send Message
                recipient = input("Recipient username: ").strip()
                message = input("Message: ")
                
                result = vault.send_message(recipient, message)
                
                if result['success']:
                    print(f"\n✓ {result['message']} (ID: {result['msg_id']})")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '4':  # Read Messages
                result = vault.receive_messages()
                
                if result['success']:
                    if not result['messages']:
                        print("\nNo messages.")
                    else:
                        print(f"\n--- {len(result['messages'])} Messages ---")
                        for msg in result['messages']:
                            verified = "✓" if msg.get('signature_valid') else "✗"
                            print(f"\nFrom: {msg['sender']} [{verified}]")
                            print(f"Time: {time.ctime(msg['timestamp'])}")
                            if 'message' in msg:
                                print(f"Message: {msg['message']}")
                            else:
                                print(f"Error: {msg.get('error')}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '5':  # Encrypt File
                input_path = input("Input file path: ").strip()
                output_path = input("Output file path: ").strip()
                password = getpass.getpass("Encryption password: ")
                
                result = vault.encrypt_file(input_path, output_path, password)
                
                if result['success']:
                    print(f"\n✓ {result['message']}")
                    print(f"   Hash: {result['original_hash'][:32]}...")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '6':  # Decrypt File
                input_path = input("Encrypted file path: ").strip()
                output_path = input("Output file path: ").strip()
                password = getpass.getpass("Decryption password: ")
                
                result = vault.decrypt_file(input_path, output_path, password)
                
                if result['success']:
                    print(f"\n✓ {result['message']}")
                    print(f"   Integrity verified: {result['verified']}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '7':  # Blockchain Status
                status = vault.get_blockchain_status()
                print("\n--- Blockchain Status ---")
                print(f"Blocks: {status['blocks']}")
                print(f"Difficulty: {status['difficulty']}")
                print(f"Pending transactions: {status['pending_transactions']}")
                print(f"Chain valid: {status['is_valid']}")
                print(f"Last block: {status['last_block_hash']}")
            
            elif choice == '8':  # Mine Block
                result = vault.mine_block()
                
                if result['success']:
                    print(f"\n✓ {result['message']}")
                    print(f"   Block #{result['block_index']}")
                    print(f"   Hash: {result['block_hash'][:32]}...")
                    print(f"   Transactions: {result['transactions']}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '9':  # View Block
                index = int(input("Block index: "))
                result = vault.get_block(index)
                
                if result['success']:
                    block = result['block']
                    print(f"\n--- Block #{block['index']} ---")
                    print(f"Timestamp: {time.ctime(block['timestamp'])}")
                    print(f"Hash: {block['hash']}")
                    print(f"Previous: {block['previous_hash'][:32]}...")
                    print(f"Merkle root: {block['merkle_root'][:32]}...")
                    print(f"Nonce: {block['nonce']}")
                    print(f"Transactions: {len(block['transactions'])}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '10':  # Verify Transaction
                block_idx = int(input("Block index: "))
                tx_idx = int(input("Transaction index: "))
                
                result = vault.verify_transaction(block_idx, tx_idx)
                
                if result['success']:
                    print(f"\n--- Merkle Verification ---")
                    print(f"Transaction: {json.dumps(result['transaction'], indent=2)}")
                    print(f"Merkle root: {result['merkle_root'][:32]}...")
                    print(f"Verified: {'✓' if result['verified'] else '✗'}")
                else:
                    print(f"\n✗ {result['error']}")
            
            elif choice == '11':  # Classical Ciphers
                classical_ciphers_menu(vault)
            
            elif choice == '12':  # Logout
                result = vault.logout()
                print(f"\n{'✓' if result['success'] else '✗'} {result.get('message', result.get('error'))}")
            
            else:
                print("\nInvalid choice. Please try again.")
        
        except KeyboardInterrupt:
            print("\n\nInterrupted. Saving state...")
            vault._save_blockchain()
            break
        except Exception as e:
            print(f"\n✗ Error: {e}")


if __name__ == "__main__":
    main()