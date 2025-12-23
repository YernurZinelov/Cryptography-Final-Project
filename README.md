# CryptoVault Security Suite

**CryptoVault** is a comprehensive cryptographic application designed for secure handling of data, messages, and files. The project demonstrates core cryptographic concepts including:

- Symmetric and asymmetric encryption
- Hashing and integrity verification
- Digital signatures and PKI
- Multi-factor authentication (MFA)
- Blockchain-based auditing of user actions

---

## Key Features

1. **Authentication**
   - Secure password hashing (Argon2id)
   - TOTP and backup codes support
   - Constant-time password comparison and brute-force protection

2. **Secure Messaging**
   - End-to-end encryption (ECDH + AES-GCM)
   - Digital signatures (Ed25519/ECDSA)
   - Sender authenticity and non-repudiation

3. **File Encryption**
   - AES-GCM encryption with key derivation
   - Unique file encryption keys (FEK) per file
   - File integrity verification via SHA-256 and HMAC

4. **Blockchain Audit Ledger**
   - All events are logged on blockchain
   - Merkle trees for transaction verification
   - Proof of Work with configurable difficulty

5. **Classical Ciphers (Demo)**
   - Caesar cipher (with frequency analysis)
   - Vigenère cipher (with Kasiski examination)

---

## Installation

```bash
git clone <repo-url>
cd cryptovault
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

---

## Running the Application

```bash
python src/main.py
```
Follow the CLI instructions to register, log in, send messages, encrypt files, and work with the blockchain.

---

## Requirements

- Python 3.10+
- Libraries: cryptography, pyotp, argon2-cffi, qrcode, etc.

---

## Project Structure
```bash
cryptovault/
├── README.md
├── requirements.txt
├── setup.py
├── architecture.md
├── security_analysis.md
├── user_guide.md
│
├── src/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point
│   │
│   ├── crypto_core/               # From-scratch implementations
│   │   ├── __init__.py
│   │   ├── sha256.py              # SHA-256 from scratch
│   │   ├── merkle_tree.py         # Merkle tree from scratch
│   │   ├── classical_ciphers.py   # Caesar + Vigenère from scratch
│   │   └── utils.py               # Shared crypto utilities
│   │
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── registration.py        # User registration + password hashing
│   │   ├── login.py               # Login + session management
│   │   └── totp.py                # TOTP 2FA implementation
│   │
│   ├── messaging/
│   │   ├── __init__.py
│   │   ├── key_exchange.py        # ECDH key exchange
│   │   ├── encryption.py          # AES-256-GCM message encryption
│   │   └── signatures.py          # ECDSA digital signatures
│   │
│   ├── files/
│   │   ├── __init__.py
│   │   ├── encryption.py          # File encryption with AES-256-GCM
│   │   ├── key_derivation.py      # PBKDF2/Argon2 key derivation
│   │   └── integrity.py           # SHA-256 + HMAC verification
│   │
│   ├── blockchain/
│   │   ├── __init__.py
│   │   ├── block.py               # Block structure + PoW
│   │   ├── chain.py               # Blockchain management
│   │   └── merkle.py              # Merkle tree integration
│   │
│   └── storage/
│       ├── __init__.py
│       └── database.py            # JSON file-based storage
│
└── tests/
    ├── __init__.py
    ├── test_crypto_core.py
    ├── test_auth.py
    ├── test_messaging.py
    ├── test_files.py
    └── test_blockchain.py
```
---
