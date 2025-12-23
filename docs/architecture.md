# CryptoVault Architecture

## Overview

CryptoVault is composed of four main modules, all integrated through the central **Core Crypto Library**:
```bash
┌─────────────────────────────────────────┐
│            CryptoVault Suite            │
├─────────────┬─────────────┬─────────────┤
│  Messaging  │  Files      │ Blockchain  │
│  Module     │  Module     │ Module      │
├─────────────┴─────────────┴─────────────┤
│          Authentication Module          │
├─────────────────────────────────────────┤
│           Core Crypto Library           │
│ - AES/ChaCha20, RSA/ECDSA               │
│ - SHA-256, HMAC                         │
│ - Key Derivation, Merkle Trees          │
└─────────────────────────────────────────┘
```

---

## Modules

### 1. Authentication Module
- User registration and login
- Multi-factor authentication (TOTP)
- Secure password hashing and backup codes storage

### 2. Messaging Module
- ECDH key generation for secure exchange
- AES-GCM message encryption
- Digital signatures (Ed25519/ECDSA)
- Ensures sender authenticity and non-repudiation

### 3. File Encryption Module
- Encrypt and decrypt files securely
- Generate unique file encryption keys (FEK)
- Verify file integrity with SHA-256/HMAC

### 4. Blockchain Module
- Logs all user events
- Block structure: prev_hash, merkle_root, timestamp, nonce
- Merkle tree for transaction verification
- Proof of Work for block confirmation

---

## Core Crypto Library
- Symmetric encryption (AES, ChaCha20)
- Asymmetric encryption (RSA, ECDSA)
- Hashing and Merkle tree construction
- Classical ciphers demo (Caesar, Vigenère)
