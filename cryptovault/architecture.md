## System Overview
````
┌─────────────────────────────────────────────────────────────┐
│                    CryptoVault Suite                         │
├─────────────┬─────────────┬─────────────┬───────────────────┤
│  Messaging  │    Files    │   Ledger    │   Authentication  │
│   Module    │   Module    │   Module    │      Module       │
├─────────────┴─────────────┴─────────────┴───────────────────┤
│                    Core Crypto Library                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │  SHA-256 │ │  Merkle  │ │  Caesar  │ │   Vigenère    │  │
│  │(scratch) │ │  Tree    │ │  Cipher  │ │    Cipher     │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      Storage Layer                           │
│               (JSON File-based Database)                     │
└─────────────────────────────────────────────────────────────┘
````

## Module Interactions

### Authentication Flow
````
User Registration:
  1. Validate password strength
  2. Generate salt (CSPRNG)
  3. Hash password (Argon2id)
  4. Generate TOTP secret
  5. Generate backup codes
  6. Generate ECDH + ECDSA keypairs
  7. Store in database
  8. Log to blockchain

User Login:
  1. Check rate limit
  2. Retrieve user data
  3. Verify password (constant-time)
  4. Verify TOTP code (±1 window)
  5. Generate session token (HMAC-SHA256)
  6. Log to blockchain
````

### Messaging Flow
````
Send Message:
  1. Load sender's private key
  2. Load recipient's public key
  3. ECDH key exchange → shared secret
  4. HKDF → encryption key
  5. AES-256-GCM encryption
  6. ECDSA signature on plaintext
  7. Store encrypted message
  8. Log to blockchain

Receive Message:
  1. Retrieve encrypted messages
  2. ECDH with sender's public key
  3. Derive same encryption key
  4. AES-256-GCM decryption
  5. Verify ECDSA signature
  6. Log to blockchain
````

### File Encryption Flow
````
Encrypt:
  1. Calculate original file hash (SHA-256)
  2. Derive master key from password (Argon2id)
  3. Generate random FEK (File Encryption Key)
  4. Encrypt FEK with master key
  5. Encrypt file chunks (AES-256-GCM)
  6. Write header + encrypted chunks
  7. Calculate HMAC of encrypted file
  8. Log to blockchain

Decrypt:
  1. Read and parse header
  2. Derive master key from password
  3. Decrypt FEK
  4. Decrypt file chunks
  5. Verify integrity (SHA-256)
  6. Log to blockchain
````

### Blockchain Structure
````
Block:
  ┌────────────────────────────────┐
  │ index: 5                       │
  │ timestamp: 1703123456          │
  │ previous_hash: "abc123..."     │
  │ merkle_root: "def456..."       │
  │ nonce: 12847                   │
  │ hash: "0000xyz..."             │
  │ transactions: [                │
  │   { type: "AUTH_LOGIN", ... }, │
  │   { type: "FILE_ENCRYPT", ...} │
  │ ]                              │
  └────────────────────────────────┘
````

## Data Flow
````
┌──────────┐     ┌──────────┐     ┌──────────┐
│   User   │────▶│   CLI    │────▶│  Vault   │
└──────────┘     └──────────┘     └────┬─────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
        ┌──────────┐            ┌──────────┐            ┌──────────┐
        │   Auth   │            │Messaging │            │  Files   │
        │  Module  │            │  Module  │            │  Module  │
        └────┬─────┘            └────┬─────┘            └────┬─────┘
              │                        │                        │
              └────────────────────────┼────────────────────────┘
                                       │
                                       ▼
                              ┌──────────────┐
                              │  Blockchain  │
                              │    Module    │
                              └──────┬───────┘
                                       │
                                       ▼
                              ┌──────────────┐
                              │   Storage    │
                              │   (JSON)     │
                              └──────────────┘
````

## Cryptographic Primitives Used

| Purpose | Algorithm | Implementation |
|---------|-----------|----------------|
| Password Hashing | Argon2id | Library (argon2-cffi) |
| Key Derivation | Argon2id / PBKDF2 | Library |
| Symmetric Encryption | AES-256-GCM | Library (cryptography) |
| Key Exchange | ECDH (P-256) | Library (cryptography) |
| Digital Signatures | ECDSA (P-256) | Library (cryptography) |
| Hashing | SHA-256 | **From Scratch** |
| Merkle Trees | SHA-256 based | **From Scratch** |
| Classical Ciphers | Caesar, Vigenère | **From Scratch** |
| TOTP | HMAC-SHA1 | Library (pyotp) |
````