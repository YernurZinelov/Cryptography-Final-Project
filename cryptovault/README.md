# 🔐 CryptoVault Security Suite

CryptoVault is a comprehensive cryptographic security application designed for the secure handling of **user authentication, messages, files, and audit logs**.  
The project demonstrates both **theoretical understanding** and **practical application** of modern cryptographic concepts as required for an academic cryptography course.

---

## 📌 Project Overview

CryptoVault integrates multiple cryptographic mechanisms into a single system, including:

- Symmetric and asymmetric encryption
- Hashing and data integrity verification
- Digital signatures and Public Key Infrastructure (PKI)
- Multi-factor authentication (MFA)
- Blockchain-based audit logging
- Classical cryptography (educational demonstrations)

The application is implemented in **Python** and exposes a **command-line interface (CLI)** for interaction.

---

## ✨ Key Features

### 🔑 Authentication
- Secure password hashing using **Argon2id**
- Multi-factor authentication using **TOTP**
- Backup codes for account recovery
- Constant-time password comparison
- Basic brute-force protection

---

### 💬 Secure Messaging
- End-to-end encrypted messaging using **ECDH + AES-256-GCM**
- Digital signatures using **ECDSA / Ed25519**
- Sender authentication and non-repudiation
- Unique encryption keys per session

---

### 📁 File Encryption
- File encryption using **AES-256-GCM**
- Secure key derivation via **PBKDF2 / Argon2**
- Unique File Encryption Key (FEK) per file
- File integrity verification using **SHA-256 and HMAC**

---

### ⛓ Blockchain Audit Ledger
- Immutable logging of security-sensitive events
- Blockchain with:
  - Proof of Work (configurable difficulty)
  - Merkle trees for transaction verification
  - Chain integrity validation
- Audit logs for:
  - Authentication events
  - File operations
  - Messaging actions

---

### 🏛 Classical Ciphers (Educational Demonstrations)
- **Caesar cipher**
  - Includes frequency analysis attack
- **Vigenère cipher**
  - Includes Kasiski examination

These ciphers are implemented **from scratch** for learning purposes only.

---

## ⚙️ Installation

Clone the repository and set up a virtual environment:

```bash
git clone <repo-url>
cd cryptovault

python -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

pip install -r requirements.txt
