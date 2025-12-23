# CryptoVault User Guide

## Running the Application

```bash
python src/main.py
```

---

## Main Menu
**1. Register – Create a new user account**

**2. Login – Authenticate with password and TOTP**

**3. Send Message – Send an encrypted message**

**4. Read Messages – Receive and decrypt messages**

**5. Encrypt File – Encrypt a file with a password**

**6. Decrypt File – Decrypt a file**

**7. View Blockchain Status – Check blockchain stats**

**8. Mine Block – Mine pending transactions into a block**

**9. View Block – View block by index**

**10. Verify Transaction (Merkle Proof) – Verify a transaction inclusion**

**11. Classical Ciphers Demo – Caesar and Vigenère demo**

**12. Logout – Logout of the system**

**0. Exit – Exit the application**

---

## Registration

- Enter a unique username
- Enter a strong password (minimum 8 characters, letters + numbers)
- Set up TOTP via QR code in your authenticator app
- Save backup codes for account recovery

---

## Login

- Enter username, password, and TOTP code
- Account temporarily locks on repeated failures

---

## Messaging

- Send: enter recipient username and message content
- Receive: messages are decrypted automatically and signatures verified

---

## File Encryption

- Select the input file and output file path
- Enter a password for encryption
- To decrypt, specify the encrypted file and password

---

## Blockchain

- Status: shows block count, difficulty, pending transactions, validity
- Mining: creates a new block from pending transactions
- Transaction verification: Merkle proof confirms transaction authenticity

---

## Classical Ciphers

- Caesar: encrypt/decrypt and frequency analysis
- Vigenère: encrypt/decrypt and Kasiski examination for key recovery

---
