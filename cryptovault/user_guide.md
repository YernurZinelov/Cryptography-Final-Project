# CryptoVault User Guide

## Getting Started

### Installation

1. Ensure Python 3.10+ is installed
2. Clone the repository
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `python src/main.py`

## Features Guide

### 1. User Registration

**Purpose**: Create a new account with multi-factor authentication

**Steps**:
1. Select option `1` from the menu
2. Enter desired username
3. Enter a strong password:
   - Minimum 12 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one digit
   - At least one special character (!@#$%^&*...)
4. Scan the QR code with your authenticator app
5. **Important**: Save your backup codes securely!

**Example**:
````
Username: alice
Password: SecurePass123!

✓ Registration successful!

[QR CODE DISPLAYED]

Backup Codes:
  A1B2-C3D4-E5F6
  G7H8-I9J0-K1L2
  ...
````

### 2. Login

**Purpose**: Access your account securely

**Steps**:
1. Select option `2`
2. Enter username
3. Enter password
4. Enter 6-digit code from authenticator app

**Note**: Account locks for 5 minutes after 5 failed attempts

### 3. Send Encrypted Message

**Purpose**: Send end-to-end encrypted message to another user

**Steps**:
1. Login first
2. Select option `3`
3. Enter recipient's username
4. Type your message

**Security**:
- Message encrypted with AES-256-GCM
- Key derived via ECDH key exchange
- Digitally signed for non-repudiation

### 4. Read Messages

**Purpose**: View and decrypt received messages

**Steps**:
1. Login first
2. Select option `4`
3. Messages displayed with sender and verification status

**Verification Status**:
- ✓ = Signature verified (authentic)
- ✗ = Signature invalid (potentially tampered)

### 5. Encrypt File

**Purpose**: Securely encrypt any file

**Steps**:
1. Login first
2. Select option `5`
3. Enter input file path
4. Enter output file path
5. Enter encryption password

**Example**:
````
Input: /path/to/secret.pdf
Output: /path/to/secret.pdf.enc
Password: ********

✓ File encrypted successfully
Hash: a1b2c3d4...