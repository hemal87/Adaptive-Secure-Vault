# 🔐 Adaptive Secure Vault

### An Agentic AI-Based Adaptive Data Protection System

Adaptive Secure Vault is a secure file storage and cloud transfer application that combines modern cryptographic techniques with an adaptive security mechanism to protect sensitive files from unauthorized access, tampering, and suspicious activities.

The system uses AES-256-GCM encryption, PBKDF2 key derivation, SHA-256 integrity verification, and a SecurityAgent mechanism to evaluate suspicious access behaviour and trigger adaptive security responses.

---

## 🚀 Key Features

### 1. Advanced File Encryption

* AES-256-GCM authenticated encryption.
* PBKDF2-based password key derivation.
* Random salt and nonce generation.
* Secure encrypted file generation.

### 2. File Integrity Verification

* SHA-256 hash-based integrity checking.
* Detects unauthorized file modifications.
* Verifies encrypted file integrity before decryption.

### 3. Agentic AI-Based Security Mechanism

* SecurityAgent for adaptive risk evaluation.
* Risk score calculation.
* Rapid retry detection.
* Persistent risk state across sessions.
* Adaptive security responses.

### 4. Adaptive Security Responses

Depending on the detected risk level, the system can trigger:

* ALLOW
* FAKE_DATA
* LIMIT_VIEW
* SELF_DESTRUCT

### 5. Access Control

* Configurable maximum access attempts.
* Failed attempt tracking.
* Date-based access restrictions.
* Emergency lockdown mechanism.

### 6. Secure Cloud File Transfer

* Cross-network file transfer.
* Flask-based cloud relay server.
* Render cloud deployment.
* Unique Transfer ID generation.
* Token-based download authentication.
* Time-limited transfers.
* One-time download mechanism.
* Transfers encrypted files along with associated settings metadata.

### 7. Desktop Application

* Interactive Tkinter GUI.
* Sender and receiver functionality.
* Standalone Windows executable using PyInstaller.

---

## 🛠️ Technologies Used

| Technology  | Purpose                            |
| ----------- | ---------------------------------- |
| Python      | Core application development       |
| Tkinter     | Graphical User Interface           |
| AES-256-GCM | File encryption                    |
| PBKDF2      | Password-based key derivation      |
| SHA-256     | Hashing and integrity verification |
| Flask       | Cloud relay backend                |
| Requests    | HTTP communication                 |
| Render      | Cloud server deployment            |
| GitHub      | Source code management             |
| PyInstaller | EXE generation                     |

---

## 🏗️ System Architecture

The project consists of two major components:

### 1. Main Desktop Application

Responsible for:

* File selection.
* Encryption and decryption.
* Password-based access.
* Integrity verification.
* Risk evaluation.
* Uploading and downloading encrypted files.

### 2. Cloud Relay Server

Responsible for:

* Receiving encrypted files.
* Generating Transfer IDs and Download Tokens.
* Authenticating download requests.
* Temporarily storing transfer data.
* Delivering encrypted files to the receiver.

**Cloud Relay Repository:**
`adaptive-secure-vault-relay`

---

## 🔄 Working Process

### Sender Side

1. The user opens the Adaptive Secure Vault application.
2. Selects a file for encryption.
3. Enters the encryption password.
4. PBKDF2 derives the encryption key.
5. AES-256-GCM encrypts the file.
6. The application generates an encrypted `.enc` file and an associated `.asv.json` settings file.
7. The user selects Upload to Cloud.
8. Both files are uploaded to the cloud relay server.
9. The server generates a unique Transfer ID and Download Token.

### Receiver Side

1. The receiver opens the Adaptive Secure Vault executable.
2. Selects Download from Cloud.
3. Enters the Transfer ID and Download Token.
4. The server verifies the download token.
5. The encrypted file and settings file are downloaded together.
6. The receiver selects the encrypted file.
7. Enters the original encryption password.
8. The system verifies integrity and performs AES-GCM decryption.
9. The original file is recovered.

---

## 📂 Project File Structure

```text
Adaptive-Secure-Vault/
│
├── gui.py
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── assets/
│
└── screenshots/
```

*Note: Adjust the file structure according to the actual files in your repository.*

---

## ⚙️ Installation and Setup

### Prerequisites

* Python 3.10 or compatible version.
* Windows operating system.
* Internet connection for cloud transfer.

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### Step 2: Navigate to the Project

```bash
cd Adaptive-Secure-Vault
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run the Application

```bash
python gui.py
```

---

## 📦 Generate Windows Executable

To create a standalone Windows executable, install PyInstaller:

```bash
pip install pyinstaller
```

Run:

```bash
pyinstaller --onefile --windowed --name AdaptiveSecureVault gui.py
```

The executable will be generated inside:

```text
dist/AdaptiveSecureVault.exe
```

The receiver can run the packaged application without separately installing Python or VS Code, provided the executable and its bundled dependencies are compatible with the receiver's system.

---

## 🔐 Security Considerations

* Files are encrypted before cloud upload.
* AES-GCM authentication helps detect unauthorized ciphertext modifications.
* PBKDF2 derives cryptographic keys from user passwords.
* SHA-256 supports file integrity verification.
* Download tokens are stored as hashes on the relay server.
* Transfers have a limited validity period.
* Successful downloads consume the transfer record.

**Important:** The current cloud relay uses temporary storage and in-memory transfer metadata. Pending transfers may be lost if the service restarts. The settings sidecar file is not encrypted in the current implementation. Avoid using the prototype to transfer highly sensitive real-world data.

---

## 🔮 Future Enhancements

* Persistent cloud storage.
* Database-backed transfer management.
* Advanced machine learning-based anomaly detection.
* Multi-factor authentication.
* Android application integration.
* Enhanced protection for security metadata.
* Improved cloud scalability.

---

## 🎯 Project Objective

The primary objective of Adaptive Secure Vault is to develop an integrated data protection solution that combines cryptographic security, adaptive access control, suspicious activity monitoring, and cross-network encrypted file transfer.

---

## 👩‍💻 Project Information

**Project Name:** Adaptive Secure Vault

**Domain:** Cybersecurity / Applied Cryptography / Adaptive Security

**Application Type:** Python Desktop Application

**Cloud Backend:** Flask + Render

**Repository:** Adaptive Secure Vault

---

### ⭐ If you find this project interesting, consider giving the repository a star!
