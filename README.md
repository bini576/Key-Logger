<div align="center">

# âŒ¨ï¸ Educational Keylogger with AES-256 Encryption
### Defensive Telemetry Logging, Keystroke Capture Analysis & Symmetric Cryptographic Storage

[![Python 3](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Cryptography: AES-256](https://img.shields.io/badge/Cryptography-AES--256%20CBC-00C7B7?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![Use Case: Educational](https://img.shields.io/badge/Purpose-Defensive%20Research-red?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

</div>

---

> [!CAUTION]
> ### ðŸ›‘ STRICT ETHICS & LEGAL WARNING
> **FOR CONTROLLED LAB TESTING & EDUCATIONAL RESEARCH ONLY.**  
> Keylogging software without the explicit, documented consent of the device owner constitutes a serious criminal offense under cyber crime statutes globally. This software is engineered solely to study input interception mechanisms from an Endpoint Detection and Response (EDR) perspective and to illustrate the cryptographic protection of telemetry logs in transit and at rest.

---

## ðŸ“Œ Project Overview

In cybersecurity, understanding the mechanics of keystroke logging is essential for engineering effective endpoint defenses, behavior-based heuristics, and anti-malware telemetry.

This project implements an **educational input capture utility** written in **Python**. Unlike rudimentary scripts that store plaintext logs vulnerable to exfiltration or inspection, this implementation introduces a secure **AES-256 symmetric cipher pipeline**. All intercepted input events are processed through a cryptographic buffer and serialized to disk in ciphertext format, paired with a companion decryption tool for authorized log analysis.

---

## âœ¨ Features

- **Asynchronous Hook Interception:** Utilizes platform event listeners (`pynput` / `keyboard`) to track and buffer low-level keypress and release events without freezing the main process thread.
- **Strong AES-256 Cryptography:**
  - Encrypts keystroke telemetry utilizing **AES in CBC (Cipher Block Chaining)** or **GCM (Galois/Counter Mode)**.
  - Generates a cryptographically secure random Initialization Vector (IV) for each log segment.
  - Implements PKCS#7 padding standard for variable-length payload block alignment.
- **Tamper-Evident Local Storage:** Captured data cannot be read, modified, or forged in plaintext without the secret key.
- **Dedicated Decryption Utility:** Companion script enabling system administrators or researchers to decrypt and inspect captured telemetry logs for forensic audit.
- **Graceful Termination & Signal Handling:** Captures `SIGINT` / `Ctrl+C` to cleanly flush cryptographic buffers and close file descriptors before process exit.

---

## ðŸ” How the AES Encryption Works

```
[ Keystroke Event Stream ]
           â”‚
           â–¼
 [ In-Memory Text Buffer ]
           â”‚
           â–¼ (Apply PKCS#7 Padding)
  [ 128-bit Block Slices ] â”€â”€â”€â–º [ Secret Key (256-bit) ] + [ Random 16-byte IV ]
                                           â”‚
                                           â–¼
                                [ AES Engine (CBC Mode) ]
                                           â”‚
                                           â–¼
                               [ Encrypted Log (.bin / .enc) ]
```

1. **Key & IV Generation:** A 256-bit secret key is derived using PBKDF2 with SHA-256 or securely generated using `os.urandom(32)`. A 16-byte random IV is generated for each session.
2. **Cipher Block Chaining (CBC):** Each block of plaintext keystrokes is XORed with the previous ciphertext block before encryption, ensuring identical key sequences do not yield identical ciphertext patterns.
3. **Decryption Verification:** The companion `decryptor.py` extracts the IV prefix, initializes the cipher instance with the shared secret key, decrypts the ciphertext stream, and strips the PKCS#7 padding.

---

## ðŸš€ Installation & Lab Setup

### Prerequisites
- Python 3.8+
- Isolated virtual machine / sandbox lab environment (e.g., Kali Linux, Ubuntu VM, or isolated Windows sandbox)

### 1. Clone the Repository
```bash
git clone https://github.com/bini576/Key-Logger.git
cd Key-Logger
```

### 2. Configure Virtual Environment
```bash
python3 -m venv venv

# Activate on Linux / macOS:
source venv/bin/activate

# Activate on Windows:
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `cryptography`, `pynput`)*

---

## ðŸ› ï¸ Usage (Lab Demonstration)

> [!NOTE]
> Execute these commands only on your own local development machine or dedicated sandbox VM.

### Step 1: Start the Encrypted Logger
```bash
python keylogger.py
```
- The logger will run quietly in the background, buffering keystrokes into memory and outputting encrypted ciphertext blocks into `encrypted_log.enc`.
- Press `Ctrl + C` or enter the designated emergency hotkey to stop logging.

### Step 2: Verify Ciphertext File
Inspect the written file to confirm that no plaintext strings exist:
```bash
cat encrypted_log.enc
# or on Windows
type encrypted_log.enc
```
*(You will see only binary or Base64-encoded encrypted cipher blocks)*

### Step 3: Decrypt Logs with the Secret Key
```bash
python decryptor.py --key "<YOUR_SECRET_KEY>" --file encrypted_log.enc
```
The sanitized plaintext log will be reconstituted for forensic review.

---

## ðŸ›¡ï¸ Detection & Defensive Mitigations

How security teams and EDR agents defend against keystroke interception:

1. **Kernel API Monitoring:** Modern EDR solutions monitor calls to Windows `SetWindowsHookEx` or Linux X11/Wayland event taps.
2. **Behavioral Heuristics:** Identifying unauthorized background processes consistently accessing standard input hooks without GUI presence.
3. **Hardware & Secure Enclaves:** Virtual on-screen keyboards with randomized key layouts, smartcard authentication, and FIDO2 passkeys render keystroke sniffing ineffective for authentication.
4. **Principle of Least Privilege:** Restricting standard user permissions prevents installation of persistent hooks and unauthorized driver services.

---

## âš–ï¸ Disclaimer

This software is strictly intended for educational demonstrations of cryptography, input subsystem APIs, and cybersecurity defense. Neither the author nor Bahir Dar University assumes any responsibility for misuse, illegal activity, or damage caused by this software.

---

## ðŸ“„ License & Author

Distributed under the **MIT License**.

- **Author:** [Biniyam Ademasu Afework](https://github.com/bini576)
- **Role:** Cybersecurity Analyst & Security Engineer
- **GitHub:** [@bini576](https://github.com/bini576)
- **LinkedIn:** [linkedin.com/in/biniyam-ademasu](https://linkedin.com/in/biniyam-ademasu)
