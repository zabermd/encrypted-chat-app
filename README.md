# Encrypted Chat App (CSE722 Project)

This is a secure peer-to-peer chat application built in Python with GUI, using RSA and AES encryption for message confidentiality, integrity, and authenticity.

## 🔐 Features

- GUI-based chat using `Tkinter`
- RSA public key exchange
- AES-256 symmetric key exchange (encrypted via RSA)
- Message encryption using Fernet (AES-GCM)
- Key status and live connection info in GUI
- Wireshark verifiable traffic (plaintext and encrypted)

## ▶️ How to Run

### 1. Install dependencies

```bash
pip install cryptography
````

### 2. Run the application

```bash
python gui_chat.py
```

### 3. Usage

* Select `server` or `client` mode
* For client: enter the server's IP address
* Exchange public keys → Send AES key → Chat securely
* Use "Show Key Info" and "Show AES Key" to debug
* Use "End Chat" to close the session

## 📸 Packet Capture

We used Wireshark to verify both plaintext and encrypted communication.

* Screenshot 1: Plaintext message captured
* Screenshot 2: Encrypted message captured

## 📁 File Structure

```
.
├── gui_chat.py
├── crypto_utils.py
├── README.md
└── (screenshots, if any)
```

## 🧑‍💻 Author

* Zaber Mohammad
* zabermd5972@gmail.com
* Kabbya Kantam Patwary
* 

````
