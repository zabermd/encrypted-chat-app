
````markdown
# 🔐 Mutual Authentication Encrypted Chat App (Windows 64-bit)

# Encrypted Chat App (CSE722 Project)

This is a secure peer-to-peer chat application built in Python with GUI, using RSA and AES encryption for message confidentiality, integrity, and authenticity.

## 📌 Overview
This is a **Python-based secure chat application** that supports:
- **Confidentiality** — AES-256 encryption for messages.
- **Integrity** — Message authentication via Fernet’s HMAC.
- **Mutual Authentication** — RSA identity keys + timestamp nonce exchange.
- **Perfect Forward Secrecy** — Ephemeral RSA key exchange for AES key.
- **Wireshark Debug Mode** — Easily capture and filter each phase of communication.

## 🔐 Features

- GUI-based chat using `Tkinter`
- RSA public key exchange
- AES-256 symmetric key exchange (encrypted via RSA)
- Message encryption using Fernet (AES-GCM)
- Key status and live connection info in GUI
- Wireshark verifiable traffic (plaintext and encrypted)

The application is built for **Windows 10/11 (64-bit)** but can also run on Linux/Mac with minor modifications.

---

## ⚙️ Requirements

- **OS:** Windows 10/11 64-bit  
- **Python:** 3.10+  
- **Pip:** Installed with Python  
- **Wireshark:** For traffic simulation & capture

---

## 📥 Installation

1. **Clone the repository**
   ```powershell
   git clone https://github.com/zabermd/encrypted-chat-app.git
   cd encrypted-chat-app
````

2. **Install dependencies**

   ```powershell
   pip install cryptography
   ```

3. **(Optional) Install Wireshark**

   * Download from: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
   * Install and ensure you have permission to capture on your Wi-Fi adapter.

---

## 🚀 Running the Chat App (Windows)

You can run the application in **Server** mode or **Client** mode. Both must be on the same Wi-Fi network.

1. **Find your IP address (Server only)**

   * Open Command Prompt:

     ```powershell
     ipconfig
     ```
   * Look for `IPv4 Address` under your active Wi-Fi/Ethernet adapter.

2. **Run the Server**

   ```powershell
   python gui_chat.py
   ```

   * When prompted, type: `server`.

3. **Run the Client**

   ```powershell
   python gui_chat.py
   ```

   * When prompted, type: `client`.
   * Enter the **Server’s IPv4 address** from Step 1.

4. **Start Chatting**

   * The app will automatically:

     * Exchange **Identity Public Keys** (`[IDPUB]`)
     * Perform **Mutual Authentication** (`[AUTH]`)
     * Exchange **Ephemeral RSA Keys** (`[KEY]`)
     * Exchange **AES Key** (`[AES]`)
     * Send **Encrypted Messages** (`[MSG]`)

5. **End Chat**

   * Click **End Chat** or type `!exit` and press Enter.

---

## 🛡 Security Features

| Feature                     | Implementation                                            |
| --------------------------- | --------------------------------------------------------- |
| **Confidentiality**         | AES-256 symmetric encryption (Fernet)                     |
| **Integrity**               | Fernet HMAC authentication                                |
| **Mutual Authentication**   | RSA identity keys + timestamp nonce verification          |
| **Perfect Forward Secrecy** | Ephemeral RSA key exchange per session                    |
| **Replay Protection**       | Timestamp nonces prevent re-use of authentication packets |

---

## 📡 Capturing in Wireshark (Windows)

1. **Start Wireshark**

   * Select **Wi-Fi** (or Ethernet) interface.
   * Capture filter:

     ```
     tcp port 12345
     ```

2. **Run the Chat App** (as above).

3. **Filter by Phases**

   * Identity Exchange:

     ```
     tcp.port == 12345 && frame contains "[IDPUB]"
     ```
   * Mutual Authentication:

     ```
     tcp.port == 12345 && frame contains "[AUTH]"
     ```
   * Ephemeral RSA Exchange:

     ```
     tcp.port == 12345 && frame contains "[KEY]"
     ```
   * AES Key Exchange:

     ```
     tcp.port == 12345 && frame contains "[AES]"
     ```
   * Encrypted Messages:

     ```
     tcp.port == 12345 && frame contains "[MSG]"
     ```

4. **Stop Capture & Save**

   * Save `.pcapng` files for documentation.

---

## 🖼 Example Packet Flow

```
[IDPUB] → [IDPUB] → [AUTH] → [AUTH] → [KEY] → [KEY] → [AES] → [MSG]...
```

---

## 📂 Project Structure

```
.
├── gui_chat.py          # Main application
├── crypto_utils.py      # Cryptographic helper functions
├── README.md            # Project instructions
└── (screenshots)
```

---

## 🧾 License

This project is for **educational purposes** as part of the CSE722 course.

---

## ✍️ Author

* **Zaber Mohammad**
* **Kabbya Kantam Patwary**

```
