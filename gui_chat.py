import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import sys, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    generate_aes_key, encrypt_aes_key_with_rsa, get_fernet, decrypt_aes_key_with_rsa
)

# -------------------
# CONFIG
# -------------------
PORT = 12345
BUFFER_SIZE = 4096
EXIT_COMMAND = "!exit"
DEBUG_MODE = False  # Set to False to disable Wireshark tags & console logs

class ChatApp:
    def __init__(self, is_server, peer_ip=None):
        # Identity keys for mutual authentication
        self.identity_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.identity_public_key = self.identity_private_key.public_key()
        self.peer_identity_public_key = None

        # RSA ephemeral keys for AES exchange
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_key = None
        self.fernet = None

        self.window = tk.Tk()
        self.window.title("Encrypted Chat App as " + ("Server" if is_server else "Client"))

        # Chat UI
        self.chat_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, width=50, height=20, state='disabled')
        self.chat_area.pack(padx=10, pady=5)

        self.entry = tk.Entry(self.window, width=40)
        self.entry.pack(side=tk.LEFT, padx=10, pady=5)
        self.entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = tk.Button(self.window, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.end_button = tk.Button(self.window, text="End Chat", command=self.end_chat)
        self.end_button.pack(side=tk.LEFT, padx=5)

        self.key_button = tk.Button(self.window, text="Send Public Key", command=self.send_public_key)
        self.key_button.pack(side=tk.LEFT, padx=5)

        self.aes_button = tk.Button(self.window, text="Send AES Key", command=self.send_aes_key)
        self.aes_button.pack(side=tk.LEFT, padx=5)

        self.key_info_button = tk.Button(self.window, text="Show Key Info", command=self.show_rsa_keys)
        self.key_info_button.pack(side=tk.LEFT, padx=5)

        self.aes_info_button = tk.Button(self.window, text="Show AES Key", command=self.show_aes_key)
        self.aes_info_button.pack(side=tk.LEFT, padx=5)

        # Socket setup
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if is_server:
            self.socket.bind(('0.0.0.0', PORT))
            self.socket.listen(1)
            self._log("[+] Waiting for a connection...")
            threading.Thread(target=self.accept_connection, daemon=True).start()
        else:
            self.socket.connect((peer_ip, PORT))
            self.conn = self.socket
            self._log(f"[+] Connected to {peer_ip}:{PORT}")
            # Send my identity public key
            self._debug_send("[IDPUB]", serialize_public_key(self.identity_public_key))
            threading.Thread(target=self.receive_messages, daemon=True).start()

        self.window.protocol("WM_DELETE_WINDOW", self.end_chat)

    # Debug send helper
    def _debug_send(self, tag, data):
        if DEBUG_MODE:
            payload = tag.encode() + data
            print(f"[DEBUG] Sending {tag} packet ({len(data)} bytes)")
        else:
            payload = data
        self.conn.send(payload)

    # GUI log helper
    def _log(self, msg):
        if DEBUG_MODE:
            print(f"[DEBUG] {msg}")
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')

    # Server accept
    def accept_connection(self):
        self.conn, addr = self.socket.accept()
        self._log(f"[+] Connected by {addr}")
        # Send my identity public key
        self._debug_send("[IDPUB]", serialize_public_key(self.identity_public_key))
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # Mutual authentication
    def mutual_authenticate(self):
        timestamp = str(int(time.time() * 1000)).encode()
        signature = self.identity_private_key.sign(
            timestamp,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self._debug_send("[AUTH]", timestamp + b"||" + signature)
        self._log("[*] Sent authentication nonce.")

    def verify_authentication(self, timestamp, signature):
        try:
            self.peer_identity_public_key.verify(
                signature,
                timestamp,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            self._log("[✓] Peer authenticated successfully.")
        except Exception:
            self._log("[✗] Peer authentication failed.")
            self.conn.close()

    # Receive
    def receive_messages(self):
        while True:
            try:
                msg = self.conn.recv(BUFFER_SIZE)
                if not msg:
                    self._log("[*] Peer has disconnected.")
                    break

                # Identity public key exchange
                if msg.startswith(b"[IDPUB]"):
                    self.peer_identity_public_key = deserialize_public_key(msg[len(b"[IDPUB]"):])
                    self._log("[*] Received peer identity public key.")
                    self.mutual_authenticate()
                    continue

                # Mutual authentication
                if msg.startswith(b"[AUTH]"):
                    payload = msg[len(b"[AUTH]"):]
                    timestamp, signature = payload.split(b"||", 1)
                    self.verify_authentication(timestamp, signature)
                    continue

                # RSA public key exchange
                if msg.startswith(b"[KEY]"):
                    self.peer_public_key = deserialize_public_key(msg[len(b"[KEY]"):])
                    self._log("[*] Received peer's ephemeral RSA public key.")
                    if self.private_key is None:
                        self.private_key, self.public_key = generate_rsa_keypair()
                        self._debug_send("[KEY]", serialize_public_key(self.public_key))
                        self._log("[*] Sent my ephemeral public key.")
                    continue

                # AES key exchange
                if msg.startswith(b"[AES]"):
                    encrypted_key = msg[len(b"[AES]"):]
                    self.shared_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
                    self.fernet = get_fernet(self.shared_key)
                    self._log("[*] Received and decrypted AES key.")
                    continue

                # Chat messages
                if msg.startswith(b"[MSG]"):
                    msg = msg[len(b"[MSG]"):]
                if self.fernet:
                    try:
                        decoded_msg = self.fernet.decrypt(msg).decode()
                    except Exception:
                        self._log("[!] Integrity check failed for a message.")
                        continue
                else:
                    decoded_msg = msg.decode()

                if decoded_msg.strip() == EXIT_COMMAND:
                    self._log("[*] Peer ended the chat.")
                    break

                self._log(f"Peer: {decoded_msg}")

            except Exception as e:
                print(f"[!] Error receiving message: {e}")
                break
        try:
            self.conn.close()
        except:
            pass

    # Send chat
    def send_message(self):
        msg = self.entry.get()
        if not msg.strip():
            return
        data = self.fernet.encrypt(msg.encode()) if self.fernet else msg.encode()
        self._debug_send("[MSG]", data)
        self._log(f"You: {self.entry.get()}")
        self.entry.delete(0, tk.END)
        if msg.strip() == EXIT_COMMAND:
            self.end_chat()

    def end_chat(self):
        try:
            self.conn.send(EXIT_COMMAND.encode())
            self.conn.close()
        except:
            pass
        self.window.destroy()
        sys.exit(0)

    def send_public_key(self):
        if self.private_key is None:
            self.private_key, self.public_key = generate_rsa_keypair()
        self._debug_send("[KEY]", serialize_public_key(self.public_key))
        self._log("[*] Sent my ephemeral RSA public key.")

    def send_aes_key(self):
        if self.peer_public_key is None:
            messagebox.showwarning("Warning", "Public key not received yet!")
            return
        self.shared_key = generate_aes_key()
        encrypted_key = encrypt_aes_key_with_rsa(self.peer_public_key, self.shared_key)
        self._debug_send("[AES]", encrypted_key)
        self.fernet = get_fernet(self.shared_key)
        self._log("[*] Sent encrypted AES key.")

    # Show RSA keys
    def show_rsa_keys(self):
        window = tk.Toplevel(self.window)
        window.title("RSA Key Information")
        text = tk.Text(window, width=80, height=30, wrap=tk.WORD)
        text.pack(padx=10, pady=10)
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode() if self.private_key else "Not generated yet."
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode() if self.public_key else "Not generated yet."
        peer_pub_pem = self.peer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode() if self.peer_public_key else "Not received yet."
        text.insert(tk.END, f"---- Your Ephemeral Private Key ----\n{priv_pem}\n"
                            f"---- Your Ephemeral Public Key ----\n{pub_pem}\n"
                            f"---- Peer Ephemeral Public Key ----\n{peer_pub_pem}")
        text.config(state='disabled')

    def show_aes_key(self):
        window = tk.Toplevel(self.window)
        window.title("AES Key Information")
        text = tk.Text(window, width=80, height=5, wrap=tk.WORD)
        text.pack(padx=10, pady=10)
        key_display = self.shared_key.decode() if self.shared_key else "AES key not shared yet."
        text.insert(tk.END, f"---- Shared AES-256 Key ----\n{key_display}")
        text.config(state='disabled')

    def run(self):
        self.window.mainloop()

# --------- MAIN ---------
if __name__ == "__main__":
    role = simpledialog.askstring("Role", "Enter mode (server/client):")
    if not role:
        sys.exit(0)
    role = role.strip().lower()
    if role == "server":
        app = ChatApp(is_server=True)
    elif role == "client":
        ip = simpledialog.askstring("Connect To", "Enter server IP:")
        if not ip:
            sys.exit(0)
        app = ChatApp(is_server=False, peer_ip=ip.strip())
    else:
        messagebox.showerror("Error", "Invalid role entered. Use 'server' or 'client'.")
        sys.exit(1)
    app.run()
