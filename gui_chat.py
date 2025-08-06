import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import sys

from cryptography.hazmat.primitives import serialization
import base64


from crypto_utils import generate_rsa_keypair, serialize_public_key, deserialize_public_key, generate_aes_key, encrypt_aes_key_with_rsa, get_fernet, decrypt_aes_key_with_rsa, decrypt_with_private_key


PORT = 12345
BUFFER_SIZE = 1024
EXIT_COMMAND = "!exit"

class ChatApp:
    def __init__(self, is_server, peer_ip=None):
        # RSA setup
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_key = None
        self.fernet = None

        self.window = tk.Tk()
        self.window.title("Encrypted Chat App as " + ("Server" if is_server else "Client"))

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




        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if is_server:
            self.socket.bind(('', PORT))
            self.socket.listen(1)
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, "[+] Waiting for a connection...\n")
            self.chat_area.config(state='disabled')
            threading.Thread(target=self.accept_connection, daemon=True).start()
        else:
            self.socket.connect((peer_ip, PORT))
            self.conn = self.socket
            self.chat_area.config(state='normal')
            self.chat_area.insert(tk.END, f"[+] Connected to {peer_ip}:{PORT}\n")
            self.chat_area.config(state='disabled')
            threading.Thread(target=self.receive_messages, daemon=True).start()



        self.window.protocol("WM_DELETE_WINDOW", self.end_chat)

    def accept_connection(self):
        self.conn, addr = self.socket.accept()
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"[+] Connected by {addr}\n")
        self.chat_area.config(state='disabled')
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                msg = self.conn.recv(BUFFER_SIZE)
                if not msg:
                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, "[*] Peer has disconnected.\n")
                    self.chat_area.config(state='disabled')
                    break

                # Handle RSA public key exchange
                if msg.startswith(b"[KEY]"):
                    peer_key_bytes = msg[len(b"[KEY]"):]
                    self.peer_public_key = deserialize_public_key(peer_key_bytes)

                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, "[*] Received peer's public key.\n")

                    # Respond with our key if we haven't sent it yet
                    if self.private_key is None:
                        self.private_key, self.public_key = generate_rsa_keypair()
                        pubkey_bytes = serialize_public_key(self.public_key)
                        self.conn.send(b"[KEY]" + pubkey_bytes)
                        self.chat_area.insert(tk.END, "[*] Sent your public key in response.\n")

                    self.chat_area.config(state='disabled')
                    continue
                # Handle AES key exchange
                if msg.startswith(b"[AES]"):
                    encrypted_key = msg[len(b"[AES]"):]
                    self.shared_key = decrypt_aes_key_with_rsa(self.private_key, encrypted_key)
                    self.fernet = get_fernet(self.shared_key)

                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, "[*] Received and decrypted AES key.\n")
                    self.chat_area.config(state='disabled')
                    continue

                # Handle chat termination
                if self.fernet:
                    decoded_msg = self.fernet.decrypt(msg).decode()
                else:
                    decoded_msg = msg.decode()
                if decoded_msg.strip() == EXIT_COMMAND:
                    self.chat_area.config(state='normal')
                    self.chat_area.insert(tk.END, "\n[*] Peer has ended the chat.\n")
                    self.chat_area.config(state='disabled')
                    break

                # Normal chat message
                self.chat_area.config(state='normal')
                self.chat_area.insert(tk.END, f"Peer: {decoded_msg}\n")
                self.chat_area.yview(tk.END)
                self.chat_area.config(state='disabled')

            except Exception as e:
                print(f"[!] Error receiving message: {e}")
                break

        try:
            self.conn.close()
        except:
            pass



    def send_message(self):
        msg = self.entry.get()
        if msg.strip() == "":
            return

        if self.fernet:
            msg = self.fernet.encrypt(msg.encode())
        else:
            msg = msg.encode()

        self.conn.send(msg)
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"You: {self.entry.get()}\n")
        self.chat_area.yview(tk.END)
        self.chat_area.config(state='disabled')
        self.entry.delete(0, tk.END)

        if self.entry.get().strip() == EXIT_COMMAND:
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
        pubkey_bytes = serialize_public_key(self.public_key)
        # Use prefix to indicate this is a public key
        self.conn.send(b"[KEY]" + pubkey_bytes)
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, "[*] Sent your public key.\n")
        self.chat_area.config(state='disabled')

    def send_aes_key(self):
        if self.peer_public_key is None:
            messagebox.showwarning("Warning", "Public key not received yet!")
            return

        self.shared_key = generate_aes_key()
        encrypted_key = encrypt_aes_key_with_rsa(self.peer_public_key, self.shared_key)
        self.conn.send(b"[AES]" + encrypted_key)

        self.fernet = get_fernet(self.shared_key)
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, "[*] Sent encrypted AES key.\n")
        self.chat_area.config(state='disabled')


    def show_rsa_keys(self):
        window = tk.Toplevel(self.window)
        window.title("RSA Key Information")

        text = tk.Text(window, width=80, height=30, wrap=tk.WORD)
        text.pack(padx=10, pady=10)

        if self.private_key:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        else:
            private_pem = "Not generated yet."

        if self.public_key:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            public_pem = "Not generated yet."

        if self.peer_public_key:
            peer_pem = self.peer_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            peer_pem = "Not received yet."

        key_info = (
            "---- Your Private Key ----\n" + private_pem +
            "\n---- Your Public Key ----\n" + public_pem +
            "\n---- Peer Public Key ----\n" + peer_pem
        )
        text.insert(tk.END, key_info)
        text.config(state='disabled')

    def show_aes_key(self):
        window = tk.Toplevel(self.window)
        window.title("AES Key Information")

        text = tk.Text(window, width=80, height=5, wrap=tk.WORD)
        text.pack(padx=10, pady=10)

        if self.shared_key:
            key_display = self.shared_key.decode()  # Fernet key is base64
        else:
            key_display = "AES key not shared yet."

        text.insert(tk.END, "---- Shared AES-256 Key ----\n" + key_display)
        text.config(state='disabled')


    def run(self):
        self.window.mainloop()

# --------- MAIN LOGIC ---------
if __name__ == "__main__":
    role = simpledialog.askstring("Role", "Enter mode (server/client):")
    if role is None:
        sys.exit(0)
    role = role.strip().lower()
    if role == "server":
        app = ChatApp(is_server=True)
    elif role == "client":
        ip = simpledialog.askstring("Connect To", "Enter server IP:")
        if ip is None:
            sys.exit(0)
        app = ChatApp(is_server=False, peer_ip=ip.strip())
    else:
        messagebox.showerror("Error", "Invalid role entered. Use 'server' or 'client'.")
        sys.exit(1)

    app.run()
