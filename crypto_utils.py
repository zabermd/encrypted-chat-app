from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import os

# Generate RSA key pair
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key to send over socket
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize received public key
def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# Encrypt a message using public key (optional use later)
def encrypt_with_public_key(public_key, message: bytes):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Decrypt message using private key (optional use later)
def decrypt_with_private_key(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
# AES key generation
def generate_aes_key():
    return Fernet.generate_key()  # 32-byte base64-encoded key

# Encrypt AES key using peer's public RSA key
def encrypt_aes_key_with_rsa(peer_public_key, aes_key):
    return peer_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Decrypt AES key using own private RSA key
def decrypt_aes_key_with_rsa(private_key, encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Create Fernet object for message encryption/decryption
def get_fernet(aes_key):
    return Fernet(aes_key)