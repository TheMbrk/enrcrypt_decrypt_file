from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Constants
BACKEND = default_backend()
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000
BLOCK_SIZE = 128

def generate_key(password: str, salt: bytes) -> bytes:
    """Derives a symmetric key from the given password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    """Encrypts the file at the given path with the given password."""
    # Generate a random salt and derive a key from the password
    salt = os.urandom(SALT_SIZE)
    key = generate_key(password, salt)
    
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create a cipher object with AES algorithm
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()

    # Read the file data
    with open(file_path, 'rb') as f:
        data = f.read()

    # Pad data to be a multiple of the block size
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the salt, iv, and encrypted data to a new file
    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_file(file_path: str, password: str):
    """Decrypts the file at the given path with the given password."""
    with open(file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        iv = f.read(16)
        encrypted_data = f.read()

    # Derive the key using the password and the salt
    key = generate_key(password, salt)

    # Create a cipher object with AES algorithm
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    # Write the decrypted data to a new file
    with open(file_path[:-4], 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file.")
    parser.add_argument('file', help="The file to encrypt or decrypt.")
    parser.add_argument('password', help="The password for encryption/decryption.")
    parser.add_argument('--decrypt', action='store_true', help="Decrypt the file instead of encrypting it.")

    args = parser.parse_args()

    if args.decrypt:
        decrypt_file(args.file, args.password)
    else:
        encrypt_file(args.file, args.password)