from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits

def generate_iv():
    """Generate a random IV"""
    return os.urandom(AES_BLOCK_SIZE)

def pkcs7_pad(data):
    """Apply PKCS#7 padding to the data"""
    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def pkcs7_unpad(padded_data):
    """Remove PKCS#7 padding from the data"""
    unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def encrypt_bytes(plaintext, key):
    """
    AES-256-CBC Encryption
    Args:
        plaintext (bytes): Data to encrypt
        key (bytes): 32-byte encryption key
    Returns:
        bytes: IV + ciphertext
    """
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes")
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes long")

    # Generate IV
    iv = generate_iv()
    
    # Pad the plaintext
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

def decrypt_bytes(ciphertext_with_iv, key):
    if len(ciphertext_with_iv) < AES_BLOCK_SIZE:
        raise ValueError("Ciphertext too short")
    iv = ciphertext_with_iv[:AES_BLOCK_SIZE]
    ciphertext = ciphertext_with_iv[AES_BLOCK_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Initialize the decryptor
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext using PKCS#7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

# Example usage:
if __name__ == "__main__":
    # Generate a random 256-bit key
    key = os.urandom(AES_KEY_SIZE)
    message = b"Hello, this is a secret message!"
    
    # Encrypt
    encrypted = encrypt_bytes(message, key)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Decrypt
    decrypted = decrypt_bytes(encrypted, key)
    print(f"Decrypted: {decrypted.decode('utf-8')}")