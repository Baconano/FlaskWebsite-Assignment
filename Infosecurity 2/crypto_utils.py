import hashlib
import os
import secrets
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def hash_file_data(file_stream):
    """Fulfills: Hash any type of file using SHA-256[cite: 16, 37]."""
    sha256_hash = hashlib.sha256()
    file_stream.seek(0)
    for byte_block in iter(lambda: file_stream.read(4096), b""):
        sha256_hash.update(byte_block)
    file_stream.seek(0) 
    return sha256_hash.hexdigest()

def key_gen(size_bits):
    """Fulfills: Key generation (supports 192-bit AES)[cite: 13, 18, 32]."""
    return os.urandom(size_bits // 8)

def password_gen(length=63):
    """Fulfills: Password generation up to 63 bytes including special characters[cite: 20, 31]."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def encrypt_data(plaintext, algorithm_name, mode_name, key):
    """Fulfills: AES (two key sizes) and 3-DES with multiple block modes[cite: 12, 13, 14]."""
    # IV must be 16 bytes for AES and 8 bytes for 3-DES 
    iv_size = 16 if algorithm_name == "AES" else 8
    iv = os.urandom(iv_size)

    if algorithm_name == "AES":
        cipher_algorithm = algorithms.AES(key)
    else:
        cipher_algorithm = algorithms.TripleDES(key)

    # Supporting two block modes: CBC and CTR 
    if mode_name == "CBC":
        cipher_mode = modes.CBC(iv)
        padder = padding.PKCS7(cipher_algorithm.block_size).padder()
        plaintext = padder.update(plaintext) + padder.finalize()
    else:
        cipher_mode = modes.CTR(iv)

    cipher = Cipher(cipher_algorithm, cipher_mode)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext
def decrypt_data(ciphertext, algorithm_name, mode_name, key, iv):
    """Fulfills: Decrypt a file (symmetric) [cite: 34]"""
    if algorithm_name == "AES":
        cipher_algorithm = algorithms.AES(key)
    else:
        cipher_algorithm = algorithms.TripleDES(key)
    
    cipher_mode = modes.CBC(iv) if mode_name == "CBC" else modes.CTR(iv)
    cipher = Cipher(cipher_algorithm, cipher_mode)
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    if mode_name == "CBC":
        unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return decrypted_data
def hash_text(text_string):
    """Secure Hashing: SHA-256 for text inputs[cite: 17]."""
    return hashlib.sha256(text_string.encode()).hexdigest()