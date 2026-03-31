from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, dh
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_pair():
    """Fulfills: Public/Private key services (RSA)[cite: 15, 32]."""
    # Standard 2048-bit RSA key generation [cite: 15]
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt_text(public_key, text):
    """Fulfills: Encrypt a file/text with two-key public/private[cite: 35]."""
    # Uses OAEP padding with SHA-256 as required [cite: 14, 17]
    return public_key.encrypt(
        text.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_text(private_key, ciphertext):
    """Fulfills: Decrypt (two key, similar to previous)[cite: 35]."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def generate_dh_parameters():
    """Fulfills: Key Generation and sharing (Variation of DH)[cite: 18, 19]."""
    # Generates DH parameters and keys for secure sharing [cite: 19]
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key