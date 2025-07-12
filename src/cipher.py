from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


def cipher(password: str, salt: str, size: int, input_file: str, output_file: str):
    """Encrypt a file using AES-CBC"""
    # Derive key using scrypt
    kdf = Scrypt(
        algorithm=hashes.SHA256(),
        length=size // 8,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Use fixed IV for simplicity (in production, use random IV)
    iv = b'\x00' * 16
    
    # Create cipher
    cipher_obj = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher_obj.encryptor()
    
    # Read input file and encrypt
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        while True:
            chunk = infile.read(8192)
            if not chunk:
                break
            
            # Pad the last chunk if necessary
            if len(chunk) % 16 != 0:
                chunk += b'\x00' * (16 - len(chunk) % 16)
            
            encrypted_chunk = encryptor.update(chunk)
            outfile.write(encrypted_chunk)
        
        # Finalize
        final_chunk = encryptor.finalize()
        outfile.write(final_chunk)