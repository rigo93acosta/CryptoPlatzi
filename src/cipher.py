from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os


def cipher(password: str, salt: str, size: int, input_file: str, output_file: str):
    """Encrypt a file using AES-CBC"""
    # Derive key using scrypt
    kdf = Scrypt(
        length=size // 8,
        salt=salt.encode(),
        n=2**14,  # CPU/memory cost parameter (16384)
        r=8,      # block size parameter
        p=1,      # parallelization parameter
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
        # Read entire file to handle padding correctly
        data = infile.read()
        
        # Apply PKCS7 padding
        padding_length = 16 - (len(data) % 16)
        if padding_length == 16:
            padding_length = 0
        
        if padding_length > 0:
            data += bytes([padding_length]) * padding_length
        
        # Encrypt data in chunks
        for i in range(0, len(data), 8192):
            chunk = data[i:i+8192]
            encrypted_chunk = encryptor.update(chunk)
            outfile.write(encrypted_chunk)
        
        # Finalize
        final_chunk = encryptor.finalize()
        outfile.write(final_chunk)