from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def decipher(password: str, salt: str, size: int, input_file: str, output_file: str):
    """Decrypt a file using AES-CBC"""
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
    decryptor = cipher_obj.decryptor()
    
    # Read input file and decrypt
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        while True:
            chunk = infile.read(8192)
            if not chunk:
                break
            
            decrypted_chunk = decryptor.update(chunk)
            outfile.write(decrypted_chunk)
        
        # Finalize
        final_chunk = decryptor.finalize()
        outfile.write(final_chunk)