from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def decipher(password: str, salt: str, size: int, input_file: str, output_file: str):
    """Decrypt a file using AES-CBC"""
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
    decryptor = cipher_obj.decryptor()
    
    # Read input file and decrypt
    with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
        # Read and decrypt entire file
        encrypted_data = infile.read()
        
        # Decrypt data in chunks
        decrypted_data = b''
        for i in range(0, len(encrypted_data), 8192):
            chunk = encrypted_data[i:i+8192]
            decrypted_data += decryptor.update(chunk)
        
        # Finalize
        decrypted_data += decryptor.finalize()
        
        # Remove PKCS7 padding
        if decrypted_data:
            padding_length = decrypted_data[-1]
            if padding_length <= 16:
                # Verify padding is valid
                padding = decrypted_data[-padding_length:]
                if all(b == padding_length for b in padding):
                    decrypted_data = decrypted_data[:-padding_length]
        
        outfile.write(decrypted_data)