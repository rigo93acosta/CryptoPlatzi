from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64


def sign(algorithm: str, input_file: str, private_key_file: str, 
         encoding: str, passphrase: str = None):
    """Sign a file"""
    # Read private key
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=passphrase.encode() if passphrase else None,
            backend=default_backend()
        )
    
    # Read file to sign
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Sign the data
    if algorithm == 'RSA-SHA256':
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    # Encode signature
    if encoding == 'hex':
        return signature.hex()
    elif encoding == 'base64':
        return base64.b64encode(signature).decode()
    else:
        return signature.decode(encoding, errors='ignore')