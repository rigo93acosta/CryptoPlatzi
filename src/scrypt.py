from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64


def scrypt(password: str, salt: str, size: int, encoding: str):
    """Derive key using scrypt"""
    kdf = Scrypt(
        algorithm=hashes.SHA256(),
        length=size,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    
    key = kdf.derive(password.encode())
    
    if encoding == 'hex':
        return key.hex()
    elif encoding == 'base64':
        return base64.b64encode(key).decode()
    elif encoding == 'ascii':
        return key.decode('ascii', errors='ignore')
    else:
        return key.decode(encoding, errors='ignore')