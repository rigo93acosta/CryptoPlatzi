import hashlib
import base64


def hash_file(algorithm: str, encoding: str, input_file: str):
    """Hash a file using specified algorithm"""
    hash_obj = hashlib.new(algorithm)
    
    with open(input_file, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hash_obj.update(chunk)
    
    digest = hash_obj.digest()
    
    if encoding == 'hex':
        return digest.hex()
    elif encoding == 'base64':
        return base64.b64encode(digest).decode()
    elif encoding == 'ascii':
        return digest.decode('ascii', errors='ignore')
    else:
        return digest.decode(encoding, errors='ignore')