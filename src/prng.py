import os
import secrets
import uuid
import base64


def prng(prng_type: str, size: int, min_val: int, max_val: int, encoding: str):
    """Generate pseudo-random numbers"""
    if prng_type == 'bytes':
        random_bytes = secrets.token_bytes(size)
        if encoding == 'hex':
            return random_bytes.hex()
        elif encoding == 'base64':
            return base64.b64encode(random_bytes).decode()
        elif encoding == 'ascii':
            return random_bytes.decode('ascii', errors='ignore')
        else:
            return random_bytes.decode(encoding, errors='ignore')
    
    elif prng_type == 'int':
        return secrets.randbelow(max_val - min_val) + min_val
    
    elif prng_type == 'uuid':
        return str(uuid.uuid4())