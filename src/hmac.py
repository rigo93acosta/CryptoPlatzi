import hmac
import hashlib
import base64


def hmac_file(algorithm: str, key: str, encoding: str, input_file: str):
    """Generate HMAC for a file"""
    hmac_obj = hmac.new(key.encode(), digestmod=getattr(hashlib, algorithm))
    
    with open(input_file, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hmac_obj.update(chunk)
    
    digest = hmac_obj.digest()
    
    if encoding == 'hex':
        return digest.hex()
    elif encoding == 'base64':
        return base64.b64encode(digest).decode()
    elif encoding == 'ascii':
        return digest.decode('ascii', errors='ignore')
    else:
        return digest.decode(encoding, errors='ignore')