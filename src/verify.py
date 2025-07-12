from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64


def verify(algorithm: str, input_file: str, public_key_file: str, 
          signature: str, signature_encoding: str):
    """Verify a signature"""
    # Read public key
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    # Read file to verify
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Decode signature
    if signature_encoding == 'hex':
        sig_bytes = bytes.fromhex(signature)
    elif signature_encoding == 'base64':
        sig_bytes = base64.b64decode(signature)
    else:
        sig_bytes = signature.encode(signature_encoding)
    
    # Verify signature
    try:
        if algorithm == 'RSA-SHA256':
            public_key.verify(
                sig_bytes,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        return True
    except Exception:
        return False