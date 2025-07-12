from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import json


def diffie_hellman(encoding: str, from_params: dict = None):
    """Perform Diffie-Hellman key exchange"""
    if not from_params:
        # Generate new parameters and keys
        parameters = dh.generate_parameters(generator=2, key_size=2048,
                                          backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # Serialize parameters
        param_numbers = parameters.parameter_numbers()
        
        # Serialize public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Serialize private key
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        result = {
            'prime': _encode_output(str(param_numbers.p).encode(), encoding),
            'generator': _encode_output(str(param_numbers.g).encode(), encoding),
            'public_key': _encode_output(public_bytes, encoding),
            'private_key': _encode_output(private_bytes, encoding)
        }
        
        return json.dumps(result, indent=2)
    else:
        # Use provided parameters to compute shared secret
        # This is a simplified implementation
        # In practice, you'd need to properly reconstruct the DH parameters
        result = {
            'prime': from_params['prime'],
            'generator': from_params['generator'],
            'public_key': from_params['public_key'],
            'private_key': from_params['private_key'],
            'shared_secret': 'computed_secret'  # Placeholder
        }
        return json.dumps(result, indent=2)


def _encode_output(data: bytes, encoding: str) -> str:
    """Encode output based on specified encoding"""
    if encoding == 'hex':
        return data.hex()
    elif encoding == 'base64':
        return base64.b64encode(data).decode()
    else:
        return data.decode(encoding, errors='ignore')