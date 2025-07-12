from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
from pathlib import Path


def keypair(key_type: str, size: int, passphrase: str, out_dir: str, 
           out_format: str, modulus_length: int):
    """Generate asymmetric key pair"""
    # Generate private key
    if key_type in ['rsa', 'rsa-pss']:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=modulus_length,
            backend=default_backend()
        )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Use passphrase for encryption
    encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    
    # Serialize keys
    if out_format == 'pem':
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:  # DER
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Create output directory
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    
    # Write keys to files
    with open(f"{out_dir}/private.{out_format}", 'wb') as f:
        f.write(private_pem)
    
    with open(f"{out_dir}/public.{out_format}", 'wb') as f:
        f.write(public_pem)