import hashlib
import base64


def get_supported_algorithms():
    """Get list of supported hash algorithms"""
    return list(hashlib.algorithms_available)


def validate_algorithm(algorithm: str):
    """Validate if algorithm is supported by hashlib"""
    if algorithm not in hashlib.algorithms_available:
        supported = ', '.join(sorted(hashlib.algorithms_available))
        raise ValueError(f"Algorithm '{algorithm}' is not supported. "
                        f"Supported algorithms: {supported}")


def hash_file(algorithm: str, encoding: str, input_file: str):
    """Hash a file using specified algorithm"""
    # Validate algorithm before proceeding
    validate_algorithm(algorithm)
    
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


def get_common_algorithms():
    """Get dictionary of common hash algorithms with descriptions"""
    common_algos = {
        'md5': 'MD5 (128-bit) - Fast but cryptographically broken',
        'sha1': 'SHA-1 (160-bit) - Deprecated, use SHA-2 instead',
        'sha224': 'SHA-224 (224-bit) - Part of SHA-2 family',
        'sha256': 'SHA-256 (256-bit) - Most commonly used, good security',
        'sha384': 'SHA-384 (384-bit) - Part of SHA-2 family',
        'sha512': 'SHA-512 (512-bit) - Very secure, slower than SHA-256',
        'sha3_256': 'SHA3-256 (256-bit) - Latest standard, very secure',
        'sha3_512': 'SHA3-512 (512-bit) - Latest standard, maximum security',
        'blake2b': 'BLAKE2b - Fast and secure, good alternative to SHA-2',
        'blake2s': 'BLAKE2s - Optimized for 8-32 bit platforms'
    }
    
    # Filter to only include algorithms that are actually available
    available_common = {}
    for algo, desc in common_algos.items():
        if algo in hashlib.algorithms_available:
            available_common[algo] = desc
    
    return available_common