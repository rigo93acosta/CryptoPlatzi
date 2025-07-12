import os
import uuid
import secrets
from typing import Literal, Union

def prng(type: Literal["bytes", "int", "uuid"], size: int = 16, min: int = 0, max: int = 100, encoding: str = "hex") -> Union[str, int]:
    """
    Pseudo-random number generator supporting bytes, integer, and UUID generation.
    
    Args:
        type: Type of random value to generate ("bytes", "int", or "uuid")
        size: Number of bytes for "bytes" type (default: 16)
        min: Minimum value for "int" type (default: 0)
        max: Maximum value for "int" type (default: 100)
        encoding: Encoding for "bytes" type (default: "hex")
    
    Returns:
        Random bytes as string, random integer, or UUID string based on type
    """
    if type == "bytes":
#        return os.urandom(size).hex() if encoding == "hex" else os.urandom(size).decode(encoding)
        return secrets.token_hex(size) if encoding == "hex" else secrets.token_bytes(size).decode(encoding)
    elif type == "int":
#        from random import randint
 #       return randint(min, max)
        return min + secrets.randbelow(max - min + 1)
    elif type == "uuid":
        return str(uuid.uuid4())
    else:
        raise ValueError("Invalid type. Use 'bytes', 'int', or 'uuid'.")
