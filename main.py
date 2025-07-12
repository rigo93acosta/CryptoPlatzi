import click
import os
from pathlib import Path

from src.cipher import cipher
from src.decipher import decipher
from src.prng import prng
from src.hash import hash_file
from src.hmac import hmac_file
from src.diffie_hellman import diffie_hellman
from src.keypair import keypair
from src.sign import sign
from src.verify import verify
from src.scrypt import scrypt


@click.group()
def cli():
    """Cryptography CLI Tool"""
    pass


@cli.command()
@click.option('--type', 'prng_type', type=click.Choice(['bytes', 'int', 'uuid']), 
              required=True, help='Type of random generation')
@click.option('--size', '-s', default=16, help='Size of randomness')
@click.option('--min', default=0, help='Minimum value for int type')
@click.option('--max', default=100, help='Maximum value for int type')
@click.option('--encoding', '--enc', default='hex', 
              type=click.Choice(['hex', 'base64', 'ascii', 'utf-8']),
              help='Encoding format')
def prng_cmd(prng_type, size, min, max, encoding):
    """Generate random numbers"""
    result = prng(prng_type, size, min, max, encoding)
    click.echo(result)


@cli.command()
@click.option('--password', '-p', required=True, help='Password to encrypt with')
@click.option('--salt', required=True, help='Salt for encryption')
@click.option('--size', default=128, type=click.Choice([128, 192, 256]), 
              help='Key size')
@click.option('--input', '-i', required=True, help='Input file to encrypt')
@click.option('--output', '-o', required=True, help='Output file for encrypted data')
def cipher_cmd(password, salt, size, input, output):
    """Encrypt a file"""
    cipher(password, salt, size, input, output)
    click.echo(f"File encrypted successfully: {output}")


@cli.command()
@click.option('--password', '-p', required=True, help='Password to decrypt with')
@click.option('--salt', required=True, help='Salt for decryption')
@click.option('--size', default=128, type=click.Choice([128, 192, 256]), 
              help='Key size')
@click.option('--input', '-i', required=True, help='Input file to decrypt')
@click.option('--output', '-o', required=True, help='Output file for decrypted data')
def decipher_cmd(password, salt, size, input, output):
    """Decrypt a file"""
    decipher(password, salt, size, input, output)
    click.echo(f"File decrypted successfully: {output}")


@cli.command()
@click.option('--password', '-p', required=True, help='Password to derive key from')
@click.option('--salt', required=True, help='Salt for key derivation')
@click.option('--size', '-s', default=64, help='Number of bytes to output')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64', 'ascii', 'utf-8']),
              help='Encoding format')
def scrypt_cmd(password, salt, size, encoding):
    """Generate a key from password and salt"""
    result = scrypt(password, salt, size, encoding)
    click.echo(result)


@cli.command()
@click.option('--algorithm', '-a', default='sha256', help='Hash algorithm')
@click.option('--input', '-i', required=True, help='File to hash')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64', 'ascii', 'utf-8']),
              help='Encoding format')
def hash_cmd(algorithm, input, encoding):
    """Hash a file"""
    result = hash_file(algorithm, encoding, input)
    click.echo(result)


@cli.command()
@click.option('--algorithm', '-a', default='sha256', help='HMAC algorithm')
@click.option('--key', '-k', required=True, help='HMAC key')
@click.option('--input', '-i', required=True, help='File to HMAC')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64', 'ascii', 'utf-8']),
              help='Encoding format')
def hmac_cmd(algorithm, key, input, encoding):
    """Generate HMAC for a file"""
    result = hmac_file(algorithm, key, encoding, input)
    click.echo(result)


@cli.command(name='diffie-hellman')
@click.option('--public-key', '--pub', help='Other party public key')
@click.option('--public-key-encoding', '--pube', default='hex',
              type=click.Choice(['hex', 'base64']), help='Public key encoding')
@click.option('--private-key', '--priv', help='Own private key')
@click.option('--private-key-encoding', '--prive', default='hex',
              type=click.Choice(['hex', 'base64']), help='Private key encoding')
@click.option('--prime', '-p', help='Prime number')
@click.option('--prime-encoding', '--pe', default='hex',
              type=click.Choice(['hex', 'base64']), help='Prime encoding')
@click.option('--generator', '-g', help='Generator')
@click.option('--generator-encoding', '--ge', default='hex',
              type=click.Choice(['hex', 'base64']), help='Generator encoding')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64']), help='Output encoding')
def diffie_hellman_cmd(public_key, public_key_encoding, private_key, 
                       private_key_encoding, prime, prime_encoding, 
                       generator, generator_encoding, encoding):
    """Compute Diffie-Hellman key exchange"""
    from_params = None
    if public_key:
        from_params = {
            'public_key': public_key,
            'public_key_encoding': public_key_encoding,
            'private_key': private_key,
            'private_key_encoding': private_key_encoding,
            'prime': prime,
            'prime_encoding': prime_encoding,
            'generator': generator,
            'generator_encoding': generator_encoding,
        }
    
    result = diffie_hellman(encoding, from_params)
    click.echo(result)


@cli.command(name='dh')
@click.option('--public-key', '--pub', help='Other party public key')
@click.option('--public-key-encoding', '--pube', default='hex',
              type=click.Choice(['hex', 'base64']), help='Public key encoding')
@click.option('--private-key', '--priv', help='Own private key')
@click.option('--private-key-encoding', '--prive', default='hex',
              type=click.Choice(['hex', 'base64']), help='Private key encoding')
@click.option('--prime', '-p', help='Prime number')
@click.option('--prime-encoding', '--pe', default='hex',
              type=click.Choice(['hex', 'base64']), help='Prime encoding')
@click.option('--generator', '-g', help='Generator')
@click.option('--generator-encoding', '--ge', default='hex',
              type=click.Choice(['hex', 'base64']), help='Generator encoding')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64']), help='Output encoding')
def dh_cmd(public_key, public_key_encoding, private_key, 
           private_key_encoding, prime, prime_encoding, 
           generator, generator_encoding, encoding):
    """Compute Diffie-Hellman key exchange (alias for diffie-hellman)"""
    from_params = None
    if public_key:
        from_params = {
            'public_key': public_key,
            'public_key_encoding': public_key_encoding,
            'private_key': private_key,
            'private_key_encoding': private_key_encoding,
            'prime': prime,
            'prime_encoding': prime_encoding,
            'generator': generator,
            'generator_encoding': generator_encoding,
        }
    
    result = diffie_hellman(encoding, from_params)
    click.echo(result)


@cli.command()
@click.option('--type', type=click.Choice(['rsa', 'rsa-pss']), 
              required=True, help='Key pair type')
@click.option('--size', default=128, type=click.Choice([128, 192, 256]),
              help='Passphrase size')
@click.option('--passphrase', '-p', required=True, help='Private key passphrase')
@click.option('--out-dir', '-o', default='./.secrets', help='Output directory')
@click.option('--out-format', '-f', default='pem', 
              type=click.Choice(['pem', 'der']), help='Output format')
@click.option('--modulus-length', '-m', default=2048,
              type=click.Choice([2048, 3072, 4096]), help='Modulus length')
def keypair_cmd(type, size, passphrase, out_dir, out_format, modulus_length):
    """Generate asymmetric key pair"""
    keypair(type, size, passphrase, out_dir, out_format, modulus_length)
    click.echo(f"Key pair generated in {out_dir}")


@cli.command()
@click.option('--algorithm', '-a', default='RSA-SHA256', help='Signature algorithm')
@click.option('--input', '-i', required=True, help='File to sign')
@click.option('--private-key', '--priv', required=True, help='Private key file')
@click.option('--encoding', '--enc', default='hex',
              type=click.Choice(['hex', 'base64']), help='Encoding format')
@click.option('--passphrase', '-p', help='Private key passphrase')
def sign_cmd(algorithm, input, private_key, encoding, passphrase):
    """Sign a file"""
    result = sign(algorithm, input, private_key, encoding, passphrase)
    click.echo(result)


@cli.command()
@click.option('--algorithm', '-a', default='RSA-SHA256', help='Signature algorithm')
@click.option('--input', '-i', required=True, help='File to verify')
@click.option('--public-key', '--pub', required=True, help='Public key file')
@click.option('--signature', '-s', required=True, help='Signature to verify')
@click.option('--signature-encoding', '--se', default='hex',
              type=click.Choice(['hex', 'base64']), help='Signature encoding')
def verify_cmd(algorithm, input, public_key, signature, signature_encoding):
    """Verify a signature"""
    result = verify(algorithm, input, public_key, signature, signature_encoding)
    click.echo(f"Signature valid: {result}")


if __name__ == '__main__':
    cli()