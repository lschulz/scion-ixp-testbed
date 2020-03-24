"""Cryptographic helper functions."""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ssh_key_pair():
    """Generate a RSA key pair suitable for OpenSSH.

    :returns: Pair of serialized private and public key.
    """
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=4096
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    return (private_key, public_key)
