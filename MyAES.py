import secrets
from hashlib import blake2b

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def jiami(password: bytes, data: bytes):
    try:
        pd = blake2b(password, digest_size=32, usedforsecurity=True).digest()
        rand = secrets.token_bytes(8)
        return rand + AESGCM(pd).encrypt(rand, data, None)
    except:
        return False


def jiemi(password: bytes, data: bytes):
    try:
        pd = blake2b(password, digest_size=32, usedforsecurity=True).digest()
        return AESGCM(pd).decrypt(data[:8], data[8:], None)
    except:
        return False
