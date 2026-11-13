"""RSA as a KEM protects a fresh secret; AES-GCM protects the whole message."""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# The key encapsulation mechanism (KEM): Alice encapsulates a fresh random
# secret under Bob's public key, and only Bob can decapsulate it.


def encapsulate(public_key):
    # 32 random bytes, so the secret can serve directly as an AES-256 key.
    secret = os.urandom(32)
    return secret, public_key.encrypt(secret, OAEP)


def decapsulate(private_key, encapsulation):
    return private_key.decrypt(encapsulation, OAEP)


# The data encapsulation: the secret encrypts the message with AES-GCM.


def encrypt_message(public_key, message):
    secret, encapsulation = encapsulate(public_key)
    nonce = os.urandom(12)
    ciphertext = AESGCM(secret).encrypt(nonce, message, None)
    return encapsulation, nonce, ciphertext


def decrypt_message(private_key, encapsulation, nonce, ciphertext):
    secret = decapsulate(private_key, encapsulation)
    return AESGCM(secret).decrypt(nonce, ciphertext, None)


private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
message = os.urandom(10 * 1024)
encapsulation, nonce, ciphertext = encrypt_message(private_key.public_key(), message)
assert decrypt_message(private_key, encapsulation, nonce, ciphertext) == message
print("Message recovered.")

print()
print("Message bytes:", len(message))
print("Encapsulation bytes:", len(encapsulation))
print("Nonce bytes:", len(nonce))
print("Ciphertext bytes, including the 16-byte tag:", len(ciphertext))
