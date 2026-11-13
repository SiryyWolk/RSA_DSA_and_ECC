import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# A 3072-bit key gives about 128-bit security.
private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public_key = private_key.public_key()

# OAEP padding, with SHA-256 as the hash and inside MGF1.
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

plaintext = os.urandom(50)

# We can encrypt a small plaintext with the public key.
ciphertext = public_key.encrypt(plaintext, oaep)

# Only the private key can decrypt it.
recovered = private_key.decrypt(ciphertext, oaep)

print("Plaintext: " + plaintext.hex())
print()
print("Ciphertext: " + ciphertext.hex())
print()
print("Recovered: " + recovered.hex())
