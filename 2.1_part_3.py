import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public_key = private_key.public_key()

oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

plaintext = os.urandom(50)
ciphertext = public_key.encrypt(plaintext, oaep)

# --- Part 3: change a single byte of the ciphertext ---
tampered = bytearray(ciphertext)   # bytes can't be edited, bytearray can
tampered[100] ^= 1                 # flip one bit in byte number 100
tampered = bytes(tampered)         # convert back to bytes

print("Original ciphertext changed?", tampered != ciphertext)

# Decrypting the untouched ciphertext still works (sanity check)
print("Original decrypts OK:", private_key.decrypt(ciphertext, oaep) == plaintext)

# Decrypting the tampered one should fail
try:
    recovered = private_key.decrypt(tampered, oaep)
    print("Decrypted (unexpected):", recovered.hex())
except Exception as e:
    print("Exception:", type(e).__name__, "-", e)