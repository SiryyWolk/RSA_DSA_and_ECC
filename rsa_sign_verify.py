import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# RSA signing with PSS padding (Probabilistic Signature Scheme).
# A 3072-bit key gives about 128-bit security.
private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public_key = private_key.public_key()

# PSS padding, with SHA-256 inside MGF1 and a salt the length of the hash.
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

message = os.urandom(1024)

# We can sign the message using "hash-then-sign".
signature = private_key.sign(message, pss, hashes.SHA256())

# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
public_key.verify(signature, message, pss, hashes.SHA256())

print()
print("Message: " + message.hex())
print()
print("Signature: " + signature.hex())
