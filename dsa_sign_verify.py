import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

# DSA signs but cannot encrypt.  FIPS 186-5 allows it only for verifying
# existing signatures.  A 3072-bit key gives about 128-bit security.
private_key = dsa.generate_private_key(key_size=3072)
public_key = private_key.public_key()

message = os.urandom(1024)

# We can sign the message using "hash-then-sign".
signature = private_key.sign(message, hashes.SHA256())

# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
public_key.verify(signature, message, hashes.SHA256())

print()
print("Message: " + message.hex())
print()
print("Signature: " + signature.hex())
