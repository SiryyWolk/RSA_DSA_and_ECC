import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ECDSA with P-256 and SHA-256, about 128-bit classical security.
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

message = os.urandom(1024)

# We can sign the message using "hash-then-sign".
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# We can verify the signature.  If the signature is invalid it will
# raise an Exception.
public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

print()
print("Message: " + message.hex())
print()
print("Signature: " + signature.hex())
