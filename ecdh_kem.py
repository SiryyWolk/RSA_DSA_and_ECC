from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()

def _derive(shared):
    # Raw ECDH output is not uniformly random, so pass it through a KDF.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"ecdh-kem").derive(shared)

def encapsulate(public_key):
    ephemeral = ec.generate_private_key(CURVE)           # fresh key pair
    shared = ephemeral.exchange(ec.ECDH(), public_key)   # Diffie-Hellman with Bob's key
    encapsulation = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    return _derive(shared), encapsulation

def decapsulate(private_key, encapsulation):
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, encapsulation)
    shared = private_key.exchange(ec.ECDH(), ephemeral_public)
    return _derive(shared)

# Test: do Alice and Bob agree?
bob_private = ec.generate_private_key(CURVE)
secret_a, encapsulation = encapsulate(bob_private.public_key())
secret_b = decapsulate(bob_private, encapsulation)
print("Agree?", secret_a == secret_b)
print("Encapsulation length:", len(encapsulation), "bytes")