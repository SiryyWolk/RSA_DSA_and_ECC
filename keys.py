from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519

keys = {
    "RSA 3072": rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "DSA 3072": dsa.generate_private_key(key_size=3072),
    "P-256": ec.generate_private_key(ec.SECP256R1()),
    "Ed25519": ed25519.Ed25519PrivateKey.generate(),
    "RSA 7680": rsa.generate_private_key(public_exponent=65537, key_size=7680),
    "P-384": ec.generate_private_key(ec.SECP384R1()),
}

for name, private_key in keys.items():
    public_key = private_key.public_key()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    print(name)
    print(public_key_str.decode("utf-8"))
    print("Length in characters:", len(public_key_str))
    print()