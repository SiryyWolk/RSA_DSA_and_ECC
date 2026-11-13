import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec, ed25519

message = os.urandom(1024)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

rsa_k = rsa.generate_private_key(65537, 3072)
dsa_k = dsa.generate_private_key(3072)
ec_k = ec.generate_private_key(ec.SECP256R1())
ed_k = ed25519.Ed25519PrivateKey.generate()

schemes = {
    "RSA-PSS 3072": (lambda m: rsa_k.sign(m, pss, hashes.SHA256()),
                     lambda s, m: rsa_k.public_key().verify(s, m, pss, hashes.SHA256())),
    "DSA 3072":     (lambda m: dsa_k.sign(m, hashes.SHA256()),
                     lambda s, m: dsa_k.public_key().verify(s, m, hashes.SHA256())),
    "ECDSA P-256":  (lambda m: ec_k.sign(m, ec.ECDSA(hashes.SHA256())),
                     lambda s, m: ec_k.public_key().verify(s, m, ec.ECDSA(hashes.SHA256()))),
    "Ed25519":      (lambda m: ed_k.sign(m),
                     lambda s, m: ed_k.public_key().verify(s, m)),
}

tampered = bytearray(message)
tampered[500] ^= 1          # change a single bit of the message
tampered = bytes(tampered)

for name, (sign, verify) in schemes.items():
    s1, s2 = sign(message), sign(message)
    verify(s1, message)
    verify(s2, message)
    try:
        verify(s1, tampered)
        result = "accepted (this should not happen)"
    except Exception as e:
        result = type(e).__name__
    print(f"{name}: same twice? {s1 == s2}, lengths {len(s1)} and {len(s2)}, tampered -> {result}")