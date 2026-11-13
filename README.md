# RSA, DSA, and ECC Crypto Demonstrations

This repository contains a small set of Python examples that demonstrate common public-key cryptography workflows using the `cryptography` library.

The scripts cover:

- RSA encryption and decryption
- RSA signing and verification
- DSA signing and verification
- ECDSA with a P-256 key
- ECDH key agreement
- Hybrid RSA + AES-GCM encryption
- Public key serialization and comparison across algorithms

## Project structure

- `rsa_encrypt_decrypt.py` — encrypts and decrypts a message using RSA-OAEP
- `rsa_sign_verify.py` — signs and verifies a message using RSA-PSS
- `dsa_sign_verify.py` — signs and verifies a message using DSA
- `ecc_sign_verify.py` — signs and verifies a message using ECDSA over P-256
- `ecdh_kem.py` — performs ECDH-based key agreement and KEM-style secret derivation
- `rsa_hybrid_encrypt_decrypt.py` — hybrid encryption using RSA key encapsulation with AES-GCM
- `keys.py` — generates and prints public keys for several algorithms
- `2.1_part_3.py` — demonstrates how a single-byte change in ciphertext breaks RSA decryption

## Requirements

- Python 3.8+
- The `cryptography` package

Install dependencies:

```bash
python -m pip install cryptography
```

## Quick start

Run any of the examples directly from this repository:

```bash
python rsa_encrypt_decrypt.py
python rsa_sign_verify.py
python dsa_sign_verify.py
python ecc_sign_verify.py
python ecdh_kem.py
python rsa_hybrid_encrypt_decrypt.py
python keys.py
python 2.1_part_3.py
```

Each script is self-contained and generates fresh keys at runtime, then prints the relevant data (plaintext, ciphertext, signatures, or derived secrets).

## What the examples show

### RSA

RSA is used for both encryption and signatures:

- `rsa_encrypt_decrypt.py` shows RSA-OAEP encryption
- `rsa_sign_verify.py` shows RSA-PSS signatures
- `rsa_hybrid_encrypt_decrypt.py` shows a practical hybrid construction: RSA encapsulates a secret, and AES-GCM encrypts the actual message

### DSA and ECDSA

These examples show signature schemes based on discrete logarithms:

- `dsa_sign_verify.py` uses standard DSA
- `ecc_sign_verify.py` uses ECDSA with the secp256r1 curve

### ECDH

`ecdh_kem.py` demonstrates key agreement using elliptic-curve Diffie-Hellman, deriving a shared secret with HKDF.

## Notes

- These scripts are educational examples, not production-ready cryptographic implementations.
- They generate ephemeral keys in memory for demonstration purposes.
- For real-world systems, always use a carefully designed key management strategy, secure storage, and vetted protocol libraries.

## License

This project is intended for educational use. See repository policies or add a license file if you plan to distribute it more broadly.
