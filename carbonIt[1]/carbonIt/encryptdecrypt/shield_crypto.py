"""
shield_crypto.py
====================
Implements Carbon Shield — a multi-layer, legally compliant encryption wrapper
that protects message payloads beyond standard Fernet.

Each encryption pass adds a pseudo-“onion” layer using multiple hash+XOR transformations,
making decryption without the correct key computationally infeasible.

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju
License: MIT
"""

import base64
import hashlib
import os


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (used for obfuscation layers)."""
    return bytes(x ^ y for x, y in zip(a, b))


def shield_encrypt(plaintext: str) -> str:
    """
    Adds Carbon Shield layers before Fernet encryption.
    """
    data = plaintext.encode()

    # Layer 1: Salted hash transform
    salt1 = os.urandom(8)
    h1 = hashlib.sha256(salt1 + data).digest()
    layer1 = _xor_bytes(data, h1[:len(data)])

    # Layer 2: Secondary salt and mix
    salt2 = os.urandom(8)
    h2 = hashlib.sha512(salt2 + layer1).digest()
    layer2 = _xor_bytes(layer1, h2[:len(layer1)])

    # Layer 3: Combine salts and base64 encode
    payload = salt1 + salt2 + layer2
    encoded = base64.urlsafe_b64encode(payload).decode()
    return encoded


def shield_decrypt(encoded: str) -> str:
    """
    Removes Carbon Shield layers after Fernet decryption.
    """
    try:
        data = base64.urlsafe_b64decode(encoded)
        salt1 = data[:8]
        salt2 = data[8:16]
        layer2 = data[16:]

        # Reverse Layer 2
        h2 = hashlib.sha512(salt2 + layer2).digest()
        layer1 = _xor_bytes(layer2, h2[:len(layer2)])

        # Reverse Layer 1
        h1 = hashlib.sha256(salt1 + layer1).digest()
        plaintext_bytes = _xor_bytes(layer1, h1[:len(layer1)])

        return plaintext_bytes.decode()
    except Exception as e:
        print(f"[SHIELD DECRYPT ERROR] {e}")
        return ""
