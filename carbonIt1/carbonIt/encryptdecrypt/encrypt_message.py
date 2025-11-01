"""
encrypt_message.py
====================
Encrypts outgoing messages using Fernet (AES-128 in CBC + HMAC)
and Carbon Shield multi-layer encoding for end-to-end encryption.

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju, Poojit Matukumalli.
License: MIT
"""

from cryptography.fernet import Fernet
import base64
import hashlib
from encryptdecrypt.shield_crypto import shield_encrypt, derive_shield_key


def pad_key(key: str) -> bytes:
    """
    Do ensure the Fernet key is 32 url-safe base64 bytes.
    It deterministically expands shorter keys.
    """
    key_hash = hashlib.sha256(key.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)


def encrypt_message(chat_key: str, message: str) -> str:
    try:
        # Derive a 32-byte AES-GCM key from chat_key
        shield_key = derive_shield_key(chat_key)

        # Step 1: Shield layer (AES-GCM authenticated encrypt)
        shielded = shield_encrypt(shield_key, message)
        if not shielded:
            raise RuntimeError("Shield encryption failed")

        # Step 2: Symmetric Fernet AES encryption (as before)
        fernet_key = pad_key(chat_key)
        fernet = Fernet(fernet_key)
        encrypted = fernet.encrypt(shielded.encode())

        return encrypted.decode()
    except Exception as e:
        print(f"[ENCRYPT ERROR] {e}")
        return ""