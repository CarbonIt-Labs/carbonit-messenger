"""
decrypt_message.py
====================
Decrypts incoming messages that were encrypted using Fernet (AES-128 in CBC + HMAC)
and wrapped with the Carbon Shield multi-layer system.

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju
License: MIT
"""

from cryptography.fernet import Fernet
import base64
import hashlib
from encryptdecrypt.shield_crypto import shield_decrypt


def pad_key(key: str) -> bytes:
    """
    Ensure the Fernet key is 32 url-safe base64 bytes.
    Deterministically expand shorter keys.
    """
    key_hash = hashlib.sha256(key.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)


def decrypt_message(chat_key: str, ciphertext: str) -> str:
    """
    Decrypts message using Fernet symmetric key + Carbon Shield layer.
    (Reverse of encryption: Fernet → Shield)
    """
    try:
        # Step 1: Fernet decryption
        fernet_key = pad_key(chat_key)
        fernet = Fernet(fernet_key)
        decrypted = fernet.decrypt(ciphertext.encode()).decode()

        # Step 2: Remove Carbon Shield wrapper
        unwrapped = shield_decrypt(decrypted)

        return unwrapped
    except Exception as e:
        print(f"[DECRYPT ERROR] {e}")
        return ""
