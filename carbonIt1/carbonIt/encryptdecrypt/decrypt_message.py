"""
decrypt_message.py
====================
Decrypts incoming messages that were encrypted using Fernet (AES-128 in CBC + HMAC)
and wrapped with the Carbon Shield multi-layer system.

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju, Poojit Matukumalli.
License: MIT
"""

from cryptography.fernet import Fernet
import base64
import hashlib
from encryptdecrypt.shield_crypto import shield_decrypt, derive_shield_key


def pad_key(key: str) -> bytes:
    """
    Do ensure the Fernet key is 32 url-safe base64 bytes.
    It deterministically expands shorter keys.
    """
    key_hash = hashlib.sha256(key.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)


def decrypt_message(chat_key: str, ciphertext: str) -> str:
    try:
        # Step 1: Fernet decryption
        fernet_key = pad_key(chat_key)
        fernet = Fernet(fernet_key)
        decrypted = fernet.decrypt(ciphertext.encode()).decode()

        # Step 2: Use same derived shield key and decrypt
        shield_key = derive_shield_key(chat_key)
        unwrapped = shield_decrypt(shield_key, decrypted)

        return unwrapped
    except Exception as e:
        print(f"[DECRYPT ERROR] {e}")
        return ""