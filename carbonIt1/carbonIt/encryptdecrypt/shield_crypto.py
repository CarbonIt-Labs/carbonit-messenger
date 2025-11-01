"""
shield_crypto.py
====================
Carbon Shield (reworked) — AES-GCM authenticated encryption layer with
HKDF-derived keys so it can be used deterministically from a chat_key string.

APIs:
- derive_shield_key(chat_key: str) -> bytes        # 32-byte key
- shield_encrypt(key: bytes, plaintext: str) -> str  # returns base64(nonce + ciphertext)
- shield_decrypt(key: bytes, encoded: str) -> str    # returns plaintext or "" on error
"""

import os
import base64
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Constants
AESGCM_KEY_SIZE = 32          # 256-bit AES-GCM
AESGCM_NONCE_SIZE = 12        # recommended nonce size for GCM
HKDF_INFO = b"carbonit-shield-v1"  # context string for domain separation


def derive_shield_key(chat_key: str, salt: Optional[bytes] = None) -> bytes:
    # TODO, Add salt (optional) to HKDF for session uniqueness
    """
    Deterministically derive a 32-byte key suitable for AES-GCM from the
    chat_key (string). Both sides must call this with the exact same chat_key
    to derive the same shield key.

    Optional salt may be provided; if you want cross-session uniqueness,
    you can supply a persistent salt (but default None is fine).
    """
    ikm = chat_key.encode()  # input key material
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AESGCM_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(ikm)


def shield_encrypt(key: bytes, plaintext: str) -> str:
    """
    Encrypts the plaintext using AES-GCM.
    Returns a urlsafe-base64 string of (nonce || ciphertext_with_tag).
    """
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(AESGCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data=None)
        payload = nonce + ciphertext
        return base64.urlsafe_b64encode(payload).decode()
    except Exception as e:
        # Keep error message concise so logs don't leak secrets
        print(f"[SHIELD ENCRYPT ERROR] {e}")
        return ""


def shield_decrypt(key: bytes, encoded: str) -> str:
    """
    Decode the urlsafe-base64 payload (nonce || ciphertext) and decrypt.
    Returns plaintext, type : str, or an empty string on failure.
    """
    try:
        payload = base64.urlsafe_b64decode(encoded)
        if len(payload) < AESGCM_NONCE_SIZE + 16:  # 16 is minimum tag size
            raise ValueError("payload too short")
        nonce = payload[:AESGCM_NONCE_SIZE]
        ciphertext = payload[AESGCM_NONCE_SIZE:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode()
    except Exception as e:
        print(f"[SHIELD DECRYPT ERROR] {e}")
        return ""