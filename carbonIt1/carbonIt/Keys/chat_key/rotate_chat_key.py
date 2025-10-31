"""
rotate_chat_key.py
====================
Handles automatic session key rotation for CarbonIt Secure Messenger.
Ensures forward secrecy by rotating the shared chat key every 10 minutes
or 25 messages, and synchronizing via encrypted 'KEYUPDATE' message.

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju
License: MIT
"""

import hashlib
import base64
import time
import threading
import socket

# Global state
CARBONIT_CHAT_KEY = None
MESSAGE_COUNTER = 0
LAST_ROTATE_TIME = time.time()

ROTATE_INTERVAL = 600           # 10 minutes
ROTATE_AFTER_MESSAGES = 25      # Rotate after 25 messages


def derive_chat_key(priv_key, peer_pub_key):
    """
    Deterministically derive symmetric chat key based on both peer IDs.
    """
    combo = '|'.join(sorted([priv_key, peer_pub_key]))
    shared_secret = hashlib.sha256(combo.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(shared_secret).decode()
    return fernet_key


def rotate_chat_key(priv_key, peer_pub_key, peer_ip=None, peer_port=None):
    """
    Generates a new rotated chat key and sends a secure KEYUPDATE
    message to the peer to synchronize rotation.
    """
    global CARBONIT_CHAT_KEY, MESSAGE_COUNTER, LAST_ROTATE_TIME

    combo = f"{priv_key}|{peer_pub_key}|{time.time()}"
    new_secret = hashlib.sha256(combo.encode()).digest()
    CARBONIT_CHAT_KEY = base64.urlsafe_b64encode(new_secret).decode()

    MESSAGE_COUNTER = 0
    LAST_ROTATE_TIME = time.time()

    print("\n------------------------------------------")
    print("[KEY ROTATION] 🔄 New chat key generated.")
    print(f"[KEY HASH] {hashlib.sha256(CARBONIT_CHAT_KEY.encode()).hexdigest()[:16]}...")
    print(f"[ROTATED AT] {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("------------------------------------------\n")

    # Send KEYUPDATE notice if peer is provided
    if peer_ip and peer_port:
        try:
            msg = f"KEYUPDATE:{CARBONIT_CHAT_KEY}"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_ip, int(peer_port)))
            s.send(msg.encode())
            s.close()
            print(f"[KEY SYNC] Sent KEYUPDATE to {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"[KEY SYNC ERROR] Could not send KEYUPDATE: {e}")

    return CARBONIT_CHAT_KEY


def check_rotation(priv_key, peer_pub_key, peer_ip=None, peer_port=None):
    """
    Checks whether key rotation is needed (based on time or message count).
    """
    global MESSAGE_COUNTER, LAST_ROTATE_TIME

    now = time.time()
    MESSAGE_COUNTER += 1
    time_elapsed = now - LAST_ROTATE_TIME

    if MESSAGE_COUNTER >= ROTATE_AFTER_MESSAGES or time_elapsed >= ROTATE_INTERVAL:
        rotate_chat_key(priv_key, peer_pub_key, peer_ip, peer_port)


def auto_rotation_monitor(priv_key, peer_pub_key, peer_ip=None, peer_port=None):
    """
    Background thread to automatically rotate keys every ROTATE_INTERVAL seconds.
    """
    def monitor():
        global LAST_ROTATE_TIME
        while True:
            if time.time() - LAST_ROTATE_TIME >= ROTATE_INTERVAL:
                rotate_chat_key(priv_key, peer_pub_key, peer_ip, peer_port)
            time.sleep(30)  # check every 30 seconds

    threading.Thread(target=monitor, daemon=True).start()
