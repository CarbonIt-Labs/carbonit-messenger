#!/usr/bin/env python3
"""
shield_utils.py
----------------
Core networking utilities for Carbon Shield relays and nodes.

Handles:
- Socket helpers (listen, forward, connect)
- Envelope parsing and validation
- Route trimming (next-hop forwarding)
- Optional hop-level metadata protection

Part of: CarbonIt Secure Messenger
Author: Edwin Sam K Reju
License: MIT
"""

import socket
import json
import time
import hashlib
import base64
from encryptdecrypt.encrypt_message import encrypt_message
from encryptdecrypt.decrypt_message import decrypt_message

BUFFER_SIZE = 65536
TIMEOUT = 10.0


# =====================================================
#  Low-Level Socket Helpers
# =====================================================

def create_server_socket(ip="0.0.0.0", port=5050):
    """Create and bind a TCP socket to listen for incoming messages."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    print(f"[LISTENING] on {ip}:{port}")
    return s


def send_json(ip, port, data):
    """Send JSON data to a given IP and port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, int(port)))
        s.send(json.dumps(data).encode())
        s.close()
        return True
    except Exception as e:
        print(f"[SEND ERROR] to {ip}:{port} - {e}")
        return False


# =====================================================
#  Envelope Validation / Processing
# =====================================================

def parse_envelope(raw_data):
    """Parse incoming JSON envelope safely."""
    try:
        data = json.loads(raw_data)
        if not isinstance(data, dict):
            raise ValueError("Envelope not an object")
        if "route" not in data or "payload" not in data:
            raise ValueError("Missing route/payload")
        return data
    except Exception as e:
        print(f"[PARSE ERROR] {e}")
        return None


def trim_route(envelope):
    """
    Removes the current hop and returns the next destination.
    Example:
        route = ["hop1", "hop2", "hop3"]
        After trim_route -> next="hop2", envelope.route=["hop2","hop3"]
    """
    try:
        route = envelope.get("route", [])
        if not route:
            return None, envelope
        # pop first hop
        route.pop(0)
        if route:
            next_hop = route[0]
        else:
            next_hop = None
        envelope["route"] = route
        return next_hop, envelope
    except Exception as e:
        print(f"[ROUTE ERROR] {e}")
        return None, envelope


def is_final_destination(envelope):
    """Return True if this node is the final destination (no more hops)."""
    route = envelope.get("route", [])
    return not route


# =====================================================
#  Hop-Level Header Obfuscation (optional)
# =====================================================

def simple_header_hash(header):
    """
    Generate a reversible mask for hop headers using SHA-256 and base64.
    (Used for metadata obfuscation without violating legal transparency)
    """
    h = hashlib.sha256(header.encode()).digest()
    return base64.urlsafe_b64encode(h).decode()[:32]


def apply_header_mask(route_entry):
    """
    Obfuscate route entry string to protect relay metadata.
    """
    return simple_header_hash(route_entry)


# =====================================================
#  Message Decryption at Final Node
# =====================================================

def handle_final_message(envelope, chat_key):
    """
    Decrypt the final message payload and display contents.
    """
    try:
        ciphertext = envelope["payload"]
        sender = envelope.get("from", "unknown")
        stap = envelope.get("stap", "")
        decrypted = decrypt_message(chat_key, ciphertext)
        msg_id = hashlib.sha256(ciphertext.encode()).hexdigest()[:16]

        print(f"[RECV] from {sender}: {decrypted}")
        print(f"      sent_at (stap): {stap}, id: {msg_id}")
        return decrypted
    except Exception as e:
        print(f"[DECRYPT ERROR] {e}")
        return None


# =====================================================
#  Relay Forwarding Logic
# =====================================================

def forward_envelope(envelope):
    """
    Forward the envelope to the next hop or drop if no hops remain.
    """
    next_hop, updated = trim_route(envelope)
    if not next_hop:
        print("[FORWARD] No remaining hops — dropping.")
        return False

    try:
        ip, port = next_hop.rsplit(":", 1)
        print(f"[FORWARD] -> {ip}:{port}")
        return send_json(ip, port, updated)
    except Exception as e:
        print(f"[FORWARD ERROR] {e}")
        return False


# =====================================================
#  Envelope Creation (for relays / debugging)
# =====================================================

def make_test_envelope(message, from_id, to_id, chat_key, route=None):
    """Utility: create a test envelope manually (for debugging)."""
    if route is None:
        route = []
    encrypted = encrypt_message(chat_key, message)
    envelope = {
        "route": route,
        "payload": encrypted,
        "from": from_id,
        "to": to_id,
        "stap": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
    }
    return envelope
