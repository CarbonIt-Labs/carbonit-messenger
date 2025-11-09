"""
carbon_shield.py
----------------
Client-side Carbon Shield sender for CarbonIt.

- Reads network/relay_list.json (if present) and picks relays.
- Builds a JSON envelope with "route" (list of "ip:port"), "payload", "from", "to", "stap".
- Sends envelope to the first hop (or directly to peer).
- Uses encryptdecrypt.encrypt_message to produce payload (Fernet + Carbon Shield).

Usage:
    python carbon_shield.py
"""

import os
import json
import socket
import random
import time
import argparse
import hashlib

from encryptdecrypt.encrypt_message import encrypt_message

RELAY_LIST_PATH = os.path.join(os.path.dirname(__file__), "relay_list.json")
DEFAULT_HOPS = 3
BUFFER_SIZE = 65536
TIMEOUT = 6.0


def load_relays(path=RELAY_LIST_PATH):
    """Load relay list JSON. Returns list of dicts with keys ip, port, pub (optional)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        relays = data.get("relays", [])
        cleaned = []
        for r in relays:
            ip = r.get("ip")
            port = int(r.get("port", 5050))
            if ip:
                cleaned.append({"ip": ip, "port": port, "id": r.get("id")})
        return cleaned
    except FileNotFoundError:
        return []
    except Exception as e:
        print("[RELAYS LOAD ERROR]", e)
        return []


def pick_route(relays, hops=DEFAULT_HOPS):
    """
    Pick a random route (list of 'ip:port').
    If not enough relays, returns an empty list (meaning direct send).
    """
    if not relays:
        return []
    # avoid duplicate hops; sample up to hops
    count = min(hops, len(relays))
    chosen = random.sample(relays, count)
    return [f"{r['ip']}:{r['port']}" for r in chosen]


def build_envelope(route, payload, from_id, to_id):
    """Construct the JSON envelope to send to the first hop."""
    envelope = {
        "route": route,       # list of "ip:port" strings; first element is next hop
        "payload": payload,   # encrypted ciphertext (string)
        "from": from_id,
        "to": to_id,
        "stap": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "meta": {"proto": "carbonit-v1"}
    }
    return envelope


def send_to_first_hop(envelope):
    """Send the envelope to the first hop in envelope['route'] (or return error)."""
    route = envelope.get("route", [])
    if not route:
        return False, "Route empty - no hop to send to"

    first = route[0]
    try:
        ip_port = first.rsplit(":", 1)
        ip = ip_port[0]
        port = int(ip_port[1])
    except Exception:
        return False, f"Invalid first hop: {first}"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        # send JSON envelope
        s.send(json.dumps(envelope).encode())
        s.close()
        return True, f"Envelope sent to {first}"
    except Exception as e:
        return False, f"Send failed to {first}: {e}"


def compute_pubid(username):
    """Deterministic public id (hashed username) — matches carbonit_node logic."""
    return hashlib.sha256(username.encode()).hexdigest()


def cli_send(args):
    """Interactive CLI to send a message via Carbon Shield routing."""
    relays = load_relays()
    if relays:
        print(f"[RELAYS] Loaded {len(relays)} relays.")
    else:
        print("[RELAYS] No relay_list.json found or empty — direct sends only.")

    username = args.username or input("Your username: ").strip()
    password = args.password or input("Your password: ").strip()  # used only to generate priv id if needed
    to_pub = args.peer_pub or input("Peer public ID (hashed username): ").strip()
    direct_ip = args.peer_ip or input("Peer IP (leave blank to use relays): ").strip()
    direct_port = args.peer_port or input("Peer port (5050 default): ").strip() or "5050"

    from_pub = compute_pubid(username)

    while True:
        msg = input("You: ")
        if not msg:
            continue
        if msg.lower() in ("exit", "quit"):
            break

        # produce encrypted payload
        # NOTE: encrypt_message expects a chat_key; for routing-level encryption we keep using current chat key behavior.
        # Here we assume chat key is derived elsewhere; for simple testing you can pass a sample key.
        # For now, use peer_pub as chat_key seed (example behaviour) — replace with real derived chat_key.
        chat_key = to_pub  # placeholder: replace with real derived key in full node integration
        ciphertext = encrypt_message(chat_key, msg)  # returns ciphertext string

        # build route
        if direct_ip:
            # direct delivery (route contains the peer address only)
            route = [f"{direct_ip}:{direct_port}"]
        else:
            route = pick_route(relays, hops=args.hops)

        envelope = build_envelope(route, ciphertext, from_pub, to_pub)

        ok, info = send_to_first_hop(envelope) if route else (False, "No route available and no direct IP provided")
        if ok:
            print(f"[SENT] {info}")
        else:
            print(f"[SEND FAILED] {info}")


def main():
    p = argparse.ArgumentParser(description="Carbon Shield sender (client-side)")
    p.add_argument("--username", help="Your username (for public id generation)")
    p.add_argument("--password", help="Your password (optional)")
    p.add_argument("--peer-pub", help="Peer public ID (hashed username)")
    p.add_argument("--peer-ip", help="Direct peer IP (skip relays if provided)")
    p.add_argument("--peer-port", help="Direct peer port", default="5050")
    p.add_argument("--hops", type=int, default=DEFAULT_HOPS, help="Number of relays to use")
    args = p.parse_args()

    cli_send(args)
    print("accessed carbon shield")

if __name__ == "__main__":
    main()
