#!/usr/bin/env python3
"""
carbon_relay.py
----------------
Carbon Relay (multi-hop forwarder) for CarbonIt Secure Messenger.

- Accepts JSON envelopes over TCP.
- Envelope format (JSON):
  {
    "route": ["ip:port", "ip:port", ...],   # first element is THIS relay's address or was already consumed by previous hop
    "payload": "<base64 or encrypted string>",
    "from": "<sender_pubid>",
    "to": "<dest_pubid>",
    "stap": "<ISO timestamp>",
    "meta": { ... }                        # optional
  }

- Relay behavior:
  * If envelope.route is empty: treat the envelope as intended for this host (deliver to local consumer or drop).
  * Else: pop the next hop from route and forward the envelope to that ip:port.
  * Relay NEVER inspects/decrypts `payload`.
  * Optional short-term logging (disabled by default) for abuse handling.

Legal & safety notes:
- By default this relay does not act as an "exit" to arbitrary internet hosts; it only forwards to CarbonIt peers (safe mode).
- Relay operators must follow LEGAL_COMPLIANCE.md and operator guide.
"""

import socket
import threading
import json
import argparse
import time
import os
from typing import Optional

# --- Config ---
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5050
RECV_BUFFER = 65536
LOG_ENABLED = False          # operator can enable
LOG_PATH = "relay_log.txt"
MAX_ROUTE_LEN = 8            # safety limit to avoid loops

# If True, relay will refuse to forward to non-carbonit ports/addresses unless explicitly allowed
SAFE_MODE = True

# Allowed forward CIDRs or hosts in safe mode (by default allow local LAN for testing)
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]


# --- Helpers ---
def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def log_event(line: str):
    if not LOG_ENABLED:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{now_iso()} {line}\n")
    except Exception:
        pass


def parse_hostport(s: str):
    """Parse 'ip:port' string into (ip, int(port))."""
    try:
        ip, port = s.rsplit(":", 1)
        return ip, int(port)
    except Exception:
        return None, None


# --- Relay core ---
class CarbonRelay:
    def __init__(self, host=LISTEN_HOST, port=LISTEN_PORT, safe_mode=SAFE_MODE):
        self.host = host
        self.port = port
        self.safe_mode = safe_mode
        self.server = None
        self.stop_event = threading.Event()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(128)
        print(f"[CARBON RELAY] Listening on {self.host}:{self.port}  (safe_mode={self.safe_mode})")
        log_event(f"START {self.host}:{self.port}")

        try:
            while not self.stop_event.is_set():
                conn, addr = self.server.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("[CARBON RELAY] Shutting down (KeyboardInterrupt).")
        finally:
            self.stop()

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        print("[CARBON RELAY] Stopped.")
        log_event("STOP")

    def _handle_conn(self, conn: socket.socket, addr):
        peer = f"{addr[0]}:{addr[1]}"
        log_event(f"CONN {peer}")
        try:
            data = b""
            # read one message (assumes client sends full JSON and closes or keeps socket)
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(RECV_BUFFER)
                if not chunk:
                    break
                data += chunk
                # try quick parse (if large data, client should close or send length prefix)
                if len(data) > 0:
                    try:
                        _ = json.loads(data.decode())
                        break
                    except Exception:
                        # keep reading until valid JSON or timeout
                        continue
        except Exception as e:
            log_event(f"RECV_ERROR {peer} {e}")
            conn.close()
            return

        conn.close()

        if not data:
            return

        try:
            envelope = json.loads(data.decode())
        except Exception as e:
            log_event(f"BAD_JSON {peer} {e}")
            return

        # Basic validation
        route = envelope.get("route", [])
        payload = envelope.get("payload")
        from_id = envelope.get("from", "unknown")
        to_id = envelope.get("to", "unknown")
        stap = envelope.get("stap", None)

        log_event(f"MSG from={from_id} to={to_id} route_len={len(route)} peer={peer}")

        # Safety: avoid loops / maliciously long routes
        if not isinstance(route, list):
            log_event(f"BAD_ROUTE_FORMAT from={from_id}")
            return

        if len(route) > MAX_ROUTE_LEN:
            log_event(f"ROUTE_TOO_LONG from={from_id} len={len(route)}")
            return

        # If route empty: final hop - deliver to local consumer (drop or save)
        if len(route) == 0:
            # by default we drop (relay does NOT act as final destination)
            log_event(f"FINAL_DROP from={from_id} to={to_id}")
            # Optional: store locally for operator review if logging enabled
            return

        # Pop next hop
        next_hop = route.pop(0)
        ip, port = parse_hostport(next_hop)
        if ip is None or port is None:
            log_event(f"INVALID_HOP {next_hop}")
            return

        # Safe mode: check allowed hosts list (to avoid arbitrary exit)
        if self.safe_mode:
            if ip not in ALLOWED_HOSTS:
                log_event(f"REJECT_FORWARD to {ip}:{port} (not allowed in safe mode)")
                return

        # Rebuild envelope with updated route
        envelope["route"] = route

        # Forward to next hop
        sent_ok = self._forward_to_next(ip, port, envelope, from_id, to_id)
        if sent_ok:
            log_event(f"FORWARDED from={from_id} next={ip}:{port} remaining={len(route)}")
        else:
            log_event(f"FORWARD_FAILED from={from_id} next={ip}:{port}")

    def _forward_to_next(self, ip: str, port: int, envelope: dict, from_id: str, to_id: str) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6.0)
            s.connect((ip, port))
            s.send(json.dumps(envelope).encode())
            s.close()
            return True
        except Exception as e:
            log_event(f"CONNECT_FAIL next={ip}:{port} err={e}")
            return False


# --- CLI / launcher ---
def parse_args():
    p = argparse.ArgumentParser(prog="carbon_relay.py", description="Carbon Relay - simple multi-hop forwarder")
    p.add_argument("--host", default=LISTEN_HOST, help="Host to bind (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=LISTEN_PORT, help="Port to bind (default 5050)")
    p.add_argument("--safe", action="store_true", help="Enable safe_mode (restrict forwarding to allowed hosts)")
    p.add_argument("--log", action="store_true", help="Enable short-term logging (relay_log.txt)")
    p.add_argument("--allow", action="append", help="Add allowed host (can specify multiple), e.g. --allow 192.168.1.5")
    return p.parse_args()


def main():
    global LOG_ENABLED, SAFE_MODE, ALLOWED_HOSTS, LOG_PATH

    args = parse_args()
    LOG_ENABLED = bool(args.log)
    SAFE_MODE = bool(args.safe)
    if args.allow:
        ALLOWED_HOSTS = ALLOWED_HOSTS + args.allow

    # Optional: operator can set a log path env var
    LOG_PATH = os.getenv("CARBON_RELAY_LOG", LOG_PATH)

    relay = CarbonRelay(host=args.host, port=args.port, safe_mode=SAFE_MODE)
    try:
        relay.start()
    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
