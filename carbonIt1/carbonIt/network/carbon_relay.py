"""
carbon_relay_async.py
----------------------
Async version of Carbon Relay (multi-hop forwarder) for CarbonIt Secure Messenger.
Handles connections using asyncio (no threads, no blocking).
Uses Tor .onion routing.

Envelope format (JSON):
{
  "route": [".onion:port", ".onion:port", ...],
  "payload": "<encrypted or base64 string>",
  "from": "<sender_pubid>",
  "to": "<dest_pubid>",
  "stap": "<ISO timestamp>",
  "meta": { ... }   # optional
}
"""
import aiohttp_socks as asocks
import asyncio
import json
import time
import argparse

# --- configuration ---
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5050
LOG_ENABLED = False
LOG_PATH = "relay_log.txt"
MAX_ROUTE_LEN = 8
SAFE_MODE = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost", ".onion"]

# --- helper functions ---
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
    try:
        onion_route, port = s.rsplit(":", 1)
        return onion_route, int(port)
    except Exception:
        return None, None

# --- async Relay Core ---
class CarbonRelayAsync:
    def __init__(self, host=LISTEN_HOST, port=LISTEN_PORT, safe_mode=SAFE_MODE):
        self.host = host
        self.port = port
        self.safe_mode = safe_mode

    async def start(self):
        server = await asyncio.start_server(self._handle_conn, self.host, self.port)
        addr = server.sockets[0].getsockname()
        print(f"[CARBON RELAY ASYNC] Listening on {addr}  (safe_mode={self.safe_mode})")
        log_event(f"START {addr}")

        async with server:
            await server.serve_forever()

    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        log_event(f"CONN {peer}")

        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
        except asyncio.TimeoutError:
            log_event(f"TIMEOUT {peer}")
            writer.close()
            await writer.wait_closed()
            return

        if not data:
            writer.close()
            await writer.wait_closed()
            return

        try:
            envelope = json.loads(data.decode())
        except Exception as e:
            log_event(f"BAD_JSON {peer} {e}")
            writer.close()
            await writer.wait_closed()
            return

        route = envelope.get("route", [])
        payload = envelope.get("payload")
        from_id = envelope.get("from", "unknown")
        to_id = envelope.get("to", "unknown")

        if not isinstance(route, list):
            log_event(f"BAD_ROUTE_FORMAT from={from_id}")
            return

        if len(route) > MAX_ROUTE_LEN:
            log_event(f"ROUTE_TOO_LONG from={from_id}")
            return

        if len(route) == 0:
            log_event(f"FINAL_DROP from={from_id} to={to_id}")
            return

        next_hop = route.pop(0)
        onion_route, port = parse_hostport(next_hop)
        if onion_route is None or port is None:
            log_event(f"INVALID_HOP {next_hop}")
            return

        if self.safe_mode and not onion_route.endswith(".onion"):
            log_event(f"REJECT_FORWARD to {onion_route}:{port} (not .onion). (not allowed in safe mode)")
            return

        envelope["route"] = route

        ok = await self._forward_to_next(onion_route, port, envelope, from_id, to_id)
        if ok:
            log_event(f"FORWARDED from={from_id} next={onion_route}:{port} remaining={len(route)}")
        else: 
            log_event(f"FORWARD_FAILED from={from_id} next={onion_route}:{port}")

    async def _forward_to_next(self, onion_route, port, envelope, from_id, to_id):
        try:
            reader, writer = await asocks.open_connection(proxy_host="127.0.0.1",
                proxy_port=9050,
                host=onion_route,
                port=port
                )  # asocks is the name of aiohttp-socks          
            writer.write(json.dumps(envelope).encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            log_event(f"CONNECT_FAIL, next={onion_route}:{port } err={e}")
            return False


# --- stuff showing up in the CLI ---
def parse_args():
    p = argparse.ArgumentParser(description="Carbon Relay Async - multi-hop forwarder")
    p.add_argument("--host", default=LISTEN_HOST)
    p.add_argument("--port", type=int, default=LISTEN_PORT)
    p.add_argument("--safe", action="store_true")
    p.add_argument("--log", action="store_true")
    p.add_argument("--allow", action="append")
    return p.parse_args()

async def main():
    global LOG_ENABLED, SAFE_MODE, ALLOWED_HOSTS
    args = parse_args()
    LOG_ENABLED = args.log
    SAFE_MODE = args.safe
    if args.allow:
        ALLOWED_HOSTS += args.allow

    relay = CarbonRelayAsync(args.host, args.port, SAFE_MODE)
    await relay.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[CARBON RELAY ASYNC] Shutting down.")
