"""
User side carbon relay. Recieves and sends messages.
By- Poojit Matukumalli
thats it. Go read the code 🙏
"""
import json; import random; import asyncio; import aiohttp_socks as asocks
import os;   import time  ; import subprocess

# Setting up the user's onion url/route/address or whatever it is
addr_file = os.path.join("carbonIt1","carbonIt","network", "Networking", "data", "HiddenService","hostname")
with open(addr_file, "r") as f:
    addr_user_onion = f.read()

# Configuration ig
user_onion = addr_user_onion
recipient_onion = "5aysoc7uflfmgztpkdvhmioxhyj6wmntnldm2mmgpjjf5eqc6od2kyad.onion"  # TODO : Add actual data fetcher using SQLite or something else
relay_file = os.path.join("carbonIt1","carbonIt", "network", "relay_list.json")
proxy = ("127.0.0.1", 9050)
listen_port = 5050

def load_active_relays():       # Loads active relays... Duh
    try:
        with open(relay_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        relays = data.get("relays", [])
        active_relays = []
        for r in relays:
            if r.get("status") == "active" and r.get("onion"):
                addr = r["onion"]
                port = r.get("port", 5050)
                active_relays.append(f"{addr}:{port}")
        return active_relays
    except Exception as e:
        print(f"[ERR] Failed to load {relay_file}: {e}")
        return []

def encrypt_payload(msg: str) -> str:
    return f"ENCRYPTED::{msg}"              # TODO : Add Encryption

def decrypt_payload(msg: str) -> str:
    """Mock decryption — replace later."""
    if msg.startswith("ENCRYPTED::"):
        return msg[len("ENCRYPTED::"):]
    return msg

def parse_hostport(addr: str):
    try:
        h, p = addr.rsplit(":", 1)
        return h, int(p)
    except:
        return None, None

async def send_via_tor(onion_route: str, port: int, envelope: dict):
    """Send envelope through Tor to the given relay."""
    try:
        reader, writer = await asocks.open_connection(
            proxy_host=proxy[0],
            proxy_port=proxy[1],
            host=onion_route,
            port=port
        )
        writer.write(json.dumps(envelope).encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print(f"[OK] Envelope sent → {onion_route}:{port}")
    except Exception as e:
        print(f"[FAIL] Transmission error → {onion_route}:{port} | {e}")

# sending logic
async def relay_send(message: str, show_route: bool = True):
    active_relays = load_active_relays()
    if not active_relays:
        print("[ERR] No active relays found.")
        return

    # this randomly chooses 2–4 relays
    route_relays = random.sample(active_relays, k=min(len(active_relays), random.randint(3, 5)))

    # route (user → relays → destination)
    route = [user_onion] + route_relays + [recipient_onion]
    if show_route:
        print(f"[ROUTE] {' → '.join(route)}")

    envelope = {
        "route": route.copy(),
        "payload": encrypt_payload(message),
        "from": user_onion,
        "to": recipient_onion,
        "stap": time.time(),
        "meta": {"type": "msg"}
    }

    # Pop the user address to avoid looping
    route.pop(0)
    first_hop = route[0]
    host, port = parse_hostport(first_hop)
    if not host or port is None:
        print("[Error] Invalid first hop.")
        return

    await send_via_tor(host, port, envelope)

# the listener 
async def handle_incoming(reader, writer):
    try:
        data = await reader.read(8192)
        msg_raw = data.decode()
        try:
            envelope = json.loads(msg_raw)
            decrypted = decrypt_payload(envelope.get("payload", ""))
            print(f"\n[INCOMING MESSAGE]\nFrom: {envelope.get('from')}\nMsg: {decrypted}\n")
        except Exception:
            print(f"[RAW INCOMING DATA]: {msg_raw}")
    except Exception as e:
        print(f"[ERR] Inbound handler crashed: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def inbound_listener():
    server = await asyncio.start_server(handle_incoming, "127.0.0.1", listen_port)
    print(f"[LISTENER] Active on 127.0.0.1:{listen_port}")
    async with server:
        await server.serve_forever()

# running both
async def main():
    await asyncio.gather(
        inbound_listener(),
        relay_send("CarbonIt handshake test.")  # outbound test message
    )

if __name__ == "__main__":
    asyncio.run(main())