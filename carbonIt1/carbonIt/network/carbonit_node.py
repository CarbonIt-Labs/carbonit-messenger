"""
carbonit_node.py
=========================
Main peer-to-peer node for CarbonIt Secure Messenger.

Handles:
 - Peer connections (TCP)
 - Encrypted messaging using Carbon Shield encryption layer
 - Automatic chat-key rotation every 10 minutes or 25 messages
 - Secure KEYUPDATE sync between peers

Author: Edwin Sam K Reju, Poojit Matukumalli
License: MIT
"""

import aiohttp_socks
import asyncio
import time
import json
import hashlib
import sys, os

# === PATH FIX (ensures proper imports) ===
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# === IMPORTS ===
from encryptdecrypt.encrypt_message import encrypt_message
from encryptdecrypt.decrypt_message import decrypt_message
from Keys.chat_key.derive_chat_key import derive_chat_key
from Keys.chat_key.rotate_chat_key import rotate_chat_key, check_rotation, auto_rotation_monitor


# === GLOBAL CONFIG ===
HOST = "0.0.0.0"
PORT = 5050
BUFFER_SIZE = 4096

CARBONIT_CHAT_KEY = None
PEER_ADDR = None
PEER_PUB_KEY = None
USERNAME = None


# === NETWORK SETUP ===
async def handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global CARBONIT_CHAT_KEY
    addr = writer.get_extra_info("peername")
    print(f"[INCOMING CONNECT] {addr}")
    while True:
        try:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                return

            msg = data.decode()

            # Handle key rotation sync
            if msg.startswith("KEYUPDATE:"):
                new_key = msg.split(":", 1)[1].strip()
                CARBONIT_CHAT_KEY = new_key
                print(f"\n[🔑 KEYUPDATE RECEIVED] Session key updated securely.")
                continue

            # Normal encrypted message
            if not isinstance(CARBONIT_CHAT_KEY, str):
                # If chat key is missing or it isn't a string, we cannot call decrypt_message
                print("\n[DECRYPT ERROR] No valid chat key available; cannot decrypt message.")
                continue

            decrypted = decrypt_message(CARBONIT_CHAT_KEY, msg)
            if decrypted:
                print(f"\nPeer: {decrypted}")
            else:
                print("\n[DECRYPT ERROR] Could not decrypt message.")

        except Exception as e:
            print(f"[CONNECTION ERROR] {e}")
        finally:
            writer.close()
            await writer.wait_closed()


async def start_listener(host = "0.0.0.0", port=5050):
    server = await asyncio.start_server(handle_conn, "127.0.0.1", port)
    async with server:
        await server.serve_forever()

    print("------------------------------------------")
    print(f"[LISTENING] on {HOST}:{PORT} ...")
    print("------------------------------------------")


async def start_client(peer_onion, peer_port, priv_key, peer_pub_key):
    global CARBONIT_CHAT_KEY
    reader = None ; writer = None
    try:
        reader, writer = await aiohttp_socks.open_connection(
            proxy_host="127.0.0.1",
            proxy_port=9050,
            host=peer_onion,
            port = int(peer_port)
        )

        print(f"You: [CONNECTED TO PEER] {peer_onion}:{peer_port}")

        while True:
            msg = input("You: ")
            if msg.lower() == "exit":
                break

            check_rotation(priv_key, peer_pub_key)

            # make sure the chat key is available and valid before encrypting
            if CARBONIT_CHAT_KEY is None:
                # If chat key is missing, create it again
                CARBONIT_CHAT_KEY = derive_chat_key(priv_key, peer_pub_key)
                if CARBONIT_CHAT_KEY is None:
                    print("[ENCRYPT ERROR] No chat key available; message not sent.")
                    continue
                else:
                    print("[KEY INFO] Chat key derived for encryption.")

            encrypted = encrypt_message(CARBONIT_CHAT_KEY, msg)
            writer.write(encrypted.encode())
            await writer.drain()

    except Exception as e:
        print(f"[SEND ERROR] {e}")
    finally:
        if writer is not None and hasattr(writer, "close"):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# === MAIN ===
async def main():
    global USERNAME, CARBONIT_CHAT_KEY, PEER_PUB_KEY

    print("       CarbonIt Secure Messenger")
    print("==========================================\n")

    USERNAME = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    # Generate deterministic public key ID
    priv_key = hashlib.sha256((USERNAME + password).encode()).hexdigest()
    pub_key = hashlib.sha256(USERNAME.encode()).hexdigest()

    print("\nYour CarbonIt Public ID (Share this with your contact):")
    print("------------------------------------------")
    print(pub_key)
    print("------------------------------------------\n")

    PEER_PUB_KEY = input("Enter peer's public key (hashed username): ").strip()
    peer_onion = input("Enter peer's Onion address: ").strip()
    peer_port = input("Enter peer's port (default 5050): ").strip() or "5050"

    print("\nStarting CarbonIt node...")
    print("------------------------------------------")

    # Derive initial chat key
    CARBONIT_CHAT_KEY = derive_chat_key(priv_key, PEER_PUB_KEY)
    print("[KEY EXCHANGE] Secure handshake complete.")
    print(f"[KEY HASH] {hashlib.sha256(CARBONIT_CHAT_KEY.encode()).hexdigest()[:16]}...")
    print(f"[SESSION] Chat session established ✅")
    print(f"[TIME] {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("------------------------------------------")

    # Start background listener and auto key rotation monitor
    asyncio.create_task(start_listener())
    auto_rotation_monitor(priv_key, PEER_PUB_KEY)

    # Start client (send messages)
    await start_client(peer_onion, peer_port, priv_key, PEER_PUB_KEY)


if __name__ == "__main__":
    asyncio.run(main())
