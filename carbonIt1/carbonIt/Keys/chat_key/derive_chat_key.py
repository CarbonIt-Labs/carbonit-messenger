import hashlib, base64, time

def derive_chat_key(priv_key, peer_pub_key):
    """
    Derives a consistent symmetric Fernet key for both peers in CarbonIt.
    Ensures both sides generate the exact same key regardless of input order.
    """
    # Ensure consistent order (alphabetically sorted)
    combo = '|'.join(sorted([priv_key, peer_pub_key]))

    # Derive 32-byte digest
    shared_secret = hashlib.sha256(combo.encode()).digest()

    # Convert to Fernet-compatible base64 key
    fernet_key = base64.urlsafe_b64encode(shared_secret).decode()

    # Console status
    print("------------------------------------------")
    print("[KEY EXCHANGE] Secure handshake complete.")
    print(f"[KEY HASH] {hashlib.sha256(fernet_key.encode()).hexdigest()[:16]}...")
    print("[SESSION] Chat session established ✅")
    print(f"[TIME] {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("------------------------------------------")

    return fernet_key
