import hashlib

def generate_keys(username,password):
    # Step 1: Public key derived from username
    public_key = hashlib.sha256(username.encode()).hexdigest()
    
    # Step 2: Private key derived from username + password
    private_key = hashlib.sha256((username + password).encode()).hexdigest()
    
    return private_key, public_key
