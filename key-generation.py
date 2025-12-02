import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_key_pair(name):
    print(f"[*] Generating 2048-bit RSA Key Pair for {name}...")
    
    # 1. Generate Private Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Serialize Private Key (PEM format)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 3. Generate Public Key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 4. Save to files (Using the names your Server/Client expects)
    priv_filename = f"{name}_private_key.pem"
    pub_filename = f"{name}_public_key.pem"
    
    with open(priv_filename, "wb") as f:
        f.write(pem_private)
    print(f"    [+] Saved: {priv_filename}")
    
    with open(pub_filename, "wb") as f:
        f.write(pem_public)
    print(f"    [+] Saved: {pub_filename}")

if __name__ == "__main__":
    print("--- STARTING KEY GENERATION ---")
    
    # Generate Server Keys
    generate_key_pair("server")
    
    # Generate Client Keys
    generate_key_pair("client")
    
    print("--- KEYS GENERATED SUCCESSFULLY ---")