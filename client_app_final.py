import socket
import os
import time
import sys
import datetime
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

# Automated Scheduler for automated log sending
SCHEDULED_TIME_HOUR = 17 # 5PM/17:00
SCHEDULED_TIME_MINUTE = 00 # 5PM/17:00
monitor_interval = 30 # this is in seconds

# SERVER INFORMATION & KEYS # 
SERVER_IP = '192.168.99.100' 
SERVER_PORT = 1500 

client_private_key = "client_private_key.pem"
client_public_key = "client_public_key.pem"

def key_existence():
    """This function creates the RSA keys for the client if they aren't available"""
    if not os.path.exists(client_private_key) or not os.path.exists(client_public_key):
        print("One or both client keys are missing. Generating new RSA Pair...")

        # generating the client private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # saving the private key
        with open(client_private_key, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # saving the client public key
        with open(client_public_key, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Keys Generated.")
    else:
        print("Keys found.")

def load_client_keys():
    """Loads Client Private Key (Obj) and Client Public Key (Bytes)"""
    key_existence()
    try:
        with open(client_private_key, "rb") as f:
            client_priv = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        # We need to send the RAW bytes of our public key to the server
        with open(client_public_key, "rb") as f:
            client_pub_bytes = f.read()
            
        return client_priv, client_pub_bytes
    except Exception as e:
        print(f"Error loading keys: {e}")
        sys.exit(1)

# data encryption & padding
def aes_encrypt(file_data, aes_key):
    """Encrypting the data with AES-256-CBC"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_data

def encrypt_session(aes_key, server_public_key):
    """encrypting aes session using RSA-OAEP"""
    return server_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_auth_sha512(data, client_private_key):
    """Creating a signature with SHA-512"""
    return client_private_key.sign(
        data,
        asym_padding.PKCS1v15(),
        hashes.SHA512()
    )

def get_hash(filepath):
    """This function is used to detect changes to the SHA-512 hash of the file"""
    sha = hashlib.sha512()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data: break
                sha.update(data)
        return sha.hexdigest()
    except: return None

def report_sending(file_path):
    print(f"Creating report: {file_path}")

    # Load Client Keys
    client_priv, client_pub_bytes = load_client_keys()

    # Read the data
    try:
        with open(file_path, 'rb') as f:
            original_data = f.read()
    except FileNotFoundError:
        print(f"Error, The file: '{file_path}' was not found.")
        return
    
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to {SERVER_IP}...")
            s.connect((SERVER_IP, SERVER_PORT))

            #######################
            # 1. Receive Server Public Key
            server_pub_pem = s.recv(2048)
            server_pub = serialization.load_pem_public_key(server_pub_pem, backend=default_backend())
            
            # 2. Send Client Public Key
            s.sendall(client_pub_bytes)
            #######################

            # Encryption
            aes_key = os.urandom(32)
            start_time = time.time()

            iv, encrypted_data = aes_encrypt(original_data, aes_key)
            encrypted_key = encrypt_session(aes_key, server_pub)
            signature = sign_auth_sha512(original_data, client_priv)

            # Construct Payload
            payload = encrypted_key + iv + signature + encrypted_data
            s.sendall(payload)

            end_time = time.time()

            # Metrics
            duration = end_time - start_time
            if duration == 0: duration = 0.0001 

            file_size_bits = len(original_data) * 8
            throughput = file_size_bits / (duration * 1_000_000)
            file_hash = get_hash(file_path)

            print("[SUCCESS] Report/Log Sent!")
            print(f"    - Transfer Time: {duration:.4f} seconds")
            print(f"    - Throughput: {throughput:.2f} Mbps")
            print(f"    - File Hash: {file_hash}")

    except Exception as e:
        print(f"Send failed: {e}")

def start_scheduler_monitor(target_file):
    print(f"Scheduler, monitor and automatic sender started")
    print(f"Checking for file hash changes every {monitor_interval} seconds")
    print(f"Waiting for {SCHEDULED_TIME_HOUR:02d}:{SCHEDULED_TIME_MINUTE:02d} to send the log..")

    last_hash = get_hash(target_file)
    last_sent_day = -1
    if last_hash:
        print(f"The last file hash: {last_hash[:10]}...")

    try:
        while True:
            # 1. Check for file integrity (Hash Change)
            current_hash = get_hash(target_file)
            if current_hash != last_hash:
                print("\n[!] The Log file has changed! Sending report to server...")
                report_sending(target_file)
                last_hash = current_hash

            # 2. Check for Schedule (Time Trigger)
            now = datetime.datetime.now()
            if (now.hour == SCHEDULED_TIME_HOUR and
                now.minute == SCHEDULED_TIME_MINUTE and
                now.day != last_sent_day):
                
                print(f"\n[!] It is {SCHEDULED_TIME_HOUR:02d}:{SCHEDULED_TIME_MINUTE:02d}, sending the log... ")
                report_sending(target_file)
                last_sent_day = now.day
                print("Waiting for the next automated send...")

            time.sleep(monitor_interval)
    
    except KeyboardInterrupt:
        print("\n Automated sending interrupted by user.")

if __name__ == "__main__":
    user_home = os.path.expanduser("~")

    linux_log = "/var/log/auth.log"
    windows_log = os.path.join(user_home, "Desktop", "daily_system.log") 

    if os.path.exists(linux_log): target_file = linux_log
    elif os.path.exists(windows_log): target_file = windows_log
    else: target_file = os.path.join(user_home, "Desktop", "example.txt")

    print("---Bletchley Park SRS client---")
    print(f"Target log file: {target_file}")
    print("1. Manual Report sending")
    print(f"2. Automated report sending at {SCHEDULED_TIME_HOUR:02d}:{SCHEDULED_TIME_MINUTE:02d} or upon file modification")

    choice = input("Please choose 1/2: ")

    if choice == "1":
        if os.path.exists(target_file):
            report_sending(target_file)
        else:
            print(f"Error: The File {target_file} doesn't exist")
    elif choice == "2":
        start_scheduler_monitor(target_file)
    else:
        print("Invalid choice")