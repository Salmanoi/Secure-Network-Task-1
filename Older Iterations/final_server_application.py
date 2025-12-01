import socket
import threading
import os

# Import PyCryptodome libraries
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# Configuration
TCP_IP = '0.0.0.0' # Listen on all interfaces
TCP_PORT = 65432   # Port to listen on
BUFFER_SIZE = 1024

# --- HELPER FUNCTIONS (Crypto Logic) ---

def decrypt_aes_key(private_key, encrypted_aes_key):
    # Decrypt the session key using RSA and SHA-512
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def decrypt_file_aes(aes_key, encrypted_file_data, tag, nonce):
    # Decrypt the data using AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_file_data = cipher_aes.decrypt_and_verify(encrypted_file_data, tag)
    return decrypted_file_data

def verify_signature(public_key, file_data, signature):
    # Verify integrity using SHA-512
    hash_obj = SHA512.new(file_data)
    verifier = PKCS1_v1_5.new(public_key)
    return verifier.verify(hash_obj, signature)

# --- THREADING LOGIC ---

class ClientThread(threading.Thread):

    def __init__(self, ip, port, sock):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.sock = sock
        print(" New thread started for " + ip + ":" + str(port))

    def run(self):
        # 1. Alias self.sock to conn so your pasted logic works
        conn = self.sock
        
        try:
            # 2. Receive the encrypted AES key
            encrypted_aes_key = conn.recv(256)
            if not encrypted_aes_key: return 
            
            print("...................................")
            print("Encrypted AES key received.")
            
            # 3. Receive the length of the encrypted file
            file_size_bytes = conn.recv(4)
            if not file_size_bytes: return
            file_size = int.from_bytes(file_size_bytes, byteorder='big')

            # 4. Receive the encrypted file data
            encrypted_file_data = b''
            while len(encrypted_file_data) < file_size:
                packet = conn.recv(file_size - len(encrypted_file_data))
                if not packet: break
                encrypted_file_data += packet
            
            print("Encrypted file data received.")

            # 5. Receive Tag, Nonce, and Signature
            tag = conn.recv(16)
            nonce = conn.recv(16)
            signature = conn.recv(256)
            
            print("Tag, Nonce, and Signature received.")

            # --- DECRYPTION START ---

            # Load Server Private Key
            with open("server_private.pem", "rb") as key_file:
                server_private_key = RSA.import_key(key_file.read())

            # Decrypt AES Key
            aes_key = decrypt_aes_key(server_private_key, encrypted_aes_key)
            print("AES key decrypted.")

            # Decrypt File Data
            decrypted_file_data = decrypt_file_aes(aes_key, encrypted_file_data, tag, nonce)
            print("File decrypted successfully.")

            # Save the file (Unique name to prevent overwriting)
            filename = f"log_{self.ip}.txt"
            with open(filename, "wb") as f:
                f.write(decrypted_file_data)
            print(f"File saved as '{filename}'.")

            # --- VERIFICATION START ---

            # Load Client Public Key
            with open("client_public.pem", "rb") as key_file:
                client_public_key = RSA.import_key(key_file.read())

            # Verify Signature
            if verify_signature(client_public_key, decrypted_file_data, signature):
                print("[SUCCESS] Signature is VALID.")
            else:
                print("[ALERT] Signature is INVALID!")
            print("...................................")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

# --- MAIN EXECUTION LOOP ---

if __name__ == "__main__":
    # Create Socket
    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind((TCP_IP, TCP_PORT))
    
    print(f"Server listening on port {TCP_PORT}...")
    
    while True:
        tcpsock.listen(5)
        (conn, (ip, port)) = tcpsock.accept()
        
        # Create and start a new thread for this client
        newthread = ClientThread(ip, port, conn)
        newthread.start()