import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# CONFIGURATION
SERVER_PRIVATE_KEY_PATH = "server_private_key.pem"

def load_private_key():
    """Loads the Server's Private Key to unlock the file."""
    if not os.path.exists(SERVER_PRIVATE_KEY_PATH):
        print(f"[!] Error: '{SERVER_PRIVATE_KEY_PATH}' not found.")
        sys.exit(1)
        
    with open(SERVER_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

def decrypt_storage(filename):
    print(f"[*] Attempting to decrypt: {filename}")
    
    # 1. Load the Master Key (Server Private Key)
    private_key = load_private_key()
    
    try:
        with open(filename, "rb") as f:
            full_data = f.read()
            
        # 2. Parse the File Structure
        # [RSA Encrypted AES Key (256 bytes)] + [IV (16 bytes)] + [Encrypted Data (Rest)]
        if len(full_data) < 272:
            print("[!] Error: File is too small to be a valid encrypted log.")
            return

        encrypted_aes_key = full_data[:256]
        iv = full_data[256:272]
        encrypted_content = full_data[272:]
        
        # 3. Decrypt the AES Key using RSA Private Key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Decrypt the Content using AES Key
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # 5. Remove Padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        # 6. Display Content
        print("\n--- DECRYPTED LOG CONTENT ---")
        print(plaintext.decode('utf-8', errors='ignore'))
        print("-----------------------------\n")
        
        # Optional: Save it as a readable text file
        decrypted_filename = filename.replace(".enc", ".readable.txt")
        with open(decrypted_filename, "wb") as f:
            f.write(plaintext)
        print(f"[+] Saved readable copy to: {decrypted_filename}")

    except Exception as e:
        print(f"[!] Decryption Failed: {e}")

if __name__ == "__main__":
    # Ask user which file to open
    target_file = input("Enter the filename to decrypt (e.g., received_report_54321.enc): ")
    
    if os.path.exists(target_file):
        decrypt_storage(target_file)
    else:
        print("[!] File not found.")