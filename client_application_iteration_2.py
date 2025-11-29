import socket
import os


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt(plaintext: bytes, key: bytes) -> (bytes, bytes):
	iv = os.urandom(16)  # Initialization vector (IV)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	
def generate_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(
	algorithm=hashes.SHA512(),
	length=32,  # AES-256 key length
	salt=salt,
	iterations=100000,
	backend=default_backend()
	)
	return kdf.derive(password.encode())

def client_send_file(file_path, server_ip, server_port):
	password = "1234567890"  # Key will be derived from this password
	salt = os.urandom(16)  # Random salt for key derivation
	# Read file
	with open(file_path, 'rb') as f:
		file_data = f.read()
	
	
	# Derive AES key and encrypt the file content
	key = generate_key(password, salt)
	iv, encrypted_data = encrypt(file_data, key)

	# Create a socket connection to the server
	client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	#with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
	client_socket.connect((server_ip, server_port))
	# Send the salt and IV (16 bytes each), followed by the encrypted data
	client_socket.sendall(salt + iv + encrypted_data)
	#print("Encrypted Data:",encrypted_data)
	print("File sent successfully!")

if __name__ == "__main__":
	client_send_file("example.txt", "127.0.0.1", 1500)