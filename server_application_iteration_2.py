import socket
import os
import sys
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuring Server IP, port, and the Buffer size #
SERVER_IP = '127.0.0.1' # --LOOPBACK-- CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS
BUFFER_SIZE = 1024 # GETS DATA IN CHUNKS OF 1024 BYTES

class ClientThread(threading.Thread):
	def __init__(self, ip, port, client_socket):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.client_socket - client_socket
		print(f"[+] Thread started for {ip}:{port}")

	def run(self):
		password = "%Pa55w0rd" # the password shared with the client
		full_data = b""

		try:
			# this loop is here to recieve all the data in the 1024 buffer size amount
			while True:
				

# Generate AES key from a password (for demonstration)
def generate_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),
	length=32,  # AES-256 key length
	salt=salt,
	iterations=100000,
	backend=default_backend()
	)
	return kdf.derive(password.encode())

def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
	# Remove padding
	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
	return plaintext

def server_receive_file(save_path, server_ip, server_port):
	password = "%Pa55w0rd"  # Must match the client's password
	# Create a socket to listen for incoming connections
	server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind((server_ip, server_port))
	server_socket.listen(1)
	print("Server is listening for incoming connections...")
	conn, addr = server_socket.accept()
	with conn:
		print("Connection from",addr)
		# Receive data (salt + iv + encrypted_data)
		data = conn.recv(1024)
		full_data = data
		# Receive remaining parts of the file (in case it’s large)
		while data:
			data = conn.recv(1024)
			full_data += data
		# First 16 bytes are salt, next 16 bytes are IV, remaining is encrypted data
		salt = full_data[:16]
		iv = full_data[16:32]
		encrypted_data = full_data[32:]
		# Derive the same AES key and decrypt the file
		key = generate_key(password, salt)
		#print("The AES key",key)
		#print("Encrypted Data:",encrypted_data)
		decrypted_data = decrypt(encrypted_data, key, iv)
		# Save the decrypted content to a file
	       	
		with open(save_path, 'wb') as f:
			f.write(b"Encrypted DATA:")
			f.write(encrypted_data)
			f.write(b"Decrypted DATA:")
			f.write(decrypted_data)

		print("File received and decrypted successfully!")

if __name__ == "__main__":
    server_receive_file("received_textfile.txt", "127.0.0.1", 1500)