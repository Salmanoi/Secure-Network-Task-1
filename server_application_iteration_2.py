import socket
import os
import sys
import threading
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configuring Server IP, port, and the Buffer size #
SERVER_IP = '127.0.0.1' # --LOOPBACK-- CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS
BUFFER_SIZE = 1024 # GETS DATA IN CHUNKS OF 1024 BYTES


# Generate AES key from a password (for demonstration)
def generate_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),
	length=32,  # AES-256 key length
	salt=salt,
	iterations=100000,
	backend=default_backend()
	)
	return kdf.derive(password.encode())
class ClientThread(threading.Thread):
	def __init__(self, ip, port, client_socket):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.client_socket = client_socket
		print(f"[+] Thread started for {ip}:{port}")

	def run(self):
		password = "%Pa55w0rd" # the password shared with the client
		full_data = b""

		try:
			# Step 1: this loop is here to recieve all the data in the 1024 buffer size amount
			while True:
				data = self.client_socket.recv(BUFFER_SIZE)
				if not data:
					break
				full_data += data

			# if no data is being received from the client, the connection will be closed
			if not full_data:
				return

			print(f"[{datetime.now().time()}] Data received from {self.ip}:{self.port}")

			# Step 2: Parses the salting, IV, and encrypted data
			salt = full_data[:16] # 0 to 16 bytes is the salting
			iv = full_data[16:32] # the IV is bytes 16 to 32
			encrypted_data = full_data[32:] # the rest of the encrypted data is bytes 32 and onwards

			# Step 3: Decrytion process
			key = generate_key(password, salt)
			decrypted_data = decrypt(encrypted_data, key, iv)

			# Step 4: Saving the data to a file based off port
			filename = f"received_file_{self.port}.txt"

			with open(filename, 'wb') as f:
				f.write(b"Encrypted Data:\n")
				f.write(encrypted_data)
				f.write(b"\n\nDecrypted Data:\n")
				f.write(decrypted_data) # lmao i forgot this line

			print(f"File saved as '{filename}")

		except Exception as e:
			print(f"Connection error with {self.ip}:{self.port} - {e}")

		finally:
			self.client_socket.close()

def server_start():
	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_socket.bind((SERVER_IP, SERVER_PORT)) # binds the server ip and port to the socket

		server_socket.listen(10) # can listen to 10 clients at the same time
		print(f"Server is listening on {SERVER_IP}:{SERVER_PORT}...")

		threads = []

		while True:
				(conn, (ip, port)) = server_socket.accept()

				new_thread = ClientThread(ip, port, conn)

				new_thread.start()
				threads.append(new_thread)

	except socket.error as e:
		print(f"Error Creating the following socket: {e}")
		sys.exit(1)


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
	# Remove padding
	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
	return plaintext

if __name__ == "__main__":
    server_start()