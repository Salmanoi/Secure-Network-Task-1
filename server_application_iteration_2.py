import socket
import os
import sys
import threading
from datetime import datetime
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
#############################################################################
# Configuring Server IP, port, and the Buffer size #
SERVER_IP = '127.0.0.1' # --LOOPBACK-- CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS
BUFFER_SIZE = 1024 # GETS DATA IN CHUNKS OF 1024 BYTES
LOG_FILE = "server.log"

####### Keys
server_private_key = "server_private_key.pem"
client_public_key = "client_public_key.pem"
#######

# logging section
logging.basicConfig(
	filename=LOG_FILE,
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	datefmt='%Y-%m-%d %H:%M:%S'
)

def signature_verify(data, signature, public_key):
	"""Verifying the SHA-512 Signature"""
	try:
		public_key.verify(
			signature,
			data,
			asym_padding.PKCS1v15(),
			hashes.SHA512()
		)
		return True
	except Exception:
		return False
	
def key_loading():
	"""Loading RSA keys from .pem files"""
	try:
		with open(server_private_key, "rb") as f:
			server_priv = serialization.load_pem_private_key(
				f.read(), password=None, backend=default_backend()
			)
		with open(client_public_key, "rb") as f:
			client_pub = serialization.load_pem_public_key(
				f.read(), backend=default_backend()
			)
		return server_priv, client_pub
	except FileNotFoundError:
		print("Error: Key's not found, Run 'key-generation.py' first or again.")
		sys.exit(1)
class ClientThread(threading.Thread):
	def __init__(self, ip, port, client_socket, server_priv, client_pub):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.client_socket = client_socket
		self.server_priv = server_priv
		self.client_pub = client_pub
		connection_msg = f"Connected to client: {ip}:{port}"
		print(f"[+] {connection_msg}")
		logging.info(connection_msg)

	def run(self):
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

			# step 2: get and prase the packet
			encrypted_session_key = full_data[:256]
			iv = full_data[256:272]
			signature = full_data[272:528]
			encrypted_file_data = full_data[528:]

			# step 3:decrypting the AES key with RSA
			aes_key = decrypt_session(encrypted_session_key, self.server_priv)

			# step 4: decrypt the file data using AES
			decrypted_data = decrypt_aes(encrypted_file_data, aes_key, iv)

			# step 5: signature verification
			if signature_verify(decrypted_data, signature, self.client_pub):
				verified_msg = f"{self.ip}:{self.port} is verified."
				print(f"[VERIFIED] {verified_msg}")
				logging.info(verified_msg)

			# Step 6: Saving the data to a file based off port
				filename = f"received_file_{self.port}.txt"
				with open(filename, 'wb') as f:

					f.write(decrypted_data) # lmao i forgot this line

				msg_saved = f"Log saved securely as {filename}"
				print(f"[SAVED] {msg_saved}")
				logging.info(msg_saved)
			else:
				msg_failed = f"Message integrity check failed for {self.ip}:{self.port}. Signature invalid"
				print(f"[WARNING] {msg_failed}")
				logging.warning(msg_failed)
		except Exception as e:
			msg_error = f"Error handling {self.ip}:{self.port} - {e}"
			print(f"[ERROR] {msg_error}")
			logging.error(msg_error)
		finally:
			self.client_socket.close()
			logging.info(f"Socket connection closed for client: {self.ip}:{self.port}")



def server_start():

	server_priv, client_pub = key_loading()
	try:
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_socket.bind((SERVER_IP, SERVER_PORT)) # binds the server ip and port to the socket

		server_socket.listen(10) # can listen to 10 clients at the same time
		msg_server_start = f"Server is listening on {SERVER_IP}:{SERVER_PORT}..."
		print(f"{msg_server_start}")
		logging.info(f"System Started: {msg_server_start}")		

		threads = []

		while True:
				(conn, (ip, port)) = server_socket.accept()

				new_thread = ClientThread(ip, port, conn, server_priv, client_pub)
				new_thread.start()
				threads.append(new_thread)

	except socket.error as e:
		print(f"Error Creating the following socket: {e}")
		logging.critical(f"Server Fail: {e}")
		sys.exit(1)


def decrypt_aes(ciphertext, key, iv): 
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
	# Remove padding
	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
	return plaintext

def decrypt_session(encrypted_key, private_key):
	"""RSA being used to decrypt AES session key"""
	return private_key.decrypt(
		encrypted_key,
		asym_padding.OAEP(
			mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)


if __name__ == "__main__":
    server_start()