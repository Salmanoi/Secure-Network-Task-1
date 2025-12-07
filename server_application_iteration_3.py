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
from cryptography.hazmat.primitives.asymmetric import rsa

#############################################################################
# Configuring Server IP, port, and the Buffer size #
SERVER_IP = '192.168.99.100' # --LOOPBACK-- DONT FORGET TO CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS
BUFFER_SIZE = 1024 # GETS DATA IN CHUNKS OF 1024 BYTES
LOG_FILE = "server.log"

####### Keys
server_private_key = "server_private_key.pem"
server_public_key = "server_public_key.pem"
#######

def key_existence():
	"""This function creates the RSA keys for the server if they aren't available"""
	if not os.path.exists(server_private_key) or not os.path.exists(server_public_key):
		print("One or both server keys are missing. Generating new RSA Pair...")

		# generating the server private key
		private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

		# saving the private key
		with open(server_private_key, "wb") as f:
			f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
		
		# saving the client public key
		with open(server_public_key, "wb") as f:
			f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
		print("Keys Generated.")
	else:
		print("Keys found.")


# logging section
logging.basicConfig(
	filename=LOG_FILE,
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	datefmt='%Y-%m-%d %H:%M:%S'
)

def key_loading():
	"""Loading RSA keys from .pem files"""
	key_existence()
	
	try:
		with open(server_private_key, "rb") as f:
			server_priv = serialization.load_pem_private_key(
				f.read(), password=None, backend=default_backend()
			)
		with open(server_public_key, "rb") as f:
			server_pub_bytes = f.read()

		return server_priv, server_pub_bytes
	except FileNotFoundError:
		print("Error: Key's not found, Run 'key-generation.py' first or again.")
		sys.exit(1)

def signature_verify(data, signature, public_key):
	"""Verifying the SHA-512 Signature"""
	if public_key is None: return False # if no key
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
	
def secure_file_store(data, filename, public_key):
	"""Uses RSA and AES to save to disk securely"""

	# step 1: generating temporary AES key for storage
	storage_aes_key = os.urandom(32)
	iv = os.urandom(16)

	# step 2: encrypt the file with AES
	cipher = Cipher(algorithms.AES(storage_aes_key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()
	encrypted_data = encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()

	# encrypts the AES key with servers rsa pub key
	encrypted_key = public_key.encrypt(
		storage_aes_key,
		asym_padding.OAEP(
			mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	# step 4: saving the file
	with open(filename, "wb") as f:
		f.write(encrypted_key + iv + encrypted_data)



class ClientThread(threading.Thread):
	def __init__(self, ip, port, client_socket, server_priv, server_pub_bytes):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.client_socket = client_socket
		self.server_priv = server_priv
		self.server_pub_bytes = server_pub_bytes
		self.client_pub = None
		connection_msg = f"Connected to client: {ip}:{port}"
		print(f"[+] {connection_msg}")
		logging.info(connection_msg)

	def run(self):
		try:
			# send the servers public key to client
			self.client_socket.sendall(self.server_pub_bytes)

			# get the client public key
			client_pub_pem = self.client_socket.recv(BUFFER_SIZE)
			self.client_pub = serialization.load_pem_public_key(client_pub_pem, backend=default_backend)
			print(f"Handshake Key Exchange with {self.ip} completed")



			full_data = b""
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

			# Step 6: Saving the data securely with server public key
				server_pub = self.server_priv.public_key()
				filename = f"Report_File_Port_{self.port}.enc"

				secure_file_store(decrypted_data, filename, server_pub)

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

				# this will reload the keys if the client key was added later
				if client_pub is None: _, client_pub = key_loading()

				ClientThread(ip, port, conn, server_priv, client_pub).start()


	except socket.error as e:
		print(f"Error Creating the following socket: {e}")
		logging.critical(f"Server Fail: {e}")
		sys.exit(1)

# This section is to decrypt the AES encryption of the message
def decrypt_aes(ciphertext, key, iv): 
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
	# Remove padding
	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
	return plaintext


# decrypts the report/log, this is required otherwise it will be deterministic
def decrypt_session(encrypted_key, private_key):
	"""RSA being used to decrypt AES session key"""
	return private_key.decrypt(
		encrypted_key,
		asym_padding.OAEP( # OAEP = Optimal Asym encryption padding, translated from pycryptodome to Cryptography
			mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)


if __name__ == "__main__":
    server_start()