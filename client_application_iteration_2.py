import socket
import os
import time
import sys
import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# SERVER INFORMATION & KEYS # 
SERVER_IP = '127.0.0.1' # --LOOPBACK-- DONT FORGET TO CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS

server_public_key = "server_public_key.pem"
client_private_key = "client_private_key.pem"

def key_loading():
	"""Loading RSA keys from .pem files"""
	try:
		with open(client_private_key, "rb") as f:
			client_priv = serialization.load_pem_private_key(
				f.read(), password=None, backend=default_backend()
			)
		with open(server_public_key, "rb") as f:
			server_pub = serialization.load_pem_public_key(
				f.read(), backend=default_backend()
			)
		return client_priv, server_pub
	except FileNotFoundError:
		print("Error: Key's not found, Run 'key-generation.py' first or again.")
		sys.exit(1)




if __name__ == "__main__":
	client_send_file("example.txt", "127.0.0.1", 1500)