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
monitor_interval = 900 # this is in seconds

# SERVER INFORMATION & KEYS # 
SERVER_IP = '127.0.0.1' # --LOOPBACK-- DONT FORGET TO CHANGE THIS FOR THE CONFIGURATION OF DEMONSTRATION
SERVER_PORT = 1500 # WILL KEEP AS 1500 ALWAYS

server_public_key = "server_public_key.pem"
client_private_key = "client_private_key.pem"
client_public_key = "client_public_key.pem"

def key_existence():
	"""This function creates the RSA keys for the server if they aren't available"""
	if not os.path.exists(client_private_key) or not os.path.exists(server_public_key):
		print("One or both server keys are missing. Generating new RSA Pair...")

		# generating the server private key
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

# loads up the keys from the pem files, client priv and server pub
def key_loading():
	"""Loading RSA keys from .pem files"""
	key_existence()

	try:
		with open(client_private_key, "rb") as f:
			client_priv = serialization.load_pem_private_key(
				f.read(), password=None, backend=default_backend()
			)
		if not os.path.exists(server_public_key):
			print(f"[!] Error: '{server_public_key}' not found.")
			print("Please run the Server first to generate its keys.")
			sys.exit(1)

		with open(server_public_key, "rb") as f:
			server_pub = serialization.load_pem_public_key(
				f.read(), backend=default_backend()
			)
		return client_priv, server_pub
	except FileNotFoundError:
		print("Error: Key's not found, Run 'key-generation.py' first or again.")
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
	"""encrypting aes session using RSA-OAEP, OAEP labeled & referenced in Line 172 in server code"""
	return server_public_key.encrypt(
		aes_key,
		asym_padding.OAEP(
			mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

# creating the sha-512 signature 
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

	# step 1: loading the keys
	client_priv, server_pub = key_loading()

	# step 2: reading the data in the file
	try:
		with open(file_path, 'rb') as f:
			original_data = f.read()
	except FileNotFoundError:
		print(f"Error, The file: '{file_path}' was not found.")
		return
	
	# step 3: create an aes 256 session key
	aes_session = os.urandom(32)

	# step 4: time the cryptography functions and operations
	start_time = time.time()

	# step 5: encrypt the data with aes
	iv, encrypted_file_data = aes_encrypt(original_data, aes_session)

	# step 6: encrypting the session key with rsa
	rsa_encrypted_session = encrypt_session(aes_session, server_pub)

	# step 7: sign the data to ensure integrity
	signature = sign_auth_sha512(original_data, client_priv)

	# step 8: the final data payload with AES & RSA
	payload = rsa_encrypted_session + iv + signature + encrypted_file_data

	# step 9: connection and network stuff
	try: 
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.connect((SERVER_IP, SERVER_PORT))
			s.sendall(payload)

			end_time = time.time()

			# calculate the metrics required
			duration = end_time - start_time
			if duration == 0: duration = 0.0001 # this is to prevent diving by zero, pointed out by Google Gemini 

			# the throughput is in Mbps
			file_size_bits = len(original_data) * 8
			throughput = file_size_bits / (duration * 1_000_000)

			print("Report/Log Sent!")
			print(f"Transfer Time: {duration:.4f} seconds")
			print(f"Throughput: {throughput:.2f} Mbps")

	except ConnectionRefusedError:
		print("Connection Refused. Please check if the server is running")

def start_scheduler_monitor(target_file):
	print(f"Scheduler, monitor and automatic sender started")
	print(f"Checking for file hash changes every {monitor_interval} seconds")
	print(f"Waiting for {SCHEDULED_TIME_HOUR:02d}:{SCHEDULED_TIME_MINUTE:02d} to send the log..")

	last_hash = get_hash(target_file)
	last_sent_day = -1
	print(f"The last file hash: {last_hash[:10]}")

	try:
		while True:
			# this check for file integrity
			current_hash = get_hash(target_file)
			if current_hash != last_hash:
				print("The Log file has changed, sending report to server.")
				report_sending(target_file)
				last_hash = current_hash

			# this check if its the specified time
			now = datetime.datetime.now()
			if (now.hour == SCHEDULED_TIME_HOUR and
	   			now.minute == SCHEDULED_TIME_MINUTE and
				now.day != last_sent_day):
				
				print(f"\n It is {SCHEDULED_TIME_HOUR}:{SCHEDULED_TIME_MINUTE}, sending the log... ")
				report_sending(target_file)
				last_sent_day = now.day
				print("Waiting for the next automated send...")

			time.sleep(monitor_interval)
	
	except KeyboardInterrupt:
		print("\n Automated sending interrupted by user.")


if __name__ == "__main__":
	user_home = os.path.expanduser("~")

	linux_log = "/var/log/syslog"
	windows_log = os.path.join(user_home, "Desktop", "daily_system.log") # only for windows and testing

	if os.path.exists(linux_log):
		target_file = linux_log
	elif os.path.exists(windows_log):
		target_file = windows_log
	else:
		target_file = os.path.join(user_home, "Desktop", "example.txt") #fallback for windows testing if it doesnt work further

	# we need to allow the user to choose between automated sending or manual
	print("---Bletchley Park SRS client---")
	print(f"Target log file: {target_file}")
	print("1. Manual Report sending")
	print(f"2. Automated report sending at {SCHEDULED_TIME_HOUR}:{SCHEDULED_TIME_MINUTE} or upon file modification")

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
	