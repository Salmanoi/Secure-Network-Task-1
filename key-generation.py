from Crypto.PublicKey import RSA

# Generate keys for the client
client_key = RSA.generate(2048)
client_private_key = client_key.export_key()
client_public_key = client_key.publickey().export_key()

# Write the client's private key to a file
with open("client_private_key.pem", "wb") as f:
    f.write(client_private_key)

# Write the client's public key to a file
with open("client_public_key.pem", "wb") as f:
    f.write(client_public_key)

# Generate keys for the server
server_key = RSA.generate(2048)
server_private_key = server_key.export_key()
server_public_key = server_key.publickey().export_key()

# Write the server's private key to a file
with open("server_private_key.pem", "wb") as f:
    f.write(server_private_key)

# Write the server's public key to a file
with open("server_public_key.pem", "wb") as f:
    f.write(server_public_key)

print("Client and server RSA key pairs have been generated.")

