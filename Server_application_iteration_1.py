import socket, sys

from datetime import datetime

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("The socket is created successfully")
server_ip='127.0.0.1'
server_port=1500

s.connect((server_ip,server_port))
incoming_message=s.recv(1000)
print("Message:",incoming_message)
print("Received at: ", str(datetime.now()))
s.close()

#test
