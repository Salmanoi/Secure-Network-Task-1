import socket, sys
from datetime import datetime

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_ip='127.0.0.1'
server_port=1500

s.bind((server_ip,server_port))
s.listen(10)
while True:
        csc, address=s.accept()
        print("Connected from",address)
        print("Message sent at:",str(datetime.now()))
        csc.send("Thank you for coneccting, this is the server")

s.close()