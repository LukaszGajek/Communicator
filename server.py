import socket
import sys

s = socket.socket()
print('socket created')
port = 8001

s.bind(('',port))
print(f"port:{[port]}")
s.listen(5)
print('listening')
c, addr = s.accept()
print(f"{addr} connected")
c.send("connected".encode())
while True:
    message = input()
    if message == "quit":
        c.send("user disconnected".encode())
        c.close()
        break
    c.send(message.encode())
    