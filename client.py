import socket


port = 8001
host = "192.168.31.134"
#host = '127.0.0.1'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host,port))
    while True:
        d = s.recv(1024)
        print("received message: ",d.decode())
        if d.decode() == "user disconnected":
            s.close
            break