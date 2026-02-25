import socket
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
import base64
from enum import StrEnum
import threading

class Role(StrEnum):
    HOST = 'host'
    CLIENT = 'client'


parser = argparse.ArgumentParser()
parser.add_argument("-r", "--role", choices=Role, required=True, help = "host or a client")
parser.add_argument("-p", "--port", default = 8001, help = "select a port to connect to")
parser.add_argument("-a", "--address", default="127.0.0.1", help = "select ip adress to connect to")
parser.add_argument("-pub", "--own_public_key", default="public_key.pem", help = "path to your public key")
parser.add_argument("-priv", "--own_private_key", default="private_key.pem", help = "path to your private key")
args = parser.parse_args()


with open(args.own_public_key, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
    
with open(args.own_private_key, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

pub_pem_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def encrypt(pub_key, data): 
     encrypted = pub_key.encrypt(
         data,
         padding.OAEP(
             mgf = padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
         )
     )
     encrypted_b64 = base64.b64encode(encrypted)
     return encrypted_b64


def decrypt(private_key, data):
     encrypted = base64.b64decode(data)
     decrypted = private_key.decrypt(
         encrypted,
         padding.OAEP(
             mgf = padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
         )
     )
     return decrypted


def send_pub_key(c, pub_pem_bytes):
    c.send(len(pub_pem_bytes).to_bytes(4,'big'))
    c.send(pub_pem_bytes)


def rcv_pub_key(c, pub_pem_bytes):
    length_bytes = c.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    client_pub_pem = c.recv(length)
    client_public = serialization.load_pem_public_key(client_pub_pem)
    return client_public


def exchange_keys(c, pub_pem_bytes):
    send_pub_key(c, pub_pem_bytes)
    client_public = rcv_pub_key(c, pub_pem_bytes)
    return client_public


def send_text(s, pub_key, label):
    text = input(f"{label}: ")
    message = text.encode("utf-8")
    
    if message == "quit":
        s.send("user disconnected".encode())
        s.close()
        exit(0)
    
    encrypted_b64 = encrypt(pub_key, message)
    s.send(len(encrypted_b64).to_bytes(4,"big"))
    s.send(encrypted_b64)


def rcv_text(s, private_key, label):
    length_bytes = s.recv(4)
    length = int.from_bytes(length_bytes,"big")
    encrypted_b64 = s.recv(length)
    decrypted = decrypt(private_key, encrypted_b64)
    print(f"{label}: ", decrypted.decode("utf-8"))


def receive_loop(s, private_key, friend_label):
    while True:
        rcv_text(s, private_key, friend_label)

def send_loop(s, public_key, my_label):
    while True:
        send_text(s, public_key, my_label)

if args.role == Role.HOST:
    s = socket.socket()
    print('socket created')
    port = int(args.port)
    s.bind(('', port))
    print(f"port:{[port]}")
    s.listen(5)
    print('listening')
    c, addr = s.accept()
    print(f"{addr} connected")
    
    client_public = exchange_keys(c, pub_pem_bytes)
    
    rcv_task = threading.Thread(target=receive_loop, args=(c, private_key, "Client"))
    send_task = threading.Thread(target=send_loop, args=(c, client_public, "Host"))
    rcv_task.start()
    send_task.start()

    rcv_task.join()
    send_task.join()

elif args.role == Role.CLIENT:
    port = int(args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.address, port))
        print(f"connected to: {args.address}")

        host_public = exchange_keys(s, pub_pem_bytes)
        
        rcv_task = threading.Thread(target=receive_loop, args=(s, private_key, "Host"))
        send_task = threading.Thread(target=send_loop, args=(s, host_public, "Client"))
        rcv_task.start()
        send_task.start()

        rcv_task.join()
        send_task.join()
            
            
            
            


    
