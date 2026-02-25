import socket
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
import base64

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--role", required = True, help = "host or a client")
parser.add_argument("-p", "--port", default = 8001, help = "select a port to connect to")
parser.add_argument("-a", "--address", default = "127.0.0.1", help = "select ip adress to connect to")
parser.add_argument("-pub", "--own_public_key", default = "C:/Szkola/Informatyka/klucze/private_key.pem", help = "path to your public key")
parser.add_argument("-priv", "--own_private_key", default = "C:/Szkola/Informatyka/klucze/private_key.pem", help = "path to your private key")
args = parser.parse_args()


with open(args.own_public_key, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
    
with open(args.own_private_key, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


pub_pem_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

if args.role == "h":
    s = socket.socket()
    print('socket created')
    port = int(args.port)
    s.bind(('', port))
    print(f"port:{[port]}")
    s.listen(5)
    print('listening')
    c, addr = s.accept()
    print(f"{addr} connected")
    #c.send("connected".encode())
    
    c.send(len(pub_pem_bytes).to_bytes(4,'big'))
    c.send(pub_pem_bytes)
    
    length_bytes = c.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    client_pub_pem = c.recv(length)
    client_public = serialization.load_pem_public_key(client_pub_pem)
    
    
    while True:
        length_bytes = c.recv(4)
        length = int.from_bytes(length_bytes,"big")
        encrypted_b64 = c.recv(length)
        encrypted = base64.b64decode(encrypted_b64)
        print("dlugosc:", len(encrypted))
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("Client:", decrypted.decode("utf-8"))
        
        
        text = input("Host:")
        message = text.encode("utf-8")
        
        encrypted = client_public.encrypt(
            message,
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_b64 = base64.b64encode(encrypted)

        
        if message == "quit":
            c.send("user disconnected".encode())
            c.close()
            break
        c.send(len(encrypted_b64).to_bytes(4,"big"))
        c.send(encrypted_b64)


elif args.role == "c":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.address, args.port))
        print(f"connected to: {args.address}")
        
        s.send(len(pub_pem_bytes).to_bytes(4,'big'))
        s.send(pub_pem_bytes)
        
        length_bytes = s.recv(4)
        length = int.from_bytes(length_bytes, 'big')
        host_pub_pem = s.recv(length)
        host_public = serialization.load_pem_public_key(host_pub_pem)
        
        
        while True:
            text = input("Client:")
            message = text.encode("utf-8")
            
            encrypted = host_public.encrypt(
                message,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_b64 = base64.b64encode(encrypted)

            
            if message == "quit":
                s.send("user disconnected".encode())
                s.close()
                break
            s.send(len(encrypted_b64).to_bytes(4,"big"))
            s.send(encrypted_b64)
            
            
            length_bytes = s.recv(4)
            length = int.from_bytes(length_bytes,"big")
            encrypted_b64 = s.recv(length)
            encrypted = base64.b64decode(encrypted_b64)
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf = padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Host:", decrypted.decode("utf-8"))
            
            
            
            


    