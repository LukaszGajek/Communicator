import socket
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
import base64
from enum import StrEnum
import threading
import queue
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

class Role(StrEnum):
    HOST = 'host'
    CLIENT = 'client'

# Chcielibysmy miec obsluge wylaczenia programu w latwy sposob - jak?
# Trzeba dodac ograniczenie na liczbe bajtow w wiadomosci - ?
# Trzeba tez fixnac Address already in use - jak?


parser = argparse.ArgumentParser()
parser.add_argument("-r", "--role", choices=Role, default = "host", help = "host or a client")
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

program_exited = False
session = PromptSession()
messages = queue.Queue()

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


def send_text(s, pub_key, label, session):
    try:
        text = session.prompt(f"{label}: ")
    
        message = text.encode("utf-8")
        encrypted_b64 = encrypt(pub_key, message)
        s.send(len(encrypted_b64).to_bytes(4,"big"))
        s.send(encrypted_b64)
        if text == "quit":
            return True
    except:
        return True
    return False
        

def rcv_text(s, private_key, messages: queue.Queue):
    try :
        length_bytes = s.recv(4)
        length = int.from_bytes(length_bytes,"big")
        encrypted_b64 = s.recv(length)
        decrypted = decrypt(private_key, encrypted_b64).decode('utf-8')
        if decrypted == 'quit':
            return True
        messages.put(decrypted)
    except:
        pass
    return False


def receive_loop(s, private_key, messages: queue.Queue):
    global program_exited, session
    while True:
        exited = rcv_text(s, private_key, messages)
        if exited or program_exited:
            program_exited = True
            if session.app.is_running:
                session.app.exit()
            break

def send_loop(s, public_key, my_label, session):
    global program_exited 
    with patch_stdout():
        while True: 
            exited = send_text(s, public_key, my_label, session)
            if exited or program_exited:
                program_exited = True
                break
        
def print_loop(messages: queue.Queue, label):
# Dobrze by bylo tutaj sleepa zrobic bo sie kreci w kolko, albo zrobic get_wait() nawet bez try-except 
    global program_exited
    while True:
        if program_exited:
            break
        try:
            text = messages.get_nowait()
            print(f"{label}: ", text)
        except queue.Empty:
            pass
            
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
    c.settimeout(0.5)
    
    client_public = exchange_keys(c, pub_pem_bytes)
    
    rcv_task = threading.Thread(target=receive_loop, args=(c, private_key, messages))
    send_task = threading.Thread(target=send_loop, args=(c, client_public, "Host", session))
    print_task  = threading.Thread(target=print_loop, args=(messages, "Client"))
    rcv_task.start()
    send_task.start()
    print_task.start()

    rcv_task.join()
    send_task.join()
    print_task.join()
    c.close()

elif args.role == Role.CLIENT:
    port = int(args.port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        s.connect((args.address, port))
        print(f"connected to: {args.address}")

        host_public = exchange_keys(s, pub_pem_bytes)
        
        rcv_task = threading.Thread(target=receive_loop, args=(s, private_key, messages))
        send_task = threading.Thread(target=send_loop, args=(s, host_public, "Client", session))
        print_task  = threading.Thread(target=print_loop, args=(messages, "Host"))
        rcv_task.start()
        send_task.start()
        print_task.start()

        rcv_task.join()
        send_task.join()
        print_task.join()
        s.close()
        

exit(0)
            
            
            
            


    
