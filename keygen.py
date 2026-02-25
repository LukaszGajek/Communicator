import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

if not os.path.exists("private_key2.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key2.pem", "wb") as f:
        f.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key2.pem", "wb") as f:
        f.write(pem_public)

    print("keys created")
else:
    print("files alredy exist")
