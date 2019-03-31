#!/usr/bin/env python3
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from multiprocessing.connection import Listener
from multiprocessing.connection import Client
import threading
import random
import queue
import os
import time

def main():
    username = input("Enter username: ")
    try:
        key = load_key(username)
    except:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
        save_key(key,username)

    public_key = key.public_key()
    address = ('localhost', 6000)
    conn = Client(address, authkey=b'secret password')
    port = random.randint(6001,7000)
    #conn.send(["testing","two"])
    conn.send([
        username,
        port,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )])
    conn.close()

    group_address = ('localhost', port)     # family is deduced to be 'AF_INET'
    group_listener = Listener(group_address, authkey=b'secret password')
    group_conn = group_listener.accept()

    encryptedKey = b"error"
    try:
        encryptedKey = group_conn.recv()
    except:
        pass
    group_conn.close()

    symkey = key.decrypt(
        encryptedKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #time.sleep(10)
    while(True):
        try:
            filename = input("Enter filename: ")
            f = Fernet(symkey)
            with open (os.path.join("groupFiles",filename),'rb') as decryptfile:
                encoded = decryptfile.read()
                
            #print(encoded)  
            unencoded = f.decrypt(encoded)
            print(unencoded)
        except:
            conn = Client(address, authkey=b'secret password')
            conn.send([
                username,
                port,
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ])
            conn.close()
            group_conn = group_listener.accept()
            try:
                encryptedKey = group_conn.recv()
            except:
                pass
            symkey = key.decrypt(
                encryptedKey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            f = Fernet(symkey)
            with open (os.path.join("groupFiles",filename),'rb') as decryptfile:
                encoded = decryptfile.read()
                
            #print(encoded)  
            unencoded = f.decrypt(encoded)
            print(unencoded)

def save_key(key, filename):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join("clients",filename), 'wb') as pem_out:
        pem_out.write(pem)

def load_key(filename):
    with open(os.path.join("clients",filename), 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

if __name__ == "__main__":
    main()
