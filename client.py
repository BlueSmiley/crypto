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
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import threading
import random
import queue
import os
import time


def openFile(f, filename,drive):
    file_list = drive.ListFile({'q': "'1gPPLp6BmCAqWxYXDPv8E38H4ZVBe64bY' in parents and trashed=false"}).GetList()
    for file1 in file_list:
        if file1["title"] == filename:
            encoded = file1.GetContentString()    
            #print(encoded)  
            unencoded = f.decrypt(encoded.encode())
            print(unencoded)

def getSymKey(address,username,port,group_address,group_listener,private_key):
    public_key = private_key.public_key()
    conn = Client(address, authkey=b'secret password')
    conn.send([
        username,
        port,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )])
    conn.close()

    group_conn = group_listener.accept()

    encryptedKey = b"error"
    try:
        encryptedKey = group_conn.recv()
    except:
        pass
    group_conn.close()

    symkey = private_key.decrypt(
        encryptedKey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symkey


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


    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()

    drive = GoogleDrive(gauth)

    address = ('localhost', 6000)
    port = random.randint(6001,7000)
    group_address = ('localhost', port)     # family is deduced to be 'AF_INET'
    group_listener = Listener(group_address, authkey=b'secret password')

    symkey = getSymKey(address,username,port,group_address,group_listener,key)
    #time.sleep(10)
    while(True):
        filename = input("Enter filename: ")
        symkey = getSymKey(address,username,port,group_address,group_listener,key)
        f = Fernet(symkey)
        openFile(f,filename,drive)

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
