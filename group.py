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
import queue
import os
import time

class ClientAdder (threading.Thread):
    def __init__(self,validClients,lock,listener,key):
        super(ClientAdder,self).__init__()
        self.valid  = validClients
        self.lock = lock
        self.listener = listener
        self.key = key

    def run(self):
        while True:
            # accept connection check if valid user, if so then send encrypted key else just close connection
            conn = self.listener.accept()
            # msg = [username,port,public_key]
            msg = []
            try:
                msg = conn.recv()
            except:
                pass
            #print(msg)
            self.lock.acquire()
            if msg[0] in self.valid and self.valid[msg[0]] == True:
                address = ('localhost', msg[1])
                conn2 = Client(address, authkey=b'secret password')
                public_key = serialization.load_pem_public_key(msg[2],backend=default_backend())
                ciphertext = public_key.encrypt(
                    self.key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                conn2.send(ciphertext)
                conn2.close()
            self.lock.release()
            conn.close()

    def setKey(self, newkey):
        self.key = newkey

def encryptAllFiles(f,filelist):
    for file1 in filelist:     
        unencoded = file1.GetContentString()
        #print(file1['title'])
        #print(unencoded + "\n")
        encoded = f.encrypt(unencoded.encode())
        #print(encoded)
        file1.SetContentString(encoded.decode())
        file1.Upload()

def decryptAllFiles(f,filelist):
    for file1 in filelist:     
        encoded = file1.GetContentString()
        #print(file1['title'])
        #print(unencoded)
        unencoded = f.decrypt(encoded.encode())
        #print(unencoded)
        file1.SetContentString(unencoded.decode())
        file1.Upload()

def main():
    try:
        with open('groupkeys/symkey.txt', 'rb') as file:
            key = file.read()
    except:
        key = Fernet.generate_key()
        with open("groupkeys/symkey.txt", "wb") as file:
            file.write(key)

    f = Fernet(key)
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()

    drive = GoogleDrive(gauth)
    file_list = drive.ListFile({'q': "'1gPPLp6BmCAqWxYXDPv8E38H4ZVBe64bY' in parents and trashed=false"}).GetList()
    encryptAllFiles(f,file_list)

    address = ('localhost', 6000)     # family is deduced to be 'AF_INET'
    listener = Listener(address, authkey=b'secret password')

    validClients = {}
    lock = threading.Lock()
    thread = ClientAdder(validClients,lock,listener,key)
    thread.start()
    endProgram = False
    while not endProgram:
        command = input("<kick user> or <add user>")
        lock.acquire()
        if command.split(" ")[0] == "kick":
            username = command.split(" ")[1]
            validClients[username] = False
            file_list = drive.ListFile({'q': "'1gPPLp6BmCAqWxYXDPv8E38H4ZVBe64bY' in parents and trashed=false"}).GetList()
            decryptAllFiles(f,file_list)
            key = Fernet.generate_key()
            thread.setKey(key)
            with open("groupkeys/symkey.txt", "wb") as file:
                file.write(key)
            f = Fernet(key)
            encryptAllFiles(f,file_list)
        elif command.split(" ")[0] == "add":
            username = command.split(" ")[1]
            validClients[username] = True
        else:
            endProgram = True
        lock.release()
    #cleanup to restore files back to decrypted for easy testing
    decryptAllFiles(f,file_list)



if __name__ == "__main__":
    main()