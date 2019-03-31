#!/usr/bin/env python3
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def encryptAllFiles(f,filelist):
    for file1 in filelist:     
        unencoded = file1.GetContentString()
        
        print(unencoded + "\n")
        encoded = f.encrypt(unencoded.encode())
        print(encoded)
        file1.SetContentString(encoded.decode())
        file1.Upload()

def decryptAllFiles(f,filelist):
    for file1 in filelist:     
        encoded = file1.GetContentString()
        
        #print(unencoded)
        unencoded = f.decrypt(encoded.encode())
        #print(encoded)
        file1.SetContentString(unencoded.decode())
        file1.Upload()
        
def main():
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()

    drive = GoogleDrive(gauth)

    try:
        with open('groupkeys/symkey.txt', 'rb') as file:
            key = file.read()
    except:
        key = Fernet.generate_key()
        with open("groupkeys/symkey.txt", "wb") as file:
            file.write(key)

    file_list = drive.ListFile({'q': "'1gPPLp6BmCAqWxYXDPv8E38H4ZVBe64bY' in parents and trashed=false"}).GetList()
    f = Fernet(key)
    file4 = drive.CreateFile({"parents": [{"kind": "drive#fileLink", "id": "1gPPLp6BmCAqWxYXDPv8E38H4ZVBe64bY"}],'title':'test3.txt'})
    file4.SetContentString("Hello world")
    file4.Upload()
    #encryptAllFiles(f,file_list)
    #for file1 in file_list:
    #    print('title: %s' % (file1['title']))
     #   text = file1.GetContentString()
     #   print(text + "\n")
        
        


if __name__ == "__main__":
    main()