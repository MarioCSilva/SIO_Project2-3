import requests
import logging
import binascii
import json
import os
import random
import subprocess
import time
import sys
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives import serialization  

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class Client:
    def __init__(self):
        """Representation of the client."""

        self.ciphers = ['AES', '3DES', 'ChaCha20']
        self.digests = ['SHA-256','SHA-512']
        self.ciphermodes = ['CBC','ECB']
        self.server_public_key = None
        self.cipher = None
        self.digest = None
        self.ciphermode = None
    
    def send_message(self, message):
        # Negotiate algorithms
        data = json.dumps( message ).encode()

        if message['method'] == 'HELLO':
            req = requests.post( f'{SERVER_URL}/api/hello', data=data, headers={ b"content-type": b"application/json" } )
            response = req.json()

            if response['method'] != 'HELLO':
                print(response)
                exit(1)
                
            self.cipher = response['cipher']
            print(response)

            self.server_public_key = response['public_key']

            p, g = response['parameters']['p'], response['parameters']['g']
            pn = dh.DHParameterNumbers(p, g).parameters()

            self.private_key = pn.generate_private_key()
            self.public_key = self.private_key.public_key()

            if self.send_message( {'method': 'KEY_EXCHANGE', 'public_key': self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()} ) is None:
                print(response)
                exit(1)

            print('server_public_key', self.server_public_key)
            print('private_key', self.private_key)
            print('public_key', self.public_key)

        elif message['method'] == 'KEY_EXCHANGE':
            req = requests.post( f'{SERVER_URL}/api/key_exchange', data=data, headers={ b"content-type": b"application/json" } )
            response = req.json()
            if response['method'] == 'ACK':
                return True
        elif not self.srvr_publickey:
            pass
        else:
            return
    
    def negotiate(self):
        """ Send supported client suited ciphers. """
        self.send_message( { 'method': 'HELLO', 'ciphers': self.ciphers, 'digests': self.digests, 'ciphermode': self.ciphermode } )


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session

    client = Client()

    client.negotiate()

    # get server public key
    
    req = requests.get(f'{SERVER_URL}/api/key')
    if req:
        print(req.content)

    # client or server sends the algorithms to be used and the other sends the response (encoded with public?)


    # client generates simetric key and sends it encrypted with server public key 


    # validate all messages with MAC (calculate hash negotiated from last step and prepend it in the end)

    
    
    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()



    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    
    while True:
        main()
        time.sleep(1)