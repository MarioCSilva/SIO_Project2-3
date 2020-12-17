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
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
logger.setLevel(logging.WARNING)
logger.setLevel(logging.ERROR)
logger.setLevel(logging.DEBUG)

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
            self.ciphermode = response['ciphermode']
            self.digest = response['digest']
            print(response)

            self.server_public_key = response['public_key']

            p, g, salt, key_size =  response['parameters']['p'],\
                                    response['parameters']['g'],\
                                    response['parameters']['salt'],\
                                    response['parameters']['key_size']
                                   
            self.diffie_hellman(p, g, salt, key_size)

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
        self.send_message( { 'method': 'HELLO', 'ciphers': self.ciphers, 'digests': self.digests, 'ciphermodes': self.ciphermodes } )

    
    def diffie_hellman(self, p, g, salt, key_size):
        pn = dh.DHParameterNumbers(p, g).parameters()

        self.private_key = pn.generate_private_key()
        self.public_key = self.private_key.public_key()
        
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        server_public_key = load_pem_public_key(self.server_public_key.encode())

        self.shared_key = self.private_key.exchange(server_public_key)
        
            
    # Encrypt data
    def encrypt_data(self, derived_key, data): 
        ## Key maybe ain't this...
        ## Check Key size..
        key = derived_key

        nonce = os.urandom(16)
        
        if self.cipher == 'ChaCha20':
            algorithm = algorithms.ChaCha20(key, nonce)
        elif self.cipher == 'AES':
            algorithm = algorithms.AES(key)
        elif self.cipher == '3DES':
            algorithm = algorithm.TripleDES(key)

        ## Check IV size..
        ## ChaCha mode is None maybe
        iv = os.urandom(16)

        if self.ciphermode == 'CBC':
            mode = modes.CBC(iv)
            #Padding is required when using this mode.
            data = self.padding(algorithm.block_size, data)

        elif self.ciphermode == 'GCM':
            mode = modes.GCM(iv)
            # This mode does not require padding.

        elif self.ciphermode == 'ECB':
            mode = modes.ECB(iv)
            #Padding is required when using this mode.
            data = self.padding(algorithm.block_size, data)
        
        encryptor = Cipher(algorithm, mode).encryptor()
        ct = encryptor.update(data) + encryptor.finalize()

        return iv, ct


    def padding(self, block_size, data):
        padder = padding.PKCS7(block_size).padder()
        padded_data = padder.update(data)
        return padded_data + padder.finalize()
    
    
    def unpadder(self, block_size, data):
        unpadder = padding.PKCS7(block_size).unpadder()
        return unpadder.update(data) + unpadder.finalize()


    # Decrypt data
    def decrypt_data(self, derived_key, iv, data, nonce=None):
        key = derived_key

        if self.cipher == 'ChaCha20': # 256
            algorithm = algorithms.ChaCha20(key, nonce)
            mode = None

        elif self.cipher == 'AES': # 128, 192, 256
            algorithm = algorithms.AES(key)

        elif self.cipher == '3DES':# 64, 128, 192
            algorithm = algorithm.TripleDES(key)

        ## Check IV size..
        ## ChaCha mode is None maybe
        if self.ciphermode == 'CBC':
            mode = modes.CBC(iv)
        elif self.ciphermode == 'GCM':
            mode = modes.GCM(iv)
        elif self.ciphermode == 'ECB':
            mode = modes.ECB(iv)

        decryptor = Cipher(algorithm, mode).decryptor()
        data = decryptor.update(data)

        if self.ciphermode in {'CBC', 'ECB'}:
            data = self.unpadder(algorithm.block_size, data)

        return data


    def gen_MAC(self, hmac_key, data):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        mac_digest = hmac.HMAC(hmac_key, digest)
        mac_digest.update(data)

        return f'{data}{mac_digest.finalize()}'


    def verify_MAC(self, hmac_key, data):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()
        else:
            logger.debug("Must negotiate first.")
            return False

        mac_digest = hmac.HMAC(hmac_key, digest)
        mac_digest.update(data[:digest.digest_size])
        logger.debug("sera? vai dar merda?")

        try:
            mac_digest.verify(data[digest.digest_size:])
            return True
        except:
            logger.debug(" e nao e que deu merda!!!!")
            return False
    
    def gen_derived_key(self, media_id, chunk_id):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        salt_init = os.urandom(128)

        result = bytearray()
        chunk_id_b = bytes(chunk_id)
        media_id_b = bytes(media_id)
        
        for b1, b2, b3 in zip(salt_init, [0]*(len(salt_init)-len(chunk_id_b)) + list(chunk_id_b), [0]*(len(salt_init)-len(media_id_b)) + list(media_id_b)):
            result.append(b1 ^ b2 ^ b3)
        
        # Check length here and salt
        derived_key = HKDF(
            algorithm=digest,
            length=64,  # TODO: revise this value
            salt=bytes(result),
            info=b'handshake info',
        ).derive(self.shared_key)
        
        hmac_key = derived_key[len(derived_key)//2:]
        derived_key = derived_key[:len(derived_key)//2]

        return derived_key, hmac_key, salt_init

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
        response = req.json()
        logger.debug(response)

        iv = binascii.a2b_base64(response['iv'].encode('latin'))
        salt = binascii.a2b_base64(response['salt'].encode('latin'))
        data = binascii.a2b_base64(response['data'].encode('latin'))
        nonce = binascii.a2b_base64(response['nonce'].encode('latin'))
        media_id = response['media_id']
        chunk_id = response['chunk_id']
        
        # Generate ephemeral key and hmac key
        derived_key, hmac_key, salt_init = client.gen_derived_key(media_id.encode('latin'), chunk_id)
        
        # Verify MAC
        if not client.verify_MAC(hmac_key, data):
            logger.debug("Integrity compromised.")
            exit()  
        
        # Decrypt Data
        data = client.decrypt_data(derived_key, iv, data, nonce)
        
        # logger.debug(data)

        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    
    while True:
        main()
        time.sleep(1)