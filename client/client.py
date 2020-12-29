import requests
import logging
import binascii
import json
import os
import random
import subprocess
import time
import sys
from os import scandir
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from certificate_authority import CA
from cc_authenticator import CC_Authenticator

from collections import defaultdict 

from cryptography.exceptions import InvalidSignature


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
        self.server_dh_pubkey = None
        self.cipher = None
        self.digest = None
        self.ciphermode = None
        self.session_id = None
        self.licences = defaultdict()

        self.ca = CA('./crl')
        
        for cert in scandir('certificate'):
            self.cert, valid = self.ca.load_cert(cert)
            if not valid:
                ## Ask CA for another Certificate
                exit(1)
            
        self.cert_pub_key = self.cert.public_key()

        # password would keep the file safe from attackers
        with open("client_key.pem", "rb") as key_file:
            self.cert_priv_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

    def get_digest(self):
        if 'SHA-256' == self.digest:
            return hashes.SHA256()
        elif 'SHA-384' == self.digest:
            return hashes.SHA384()
        elif 'SHA-512' == self.digest:
            return hashes.SHA512()
        else:
            return None
        
    
    def send_message(self, data, method):
        if method == 'HELLO':
            req = requests.post( f'{SERVER_URL}/api/hello', data=data, headers={ b"content-type": b"application/json" } )
            return req.json()
        
        elif method == 'KEY_EXCHANGE':
            req = requests.post( f'{SERVER_URL}/api/key_exchange', data=data, headers={ b"content-type": b"application/json",
                                                                                        b"Authorization": str(self.session_id) } )
            return req.json()
        
        elif method == 'CONFIRM':
            req = requests.post( f'{SERVER_URL}/api', data=data, headers={ b"content-type": b"application/json",
                                                                           b"Authorization": str(self.session_id)} )
            return req.json()
        else:
            logger.error('No such method')
            return ''
        
    def get_message(self, path, authorization=None, content=None):
        if authorization is None:
            req = requests.get(f'{SERVER_URL}{path}')
        else:
            req = requests.get(f'{SERVER_URL}{path}', headers={
                b"Authorization": authorization,
                b"Content": content
            })
      
        return req.json()
        
    def negotiate(self):
        """(Re)start the handshake with the server."""
                
        response = self.get_message('/api/cert')
        logger.info("Got Server's Certificate")

        server_cert = binascii.a2b_base64(response['cert'])

        self.server_cert = x509.load_pem_x509_certificate(server_cert)

        # Validate Server's Certificate
        if not self.ca.validate_cert(self.server_cert):
            logger.debug("Server's Certificate Invalid.")
            exit(1)

        logger.debug("Server's Certificate Validated.")

        self.server_pub_key = self.server_cert.public_key()
        
        """Send supported client suited ciphers."""
        data = json.dumps({
            'cert': binascii.b2a_base64(self.cert.public_bytes(Encoding.PEM)).decode('latin').strip(),
            'method': 'HELLO',
            'ciphers': self.ciphers,
            'digests': self.digests,
            'ciphermodes': self.ciphermodes
        }).encode()
        
        # State HELLO
        response = self.send_message(data, 'HELLO')
            
        data = self.handle_hello(response)
        
        # State KEY_EXCHANGE
        response = self.send_message(data, 'KEY_EXCHANGE' )

        data = self.decrypt_response(response)

        data = self.handle_key_exchange(data)

        data = self.encrypt_request(data)
            
        # State CONFIRM
        response = self.send_message( data, 'CONFIRM')
        
        data = self.handle_confirm(response)
        
        data = self.decrypt_response(response)
        
        # State ALLOW
        self.methods = data['methods']

        for k in self.methods:
            print(k)
            for v in self.methods[k]:
                print(f' {v}')
    

    def handle_hello(self, response):
        """ DH
        Generate shared key.
        Sign the 
        """
        self.cipher = response['cipher']
        self.ciphermode = response['ciphermode']
        self.digest = response['digest']
        self.session_id = response['session_id']

        self.server_dh_pubkey = response['public_key'].encode()

        p, g, key_size = response['parameters']['p'],\
                         response['parameters']['g'],\
                         response['parameters']['key_size']
                                
        self.diffie_hellman(p, g, key_size)
        
        print("Choose one of the following authentication methods:")  
        for k, v in response['2-factor'].items():
            print(f"{k} - {v}")   

        choice = ''
        cc_cert = ''
        
        signed_DH_pub_key = self.ca.make_signature(
            self.cert_priv_key,
            self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            self.get_digest()
        )
        
        while choice not in response['2-factor'].keys():
            choice = input('> ')

        if choice == '1':
            logger.debug('Inserting 2-factor CC Token')
            cc_authenticator = CC_Authenticator()
            
            self.cc_cert = cc_authenticator.get_certificate()
            cc_cert = self.cc_cert.public_bytes(Encoding.PEM)
            
            token = os.urandom(256)
            signed_token = cc_authenticator.get_signature(token)
            
            cc_data = json.dumps({
                'choice': choice,
                'cc_cert': binascii.b2a_base64(cc_cert).decode('latin').strip(),
                'token': binascii.b2a_base64(token).decode('latin').strip(),
                'signed_token': binascii.b2a_base64(signed_token).decode('latin').strip()
            }).encode('latin')
        else:
            cc_data = json.dumps({
                'choice': choice,
            }).encode('latin')
            
        return json.dumps({
                'method': 'KEY_EXCHANGE',
                'public_key': self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                'cc_data': binascii.b2a_base64(cc_data).decode('latin').strip(),
                'signed_public_key':  binascii.b2a_base64(signed_DH_pub_key).decode('latin').strip()
        })


    def handle_key_exchange(self, response):            
        signed_public_key = binascii.a2b_base64(response['signed_public_key'].encode('latin'))
        
        if not self.ca.check_signature(self.server_cert.public_key(), self.server_dh_pubkey, signed_public_key, self.get_digest()):
            logger.debug("Something went wrong")
            self.negotiate()

        return json.dumps({
            'method': 'CONFIRM',
            'algorithms': {
                'ciphers': self.ciphers,
                'chosen_cipher': self.cipher,
                'digests': self.digests,
                'chosen_digest': self.digest,
                'ciphermodes': self.ciphermodes,
                'chosen_mode': self.ciphermode
            },
        }).encode('latin')


    def handle_confirm(self, response):
        if self.handle_error(response):
            logger.warning("Restarting communications.")
            self.negotiate()

        
    def handle_error(self, response):
        if 'error' in response:
            logger.error(response['error'])
            return True
        return False

    
    def diffie_hellman(self, p, g, key_size):
        pn = dh.DHParameterNumbers(p, g).parameters()

        self.private_key = pn.generate_private_key()
        self.public_key = self.private_key.public_key()
        
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        server_public_key = load_pem_public_key(self.server_dh_pubkey)

        self.shared_key = self.private_key.exchange(server_public_key)
        
            
    def encrypt_data(self, derived_key, data): 
        ## Key maybe ain't this...
        ## Check Key size..
        key = derived_key

        nonce = None

        if self.cipher == 'ChaCha20':
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(key, nonce)
        elif self.cipher == 'AES':
            algorithm = algorithms.AES(key)
        elif self.cipher == '3DES':
            algorithm = algorithms.TripleDES(key)

        ## Check IV size..
        iv = os.urandom(16)

        if self.cipher == 'ChaCha20':
            mode = None
        elif self.ciphermode == 'CBC':
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
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return encrypted_data, iv, nonce


    def padding(self, block_size, data):
        padder = padding.PKCS7(block_size).padder()
        padded_data = padder.update(data)
        return padded_data + padder.finalize()
    
    
    def unpadder(self, block_size, data):
        unpadder = padding.PKCS7(block_size).unpadder()
        return unpadder.update(data) + unpadder.finalize()


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
        data = decryptor.update(data) + decryptor.finalize()

        if self.ciphermode in {'CBC', 'ECB'}:
            data = self.unpadder(algorithm.block_size, data)
        return data


    def encrypt_request(self, data):
        """Encrypt a request with integrity validation."""

        derived_key, hmac_key, salt = self.gen_derived_key()
            
        data, iv, nonce = self.encrypt_data(derived_key, data)
        
        data = self.gen_MAC(hmac_key, data)

        return json.dumps({
            'salt': binascii.b2a_base64(salt).decode('latin').strip(),
            'data': binascii.b2a_base64(data).decode('latin').strip(),
            'iv': binascii.b2a_base64(iv).decode('latin').strip(),
            'nonce': binascii.b2a_base64(nonce).decode('latin').strip()
        }).encode('latin')


    def decrypt_response(self, response, media_id=None, chunk_id=None):
        """Validate the response integrity and then encrypt the response.
        
        The parameters ``media_id`` and ``chunk_id`` are used during
        chunk based key rotation.
        """
        iv = binascii.a2b_base64(response['iv'].encode('latin'))
        salt = binascii.a2b_base64(response['salt'].encode('latin'))
        data = binascii.a2b_base64(response['data'].encode('latin'))
        nonce = binascii.a2b_base64(response['nonce'].encode('latin'))
        
        # Generate ephemeral key and hmac key
        derived_key, hmac_key, _ = self.gen_derived_key(media_id, chunk_id, salt)
        
        data = self.verify_MAC(hmac_key, data)

        # Verify MAC
        if not data:
            logger.debug("Integrity or authenticity compromised.")
            exit()
        
        # Decrypt Data
        return json.loads(self.decrypt_data(derived_key, iv, data, nonce))
    

    def gen_MAC(self, hmac_key, data):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        mac_digest = hmac.HMAC(hmac_key, digest)
        mac_digest.update(data)

        return eval(f'{data}{mac_digest.finalize()}')


    def verify_MAC(self, hmac_key, data):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()
        else:
            logger.debug("Must negotiate first.")
            return None

        mac_digest = hmac.HMAC(hmac_key, digest)

        mac_digest.update(data[:-digest.digest_size])

        try:
            logger.info("Mac successfully verified.")
            mac_digest.verify(data[-digest.digest_size:])
            return data[:-digest.digest_size]
        except:
            logger.debug("Mac failed verification.")
            return None


    def gen_derived_key(self, media_id=None, chunk_id=None, salt=None):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        if salt is None:
            salt = os.urandom(128)
        salt_init = salt

        digest_shared_key = hashes.Hash(digest)
        digest_shared_key.update(self.shared_key)
        shared_key = digest_shared_key.finalize()

        if chunk_id is not None:
            shared_key = shared_key + bytes(chunk_id) + bytes(media_id)
            # result = bytearray()
            # chunk_id_b = bytes(chunk_id)
            # media_id_b = bytes(media_id)
            # for b1, b2, b3 in zip(salt, [0]*(len(salt)-len(chunk_id_b)) + list(chunk_id_b), [0]*(len(salt)-len(media_id_b)) + list(media_id_b)):
            #     result.append(b1 ^ b2 ^ b3)
            # salt_init = bytes(result)
            
        self.shared_key = shared_key
        # Check length here and salt
        derived_key = HKDF(
            algorithm = digest,
            length = 64,  # TODO: revise this value
            salt = salt_init,
            info = b'handshake info',
        ).derive(shared_key)

        hmac_key = derived_key[len(derived_key)//2:]
        derived_key = derived_key[:len(derived_key)//2]

        return derived_key, hmac_key, salt

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    client = Client()

    client.negotiate()

    data = json.dumps({
        'method': 'LIST'
    }).encode('latin')

    content = client.encrypt_request(data)

    response = client.get_message('/api', str(client.session_id), content)
    logger.info("Got Server List")

    media_list = client.decrypt_response(response)

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
        
        # on the first chunk send licence for this media
        if chunk == 0:
            data = json.dumps({
                'method': 'DOWNLOAD',
                'media_id': media_item["id"],
                'chunk_id': chunk,
                'licence': client.licences.get(media_item["id"]) if client.licences.get(media_item["id"]) else binascii.b2a_base64(b'').decode('latin').strip()
            }).encode('latin')
        else:
            data = json.dumps({
                'method': 'DOWNLOAD',
                'media_id': media_item["id"],
                'chunk_id': chunk,
            }).encode('latin')

        content = client.encrypt_request(data)

        response = client.get_message('/api', str(client.session_id), content)

        # Client has no licence
        if 'error' in response:
            logger.debug('Client has no licence')
            
            data = json.dumps({
                'method': 'LICENCE',
                'media_id': media_item["id"],
            }).encode('latin')

            content = client.encrypt_request(data)
            
            response = requests.post(f'{SERVER_URL}/api', data=content, headers={ b"content-type": b"application/json",
                                                                                  b"Authorization": str(client.session_id)} )

            response = response.json()
            
            data = client.decrypt_response(response)
            
            licence = binascii.a2b_base64(data['licence'].encode('latin'))
            
            client.licences[media_item["id"]] = licence
            
            data = json.dumps({
                'method': 'DOWNLOAD',
                'media_id': media_item["id"],
                'chunk_id': chunk,
                'licence': binascii.b2a_base64(client.licences.get(media_item["id"])).decode('latin').strip()
            }).encode('latin')
            
            content = client.encrypt_request(data)

            response = client.get_message('/api', str(client.session_id), content)
            
            if 'error' in response:
                logger.debug('Something went wrong.')
                exit()

        media_id = response['media_id'].encode('latin')
        chunk_id = str(response['chunk_id']).encode('latin')
        
        data = client.decrypt_response(response, media_id, chunk_id)

        chunk = binascii.a2b_base64(data['chunk'])
        try:
            proc.stdin.write(chunk)
        except:
            break

if __name__ == '__main__':
    
    while True:
        main()
        time.sleep(1)