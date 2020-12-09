#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization  
import logging
import binascii
import json
import os
import math
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True
    def __init__(self):
        self.ciphers=[]
        self.digests=[]
        self.ciphermodes=[]
        # self.ciphers = ['AES','3DES','ChaCha20']
        # self.digests = ['SHA-256','SHA-384','SHA-512']
        # self.ciphermodes = ['CBC','GCM','ECB']

        
    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')
        print(request.uri)

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.uri == b'/api/key':
            #...chave publica do server
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({"data":"key"}).encode("latin")
            #elif request.uri == 'api/auth':
            #autenticaçao, later on..
            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        print(request.uri)

        try:
            data = json.loads(request.content.getvalue())

            if request.path == b'/api/hello':
                print(data)
                ciphers = data['ciphers']

                # TODO: change cipher order
                if 'ChaCha20' in ciphers:
                    cipher = 'ChaCha20'
                elif '3DES' in ciphers:
                    cipher = '3DES'
                elif 'AES' in ciphers:
                    cipher = 'AES'
                else:
                    # Ciphers not supported
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'ciphers not supported'}, indent=4).encode('latin')

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                parameters = dh.generate_parameters(generator=2, key_size=1024)

                self.private_key = parameters.generate_private_key()
                self.public_key = self.private_key.public_key()
                pn = parameters.parameter_numbers()

                print(self.public_key.__str__())

                return json.dumps({
                        'method':'HELLO',
                        'cipher': cipher,
                        'public_key': self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                        'parameters': {
                            'p': pn.p,
                            'g': pn.g
                        }
                    }).encode("latin")

            elif request.path == b'/api/key_exchange':
                print(data)
                # Only do this to use or send key
                # load_pem_public_key(data['public_key'].encode())
                self.client_public_key = data['public_key']
                print("cli_pub_key",self.client_public_key)
                print("sv_private_key",self.private_key)
                print("sv_public_key",self.public_key)

                return json.dumps({ 'method': 'ACK' }).encode("latin")
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/cipher'
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    '''
    ChaCha20 Decrypt
    >>> decryptor = cipher.decryptor()
    >>> decryptor.update(ct)

    >>> import os
    >>> from cryptography.hazmat.primitives.ciphers.modes import CBC
    >>> iv = os.urandom(16)
    >>> mode = CBC(iv)
    '''

    
    # Encrypt data
    def encrypt_data(self, data): 
        ## Key maybe ain't this...
        ## Check Key size..
        key = self.public_key

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
            padder = padding.PKCS7(algorithm.block_size).padder()
            padded_data = padder.update(data)
            data = padded_data + padder.finalize()

        elif self.ciphermode == 'GCM':
            mode = modes.GCM(iv)
            # This mode does not require padding.

        elif self.ciphermode == 'ECB':
            mode = modes.ECB(iv)
            #Padding is required when using this mode.
            padder = padding.PKCS7(algorithm.block_size).padder()
            padded_data = padder.update(data)
            data = padded_data + padder.finalize()

        
        encryptor = Cipher(algorithm, mode).encryptor()
        ct = encryptor.update(data) + encryptor.finalize()

        return iv, ct, encryptor.tag



    # Decrypt data
    def decrypt_data(self, iv, data, tag): 

        key = load_pem_public_key(self.client_public_key)
        print(key)
        key = key[:256]

        shared_key = exchange.exchange(peer_public_key_2) #TODO
        # falta gerar a shared key no diffie helmann e guardar a derived key no self.derived_shared_key xD
        # depois a cada N chunks faz o diffie helman e usa essa guardada pelo diffie helman

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=backend
        ).derive(shared_key)

        if self.cipher == 'ChaCha20': # 256
            algorithm = algorithms.ChaCha20(key, nonce)

        elif self.cipher == 'AES': # 128, 192, 256
            algorithm = algorithms.AES(key)

        elif self.cipher == '3DES':# 64, 128, 192
            algorithm = algorithm.TripleDES(key)

        ## Check IV size..
        ## ChaCha mode is None maybe
        if self.ciphermode == 'CBC':
            mode = modes.CBC(iv)
        elif self.ciphermode == 'GCM':
            mode = modes.GCM(iv, tag)
        elif self.ciphermode == 'ECB':
            mode = modes.ECB(iv, tag)

        decryptor = Cipher(algorithm, mode, tag).decryptor()
        data = decrytor.update(data)

        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        data = unpadder.update(data) + unpadder.finalize()

        return data
            

    def encrypt(key, plaintext, associated_data):
        
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (iv, ciphertext, encryptor.tag)

    def decrypt(key, associated_data, iv, ciphertext, tag):
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        decryptor.authenticate_additional_data(associated_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()

iv, ciphertext, tag = encrypt(
    key,
    b"a secret message!",
    b"authenticated but not encrypted payload"
)

print(decrypt(
    key,
    b"authenticated but not encrypted payload",
    iv,
    ciphertext,
    tag
))


algorithms.TripleDES
algorithms.AES
algorithms.ChaCha20


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
