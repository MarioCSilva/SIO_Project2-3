#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
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
            good_data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")

            derived_key, hmac_key, salt = self.gen_derived_key(media_id.encode('latin'), str(chunk_id).encode('latin'))


            data, iv, nonce = self.encrypt_data(derived_key, good_data)

            data = self.gen_MAC(hmac_key, data)

            return json.dumps(
                    {
                        'media_id': media_id,
                        'chunk_id': chunk_id,
                        'salt': binascii.b2a_base64(salt).decode('latin').strip(),
                        'iv': binascii.b2a_base64(iv).decode('latin').strip(),
                        'nonce': binascii.b2a_base64(nonce).decode('latin').strip() if nonce else binascii.b2a_base64(b'').decode('latin').strip(),
                        'data': binascii.b2a_base64(data).decode('latin').strip(),
                        'good_data': binascii.b2a_base64(good_data).decode('latin').strip(),
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
                digests = data['digests']
                ciphermodes = data['ciphermodes']

                # TODO: change cipher order
                if 'ChaCha20' in ciphers:
                    self.cipher = 'ChaCha20'
                elif 'AES' in ciphers:
                    self.cipher = 'AES'
                elif '3DES' in ciphers:
                    self.cipher = '3DES'
                else:
                    # Ciphers not supported
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'ciphers not supported'}, indent=4).encode('latin')
                
                if 'SHA-256' in digests:
                    self.digest = 'SHA-256'
                elif 'SHA-384' in digests:
                    self.digest = 'SHA-384'
                elif 'SHA-512' in digests:
                    self.digest = 'SHA-512'
                else:
                    # Digest not supported
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'digests not supported'}, indent=4).encode('latin')
                
                if self.cipher == 'ChaCha20':
                    self.ciphermode = None
                elif 'CBC' in ciphermodes:
                    self.ciphermode = 'CBC'
                elif 'GCM' in ciphermodes:
                    self.ciphermode = 'GCM'
                elif 'ECB' in ciphermodes:
                    self.ciphermode = 'ECB'
                else:
                    # Cipher modes not supported
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'cipher modes not supported'}, indent=4).encode('latin')

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                
                p, g, salt = self.diffie_hellman(2, 1024)
                
                return json.dumps({
                        'method':'HELLO',
                        'cipher': self.cipher,
                        'digest': self.digest,
                        'ciphermode': self.ciphermode,
                        'public_key': self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                        'parameters': {
                            'p': p,
                            'g': g,
                            'salt': salt,
                            'key_size': 1024,
                        }
                    }).encode("latin")

            elif request.path == b'/api/key_exchange':
                print(data)
                # Only do this to use or send key
                # load_pem_public_key(data['public_key'].encode())
                self.client_public_key = data['public_key']
                print("cli_pub_key",self.client_public_key)
                
                client_public_key = load_pem_public_key(self.client_public_key.encode())

                self.shared_key = self.private_key.exchange(client_public_key)

                print("sv_private_key", self.private_key)
                print("sv_public_key", self.public_key)

                return json.dumps({ 'method': 'ACK' }).encode("latin")
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/hello /api/key_exchange'
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
        
        
    def gen_MAC(self, hmac_key, data):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        mac_digest = hmac.HMAC(hmac_key, digest)
        mac_digest.update(data)
        x = mac_digest.finalize()
        print('server mac', x)
        return eval(f'{data}{x}')


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
    
    def gen_derived_key(self, media_id=None, chunk_id=None, salt=None):
        if self.digest == 'SHA-256':
            digest = hashes.SHA256()
        elif self.digest == 'SHA-384':
            digest = hashes.SHA384()
        elif self.digest == 'SHA-512':
            digest = hashes.SHA512()

        if salt is None:
            salt_init = os.urandom(128)
        else:
            salt_init = salt

        if chunk_id is not None:
            result = bytearray()
            chunk_id_b = bytes(chunk_id)
            media_id_b = bytes(media_id)
            
            for b1, b2, b3 in zip(salt_init, [0]*(len(salt_init)-len(chunk_id_b)) + list(chunk_id_b), [0]*(len(salt_init)-len(media_id_b)) + list(media_id_b)):
                result.append(b1 ^ b2 ^ b3)
                
            salt_init = bytes(result)

        # Check length here and salt
        derived_key = HKDF(
            algorithm=digest,
            length=64,  # TODO: revise this value
            salt=salt_init,
            info=b'handshake info',
        ).derive(self.shared_key)
        
        hmac_key = derived_key[len(derived_key)//2:]
        derived_key = derived_key[:len(derived_key)//2]

        return derived_key, hmac_key, salt_init

    '''
    ChaCha20 Decrypt
    >>> decryptor = cipher.decryptor()
    >>> decryptor.update(ct)

    >>> import os
    >>> from cryptography.hazmat.primitives.ciphers.modes import CBC
    >>> iv = os.urandom(16)
    >>> mode = CBC(iv)
    '''

    def diffie_hellman(self, generator, key_size):
        parameters = dh.generate_parameters(generator=generator, key_size=key_size)
        self.private_key = parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        pn = parameters.parameter_numbers()

        print(self.public_key.__str__())

        salt = None
        
        return pn.p, pn.g, salt
            
    # Encrypt data
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


    # Decrypt data
    def decrypt_data(self, derived_key, iv, data): 
        key = derived_key

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
            mode = modes.GCM(iv)
        elif self.ciphermode == 'ECB':
            mode = modes.ECB(iv)

        decryptor = Cipher(algorithm, mode).decryptor()
        data = decrytor.update(data)

        data = self.unpadder(algorithm.block_size, data)

        return data

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
