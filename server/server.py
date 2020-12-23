import logging
import binascii
import json
import os
import math
import random
import sys
from os import scandir
#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hmac
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from certificate_authority import CA
from cryptography.exceptions import InvalidSignature

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


class Session:
    PUB_KEY = 0
    PRI_KEY = 1
    CLIPUB_KEY = 2
    SHARED_KEY = 3
    CIPHER = 4
    DIGEST = 5
    MODE = 6
    STATE = 7
    USER = 8
    CERT = 9

class State:
    HELLO = 0
    KEY_EXCHANGE = 1
    CONFIRM = 2
    ALLOW = 3

class User:
    USERNAME = 0
    PASSWORD = 1
    
# In authenticated DH, each party acquires a certificate for the other party.
# The DH public key that each party sends to the other party is digitally
# signed by the sender using the private key that corresponds to the public key on the sender’s certificate.
# A reader might ask that if the two parties are going to use certificates anyway, why
# not fall back on the “traditional” approach of having one of the parties encrypt a session key with the other
# party’s public key, since, subsequently, only the other party would be able to retrieve the session key through
# decryption with their private key. While that point is valid, DH does give you additional security because it
# creates a shared secret without any transmission of the secret between the two parties.



# State 0:
#     Cliente manda Hello:
#         Server responde com Hello
#         com a sua pub key e id da sessao do cliente
#
# State 1:
#     Cliente manda key_exchange:
#         Server guarda a pub key do cliente
#         e shared key
#
# State 2:
#     Cliente manda Confirm:
#         Server verifica se esta tudo bem
#         e nao bloqueia a sessao se estiver
#
# State 3:
#     Cliente é permitido fazer as outras operaçoes


# TODO:
# ✓ confirm
# ✓ sequential steps verification
# x encrypt session_id on headers
# x encrypt files in catalogo on disk
# x encrypt all data or send parameters raw
# x resto do projeto

class MediaServer(resource.Resource):
    isLeaf = True
    cur_session_id = 0

    
    def __init__(self):


        self.users = {}
        self.sessions = {}
        self.ciphers = ['AES','3DES','ChaCha20']
        self.digests = ['SHA-256','SHA-384','SHA-512']
        self.ciphermodes = ['CBC','GCM','ECB']

        self.ca = CA('./crl')
        
        for cert in scandir('certificate'):
            self.cert, valid = self.ca.load_cert(cert)
            if not valid:
                ## Ask CA for another Certificate
                exit(1)
            
        self.cert_pub_key = self.cert.public_key()
        
        # password would keep the file safe from attackers
        with open("server_key.pem", "rb") as key_file:
            self.cert_priv_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            
            
    # Send the list of media files to clients
    def do_list(self, session_id, request):

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

        derived_key, hmac_key, salt = self.gen_derived_key(session_id)

        data = json.dumps(media_list, indent=4).encode('latin')
        
        data, iv, nonce = self.encrypt_data(session_id, derived_key, data)

        data = self.gen_MAC(session_id, hmac_key, data)

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(
                {
                    'salt': binascii.b2a_base64(salt).decode('latin').strip(),
                    'iv': binascii.b2a_base64(iv).decode('latin').strip(),
                    'nonce': binascii.b2a_base64(nonce).decode('latin').strip() if nonce else binascii.b2a_base64(b'').decode('latin').strip(),
                    'data': binascii.b2a_base64(data).decode('latin').strip(),
                },indent=4
            ).encode('latin')

    # Send a media chunk to the client
    def do_download(self, session_id, request):
        
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

            derived_key, hmac_key, salt = self.gen_derived_key(session_id, media_id.encode('latin'), str(chunk_id).encode('latin'))

            data, iv, nonce = self.encrypt_data(session_id, derived_key, data)

            data = self.gen_MAC(session_id, hmac_key, data)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id,
                        'chunk_id': chunk_id,
                        'salt': binascii.b2a_base64(salt).decode('latin').strip(),
                        'iv': binascii.b2a_base64(iv).decode('latin').strip(),
                        'nonce': binascii.b2a_base64(nonce).decode('latin').strip() if nonce else binascii.b2a_base64(b'').decode('latin').strip(),
                        'data': binascii.b2a_base64(data).decode('latin').strip(),
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def encrypted_get(self, request):
        session_id = int(request.getHeader('Authorization'))
        session = self.sessions[session_id]

        data = json.loads(request.getHeader('Content'))
        
        salt = binascii.a2b_base64(data['salt'].encode('latin'))
        iv = binascii.a2b_base64(data['iv'].encode('latin'))
        nonce = binascii.a2b_base64(data['nonce'].encode('latin'))
        
        content = binascii.a2b_base64(data['content'].encode('latin'))
        
        derived_key, hmac_key, _ = self.gen_derived_key(session_id, salt=salt)
        data = self.verify_MAC(session_id, hmac_key, content)

        if not data:
            logger.debug("Integrity or authenticity compromised.")
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'unknown'}, indent=4).encode('latin')
        
        method = content['method']
        
        if method == 'PROTOCOL':
            return self.do_get_protocols(request)
        elif method == 'LIST':

            if session_id in self.sessions and self.sessions[session_id][Session.STATE] != State.ALLOW:
                request.setResponseCode(401)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({'error': 'unauthorized'}).encode('latin')
                
            return self.do_list(session_id, request)
        elif method == 'DOWNLOAD':

            if session_id in self.sessions and self.sessions[session_id][Session.STATE] != State.ALLOW:
                request.setResponseCode(401)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({'error': 'unauthorized'}).encode('latin')

            return self.do_download(session_id, request)
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'invalid request'}, indent=4).encode('latin')


    def encrypted_post(self, request):
        data = request.content.getvalue()
                
        session_id = int(data['session_id'])
        session = self.sessions[session_id]

        salt = binascii.a2b_base64(data['salt'].encode('latin'))
        iv = binascii.a2b_base64(data['iv'].encode('latin'))
        nonce = binascii.a2b_base64(data['nonce'].encode('latin'))
        
        content = binascii.a2b_base64(data['content'].encode('latin'))
        
        derived_key, hmac_key, _ = self.gen_derived_key(session_id, salt=salt)
            
        data = self.verify_MAC(session_id, hmac_key, content)

        # Verify MAC
        if not data:
            logger.debug("Integrity or authenticity compromised.")
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': "something wen't wrong"}).encode('latin')
        
        # Decrypt Data
        data = json.loads(self.decrypt_data(session_id, derived_key, iv, data, nonce))

        method = data['method']
        
        if method == 'CONFIRM':
            if session[Session.STATE] != State.KEY_EXCHANGE:
                request.setResponseCode(401)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({'error': 'Unauthorized'}).encode('latin')
            
            session[Session.STATE] = State.CONFIRM
            
            algorithms = data['algorithms']
        
            ciphers = algorithms['ciphers']
            digests = algorithms['digests']
            ciphermodes = algorithms['ciphermodes']
            choosen_cipher = algorithms['chosen_cipher']
            choosen_digest = algorithms['chosen_digest']
            choosen_mode = algorithms['chosen_mode']
            
            cipher, digest, ciphermode = self.choose_algorithms(ciphers, digests, ciphermodes)
            
            if cipher != choosen_cipher or digest != choosen_digest or ciphermode != choosen_mode:
                logger.debug("Algorithms did not match server's preferred choices.")
                request.setResponseCode(404)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({'error': "something wen't wrong."}).encode('latin')
            
            session[Session.STATE] = State.ALLOW
            logger.debug("Confirmed session ID " + str(session_id) + " algorithms and is now allowed to communicate.")
            
            return b'ACK'
    
    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/cert':
                #...chave publica do server
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps( {"cert": binascii.b2a_base64(self.cert.public_bytes(Encoding.PEM)).decode('latin').strip()}, indent=4 ).encode('latin')
            elif request.path == b'/api':
                return self.encrypted_get(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/cert /api'
            
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

                client_cert = x509.load_pem_x509_certificate(binascii.a2b_base64(data['cert']))

                # Validate Client's Certificate
                if not self.ca.validate_cert(client_cert):
                    logger.debug("Client's Certificate Invalid.")
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'certificate invalid'}, indent=4).encode('latin')
                logger.debug("Client's Certificate Validated.")
                
                ciphers = data['ciphers']
                digests = data['digests']
                ciphermodes = data['ciphermodes']
                
                cipher, digest, ciphermode = self.choose_algorithms(ciphers, digests, ciphermodes)
                if cipher is None:
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'algorithm options are not supported'}, indent=4).encode('latin')

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                
                p, g, session_id = self.diffie_hellman(2, 1024)
                
                self.sessions[session_id][Session.CIPHER] = cipher
                self.sessions[session_id][Session.MODE] = ciphermode
                self.sessions[session_id][Session.DIGEST] = digest
                self.sessions[session_id][Session.STATE] = State.HELLO
                self.sessions[session_id][Session.CERT] = client_cert

                challenge = os.urandom(256)
                logger.debug(challenge)
                
                return json.dumps({
                        'method': 'HELLO',
                        'session_id': session_id,
                        'cipher': cipher,
                        'digest': digest,
                        'ciphermode': ciphermode,
                        'public_key': self.sessions[session_id][Session.PUB_KEY].public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                        'parameters': {
                            'p': p,
                            'g': g,
                            'key_size': 1024,
                        },
                        'challenge': binascii.b2a_base64(challenge).decode('latin').strip()
                    }).encode("latin")

            elif request.path == b'/api/key_exchange':
                
                session_id = int(data['session_id'])
                session = self.sessions[session_id]
                
                if session[Session.STATE] != State.HELLO:
                    request.setResponseCode(401)
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'Unauthorized'}).encode('latin')
                
                session[Session.STATE] = State.KEY_EXCHANGE
                session[Session.CLIPUB_KEY] = data['public_key']
                client_public_key = load_pem_public_key(data['public_key'].encode())
                session[Session.SHARED_KEY] = session[Session.PRI_KEY].exchange(client_public_key)

                challenge = binascii.a2b_base64(data['challenge'].encode('latin'))
                signed_challenge = binascii.a2b_base64(data['signed_challenge'].encode('latin'))

                if 'SHA-256' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA256()
                elif 'SHA-384' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA384()
                elif 'SHA-512' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA512()

                try:
                    session[Session.CERT].public_key().verify(
                        signed_challenge,
                        challenge,
                        asymmetric_padding.PSS(
                            mgf=asymmetric_padding.MGF1(sign_digest),
                            salt_length=asymmetric_padding.PSS.MAX_LENGTH
                        ),
                        sign_digest
                    )
                except InvalidSignature:
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'something went wrong'}, indent=4).encode('latin')
                    
                signed_challenge = self.cert_priv_key.sign(
                    challenge,
                    asymmetric_padding.PSS(
                        mgf=asymmetric_padding.MGF1(sign_digest),
                        salt_length=asymmetric_padding.PSS.MAX_LENGTH
                    ),
                    sign_digest
                )
    
                return json.dumps({
                    'challenge': binascii.b2a_base64(challenge).decode('latin').strip(),
                    'signed_challenge': binascii.b2a_base64(signed_challenge).decode('latin').strip()
                }).encode("latin")
            
            elif request.path == b'/api':
                return self.encrypted_post(request)
                
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain') 
                return b'Methods: /api/hello /api/key_exchange'
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
        
        
    def choose_algorithms(self, ciphers, digests, ciphermodes):
        if 'ChaCha20' in ciphers:
            cipher = 'ChaCha20'
        elif 'AES' in ciphers:
            cipher = 'AES'
        elif '3DES' in ciphers:
            cipher = '3DES'
        else:
            return None, None, None

        if 'SHA-256' in digests:
            digest = 'SHA-256'
        elif 'SHA-384' in digests:
            digest = 'SHA-384'
        elif 'SHA-512' in digests:
            digest = 'SHA-512'
        else:
            return None, None, None
        
        if cipher == 'ChaCha20':
            ciphermode = None
        elif 'CBC' in ciphermodes:
            ciphermode = 'CBC'
        elif 'GCM' in ciphermodes:
            ciphermode = 'GCM'
        elif 'ECB' in ciphermodes:
            ciphermode = 'ECB'
        else:
            return None, None, None

        return cipher, digest, ciphermode
                
        
    def gen_MAC(self, session_id, hmac_key, data):
        session = self.sessions[session_id]

        if session[Session.DIGEST] == 'SHA-256':
            digest = hashes.SHA256()
        elif session[Session.DIGEST] == 'SHA-384':
            digest = hashes.SHA384()
        elif session[Session.DIGEST] == 'SHA-512':
            digest = hashes.SHA512()

        mac_digest = hmac.HMAC(hmac_key, digest)
        mac_digest.update(data)
        x = mac_digest.finalize()
        return eval(f'{data}{x}')


    def verify_MAC(self, session_id, hmac_key, data):
        session = self.sessions[session_id]
        
        if session[Session.DIGEST] == 'SHA-256':
            digest = hashes.SHA256()
        elif session[Session.DIGEST] == 'SHA-384':
            digest = hashes.SHA384()
        elif session[Session.DIGEST] == 'SHA-512':
            digest = hashes.SHA512()
        else:
            logger.debug("Must negotiate first.")
            return False
        
        mac_digest = hmac.HMAC(hmac_key, digest)

        mac_digest.update(data[:-digest.digest_size])

        try:
            logger.info("Mac successfully verified.")
            mac_digest.verify(data[-digest.digest_size:])
            return data[:-digest.digest_size]
        except:
            logger.debug("Mac failed verification.")
            return None
        
        
    def gen_derived_key(self, session_id, media_id=None, chunk_id=None, salt=None):
        session = self.sessions[session_id]
        
        if session[Session.DIGEST] == 'SHA-256':
            digest = hashes.SHA256()
        elif session[Session.DIGEST] == 'SHA-384':
            digest = hashes.SHA384()
        elif session[Session.DIGEST] == 'SHA-512':
            digest = hashes.SHA512()

        if salt is None:
            salt = os.urandom(128)
        salt_init = salt

        if chunk_id is not None:
            result = bytearray()
            chunk_id_b = bytes(chunk_id)
            media_id_b = bytes(media_id)
            
            for b1, b2, b3 in zip(salt, [0]*(len(salt)-len(chunk_id_b)) + list(chunk_id_b), [0]*(len(salt)-len(media_id_b)) + list(media_id_b)):
                result.append(b1 ^ b2 ^ b3)
                
            salt_init = bytes(result)

        # Check length here and salt
        derived_key = HKDF(
            algorithm=digest,
            length=64,  # TODO: revise this value
            salt=salt_init,
            info=b'handshake info',
        ).derive(session[Session.SHARED_KEY])

        hmac_key = derived_key[len(derived_key)//2:]
        derived_key = derived_key[:len(derived_key)//2]

        return derived_key, hmac_key, salt

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
        
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # Check concurrency here...
        session_id = self.cur_session_id
        self.cur_session_id += 1
        self.sessions[session_id] = [None] * 10
        self.sessions[session_id][Session.PUB_KEY] = public_key
        self.sessions[session_id][Session.PRI_KEY] = private_key

        pn = parameters.parameter_numbers()

        return pn.p, pn.g, session_id
            
    # Encrypt data
    def encrypt_data(self, session_id, derived_key, data): 
        ## Key maybe ain't this...
        ## Check Key size..
        key = derived_key
        session = self.sessions[session_id]
        cipher = session[Session.CIPHER]
        ciphermode = session[Session.MODE]

        nonce = None

        if cipher == 'ChaCha20':
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(key, nonce)
        elif cipher == 'AES':
            algorithm = algorithms.AES(key)
        elif cipher == '3DES':
            algorithm = algorithms.TripleDES(key)

        ## Check IV size..
        iv = os.urandom(16)

        if cipher == 'ChaCha20':
            mode = None
        elif ciphermode == 'CBC':
            mode = modes.CBC(iv)
            #Padding is required when using this mode.
            data = self.padding(algorithm.block_size, data)
        elif ciphermode == 'GCM':
            mode = modes.GCM(iv)
            # This mode does not require padding.
        elif ciphermode == 'ECB':
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
    def decrypt_data(self, session_id, derived_key, iv, data, nonce=None): 
        key = derived_key
        session = self.sessions[session_id]
        cipher = session[Session.CIPHER]
        ciphermode = session[Session.MODE]

        if cipher == 'ChaCha20': # 256
            algorithm = algorithms.ChaCha20(key, nonce)
            mode = None
        elif cipher == 'AES': # 128, 192, 256
            algorithm = algorithms.AES(key)
        elif cipher == '3DES':# 64, 128, 192
            algorithm = algorithm.TripleDES(key)

        ## Check IV size..
        ## ChaCha mode is None maybe
        if ciphermode == 'CBC':
            mode = modes.CBC(iv)
        elif ciphermode == 'GCM':
            mode = modes.GCM(iv)
        elif ciphermode == 'ECB':
            mode = modes.ECB(iv)

        decryptor = Cipher(algorithm, mode).decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        if ciphermode in {'CBC', 'ECB'}:
            data = self.unpadder(algorithm.block_size, data)
        
        return data

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()
