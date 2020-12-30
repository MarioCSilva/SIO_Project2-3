import logging
import binascii
import json
import os
import math
import random
import sys
from os import scandir
import datetime
#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
                'file_size': 3407202,
                'data': None
            }
        }
CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4
FILES_IV = b'\x12\x9c\xef+\xe8\rI5\xb4\xfc\x8aH\x88\x06j\xa9'
FILES_SALT = b'm\xa8\xb68Bj \xd1\x8e\xb8\x8e\x07\xcf\xe0\x06\x11'


class Session:
    PUB_KEY = 0
    PRI_KEY = 1
    CLIPUB_KEY = 2
    SHARED_KEY = 3
    CIPHER = 4
    DIGEST = 5
    MODE = 6
    STATE = 7
    CERT = 8


class State:
    HELLO = 0
    KEY_EXCHANGE = 1
    CONFIRM = 2
    ALLOW = 3


class User:
    CC_TOKEN = 0


class MediaServer(resource.Resource):
    isLeaf = True
    cur_session_id = 0
    first_time = False
    
    def __init__(self):
        self.users = {}
        self.sessions = {}

        self.ciphers = ['AES','3DES','ChaCha20']
        self.digests = ['SHA-256','SHA-384','SHA-512']
        self.ciphermodes = ['CBC','ECB']

        self.ca = CA('./crl')
        
        for cert in scandir('certificate'):
            self.cert, valid = self.ca.load_cert(cert)
            if not valid:
                # Ask CA for another Certificate
                exit(1)
            
        self.cert_pub_key = self.cert.public_key()
        
        with open("server_key.pem", "rb") as key_file:
            self.cert_priv_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None, # password would keep the file safe from attackers
            )
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=FILES_SALT,
            iterations=100000,
        )
        key = kdf.derive(b"34hvr93QLMdvmltXM9sfohbipweeqhwV2piasdnW3QIRfwpej439wueejsf")
        
        if self.first_time:
            self.encrypt_files(key)
        self.decrypt_files(key)


    def encrypt_files(self, key):        
        for obj in scandir(CATALOG_BASE + '/'):
            if obj.is_dir() or not (any(ext in obj.name for ext in ['mp3'])):
                continue

            fp = open(CATALOG_BASE + '/' + obj.name, 'rb')
            data = fp.read()
            fp.close()

            fp = open(CATALOG_BASE + '/' + obj.name, 'wb')

            encryptor = Cipher(
                algorithms.AES(key),
                modes.CBC(FILES_IV),
            ).encryptor()
 
            data = self.padding(algorithms.AES.block_size, data)
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            fp.write(ciphertext)
            fp.close()


    def decrypt_files(self, key):
        for obj in scandir(CATALOG_BASE + '/'):
            if obj.is_dir() or not (any(ext in obj.name for ext in ['mp3'])):
                continue

            fp = open(CATALOG_BASE + '/' + obj.name, 'rb')
            media_item = CATALOG[obj.name.split('.')[0]]
            
            data = fp.read()
            fp.close()

            decryptor = Cipher(
                algorithms.AES(key),
                modes.CBC(FILES_IV),
            ).decryptor()
 
            ciphertext = decryptor.update(data) + decryptor.finalize()
            ciphertext = self.unpadder(algorithms.AES.block_size, ciphertext)
            
            media_item['data'] = ciphertext
                        
    # Send the list of media files to clients
    def do_list(self, session_id, request):
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
            
        data = json.dumps(media_list, indent=4).encode('latin')
        
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return self.encrypt_request(session_id, data)

        
    def check_user_licence(self, session_id, media_id, licence):
        logger.debug(f'Checking licence for media id: {media_id}')
        
        client_cert = self.sessions[session_id][Session.CERT]

        if licence == b'':
            logger.debug('Client has no licence for this media.')
            return False
        
        licence = x509.load_pem_x509_certificate(licence)
        
        # check if the licence was really signed by the server
        if not self.ca.validate_cert_signature(licence, self.cert):
            logger.debug('Licence Invalid.')
            return False
        
        # check time validity of certificate here
        if licence.not_valid_after < datetime.datetime.now():
            logger.debug("Licence Invalid.")
            return False

        # check if the license belongs to the user
        subject_user_id = licence.subject.get_attributes_for_oid(NameOID.USER_ID)[0]._value
        if subject_user_id != binascii.b2a_base64(
            self.sessions[session_id][Session.CERT].public_bytes(Encoding.PEM)
        ).decode('latin').strip():
            logger.debug("Licence Invalid.")
            return False

        # check if the licence is for this ``media_id``
        if licence.subject.get_attributes_for_oid(NameOID.TITLE)[0]._value != media_id:
            logger.debug("Licence Invalid.")
            return False

        logger.debug("Successfully validated client's licence")
        
        return True
        
        
    def do_download(self, session_id, media_id, chunk_id, request):
        """Send an encrypted media chunk to the client."""
        
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        valid_chunk = False
        try:
            chunk_id = int(chunk_id)
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

        file_name = os.path.join(CATALOG_BASE, media_item['file_name'])
        with open(file_name, 'rb') as f:
            data = json.dumps({
                'chunk': binascii.b2a_base64(CATALOG[media_id]['data'][offset : offset+CHUNK_SIZE]).decode('latin').strip()
            }).encode('latin')

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return self.encrypt_request(session_id, data, media_id.encode('latin'), str(chunk_id).encode('latin'))

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    def encrypted_get(self, request):
        """Handle GET requests from the client."""

        session_id = int(request.getHeader('Authorization'))
        session = self.sessions[session_id]

        data = json.loads(request.getHeader('Content'))
        
        data = self.decrypt_response(session_id, data)
        
        if 'error' in data:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(data).encode('latin')
            
        method = data['method']

        if method == 'LIST':
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

            # On the first chunk check if the licence that the client sent is valid
            if data['chunk_id'] == 0 and not self.check_user_licence(session_id, data['media_id'], binascii.a2b_base64(data['licence'].encode('latin'))):
                request.setResponseCode(401)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({'error': 'unauthorized'}).encode('latin')
            return self.do_download(session_id, data['media_id'], data['chunk_id'], request)

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'invalid request'}, indent=4).encode('latin')


    def encrypted_post(self, request):
        """Handle POST requests from the client."""
        
        session_id = int(request.getHeader('Authorization'))
        session = self.sessions[session_id]

        data = json.loads(request.content.getvalue())
        data = self.decrypt_response(session_id, data)
        
        if 'error' in data:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(data).encode('latin')

        method = data['method']
        
        try:
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
                    print(ciphermode, choosen_mode)
                    logger.debug("Algorithms did not match server's preferred choices.")
                    request.setResponseCode(404)
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': "something wen't wrong."}).encode('latin')
                
                session[Session.STATE] = State.ALLOW
                logger.debug("Confirmed session ID " + str(session_id) + " algorithms and is now allowed to communicate.")
                
                data = json.dumps({'methods': {'GET': [{'/api': ['LIST', 'DOWNLOAD']}, '/api/cert'], 'POST': [{'/api/': ['CONFIRM', 'LICENCE']}, '/api/hello', '/api/key_exchange']}}).encode('latin')

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return self.encrypt_request(session_id, data)
                
            elif method == 'LICENCE':
                if session[Session.STATE] != State.ALLOW:
                    request.setResponseCode(401)
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'Unauthorized'}).encode('latin')

                media_id = data['media_id']
                
                # Create licence for this user of this media  
                licence = x509.CertificateBuilder().subject_name(
                    x509.Name([
                        x509.NameAttribute(NameOID.USER_ID, binascii.b2a_base64(
                            session[Session.CERT].public_bytes(Encoding.PEM)
                        ).decode('latin').strip()),
                        x509.NameAttribute(NameOID.TITLE, media_id),
                    ])
                ).issuer_name(
                    x509.Name([
                        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UA"),
                        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
                    ])
                ).public_key(
                    self.cert_pub_key
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    datetime.datetime.utcnow()
                ).not_valid_after(
                    # the licence will be valid for 600 seconds
                    datetime.datetime.utcnow() + datetime.timedelta(seconds=600)
                ).sign(self.cert_priv_key, hashes.SHA256())
                
                # Return licence
                licence_b = binascii.b2a_base64(licence.public_bytes(Encoding.PEM)).decode('latin').strip()
                data = json.dumps({'licence': licence_b}).encode('latin')
                
                logger.debug(f'Client bought a new licence for media id {media_id}')
                
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return self.encrypt_request(session_id, data)

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
            
    
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
                
                if client_cert not in self.users:
                    self.users[client_cert] = [0]*2
                    self.users[client_cert][User.CC_TOKEN] = b''
                    logger.info('Registering client...')
                
                ciphers = data['ciphers']
                digests = data['digests']
                ciphermodes = data['ciphermodes']
                
                cipher, digest, ciphermode = self.choose_algorithms(ciphers, digests, ciphermodes)
                if cipher is None:
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'algorithm options are not supported'}, indent=4).encode('latin')

                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                
                p, g, session_id = self.diffie_hellman(2, 1024)
                
                session = self.sessions[session_id]
                session[Session.CIPHER] = cipher
                session[Session.MODE] = ciphermode
                session[Session.DIGEST] = digest
                session[Session.STATE] = State.HELLO
                session[Session.CERT] = client_cert

                if self.users[session[Session.CERT]][User.CC_TOKEN] == b'':
                    factors = {0: 'None', 1: 'CC Token'}
                else:
                    factors = {0: 'CC Token'}

                session[Session.CERT]
                
                return json.dumps({
                        'session_id': session_id,
                        'cipher': cipher,
                        'digest': digest,
                        'ciphermode': ciphermode,
                        'public_key': session[Session.PUB_KEY].public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
                        'parameters': {
                            'p': p,
                            'g': g,
                            'key_size': 1024,
                        },
                        '2-factor': factors,
                    }).encode("latin")

            elif request.path == b'/api/key_exchange':
                
                session_id = int(request.getHeader('Authorization'))
                session = self.sessions[session_id]
                
                if session[Session.STATE] != State.HELLO:
                    request.setResponseCode(401)
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'Unauthorized'}).encode('latin')
                
                cc_data = json.loads(binascii.a2b_base64(data['cc_data']))
                
                if '0' == cc_data['choice']:
                    logger.debug('No 2-factor chosen.')
                elif '1' == cc_data['choice']:
                    logger.debug('CC Token chosen for 2-factor authentication.')
                    
                    token = binascii.a2b_base64(cc_data['token'])
                    signed_token = binascii.a2b_base64(cc_data['signed_token'])
                    
                    client_cc_cert = x509.load_pem_x509_certificate(binascii.a2b_base64(cc_data['cc_cert']))
                    
                    # Can't validate this for all CC cards because we don't have
                    # all the intermediate CA's for them
                    logger.debug('Validating CC card...')
                    # if not self.ca.validate_cert(client_cc_cert):
                    #     logger.debug("Client's Certificate Invalid.")
                    #     request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    #     return json.dumps({'error': 'certificate invalid'}, indent=4).encode('latin')
                    
                    logger.debug("Client's Certificate Validated.")
                    
                    if not self.ca.check_signature(client_cc_cert.public_key(), token, signed_token, hashes.SHA1()):
                        logger.debug("Client's Signature Invalid.")
                        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                        return json.dumps({'error': 'something went wrong'}, indent=4).encode('latin')
                    
                    if self.users[session[Session.CERT]][User.CC_TOKEN] != b'':
                        # Check if it's equal to the one stored
                        if self.users[session[Session.CERT]][User.CC_TOKEN] != client_cc_cert:
                            logger.debug("Client's Certificate Invalid.")
                            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                            return json.dumps({'error': 'certificate invalid'}, indent=4).encode('latin')
                    else:
                        self.users[session[Session.CERT]][User.CC_TOKEN] = client_cc_cert
                        logger.debug('Sucessfully added 2-factor to this user.')
                
                session[Session.STATE] = State.KEY_EXCHANGE
                session[Session.CLIPUB_KEY] = data['public_key'].encode()
                client_public_key = load_pem_public_key(data['public_key'].encode())
                session[Session.SHARED_KEY] = session[Session.PRI_KEY].exchange(client_public_key)

                signed_public_key = binascii.a2b_base64(data['signed_public_key'].encode('latin'))
                
                if 'SHA-256' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA256()
                elif 'SHA-384' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA384()
                elif 'SHA-512' == session[Session.DIGEST]:
                    sign_digest = hashes.SHA512()
                  
                # Validate the signature of the client's DH public key
                if not self.ca.check_signature(session[Session.CERT].public_key(), session[Session.CLIPUB_KEY], signed_public_key, sign_digest):
                    request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                    return json.dumps({'error': 'something went wrong'}, indent=4).encode('latin')
                
                # Sign the DH public key
                signed_public_key = self.ca.make_signature(
                    self.cert_priv_key,
                    session[Session.PUB_KEY].public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
                    sign_digest
                )
                
                data = json.dumps({
                    'signed_public_key': binascii.b2a_base64(signed_public_key).decode('latin').strip()
                }).encode("latin")
                
                return self.encrypt_request(session_id, data)
                
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
            cipher = '3DES'
        elif 'AES' in ciphers:
            cipher = 'ChaCha20'
        elif '3DES' in ciphers:
            cipher = 'AES'
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
            ciphermode = 'ECB'
        elif 'ECB' in ciphermodes:
            ciphermode = 'CBC'
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

        digest_shared_key = hashes.Hash(digest)
        digest_shared_key.update(session[Session.SHARED_KEY])
        shared_key = digest_shared_key.finalize()
        
        if chunk_id is not None:
            shared_key = shared_key + bytes(chunk_id) + bytes(media_id)
            
        session[Session.SHARED_KEY] = shared_key
        derived_key = HKDF(
            algorithm=digest,
            length=64,
            salt=salt_init,
            info=b'handshake info',
        ).derive(shared_key)

        hmac_key = derived_key[len(derived_key)//2:]
        derived_key = derived_key[:len(derived_key)//2]

        return derived_key, hmac_key, salt


    def diffie_hellman(self, generator, key_size):
        parameters = dh.generate_parameters(generator=generator, key_size=key_size)
        
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # TODO: Check concurrency here...
        session_id = self.cur_session_id
        self.cur_session_id += 1
        self.sessions[session_id] = [None] * 10
        self.sessions[session_id][Session.PUB_KEY] = public_key
        self.sessions[session_id][Session.PRI_KEY] = private_key

        pn = parameters.parameter_numbers()

        return pn.p, pn.g, session_id


    def encrypt_data(self, session_id, derived_key, data): 
        key = derived_key
        session = self.sessions[session_id]
        cipher = session[Session.CIPHER]
        ciphermode = session[Session.MODE]

        if cipher == 'ChaCha20':
            mode = None
            iv = nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(key[:32], nonce)
        elif cipher == 'AES':
            iv = os.urandom(16) 
            algorithm = algorithms.AES(key[:32])
        elif cipher == '3DES':
            iv = os.urandom(8) 
            algorithm = algorithms.TripleDES(key[:24])

        if ciphermode == 'CBC':
            mode = modes.CBC(iv)
            #Padding is required when using this mode.
            data = self.padding(algorithm.block_size, data)
        elif ciphermode == 'ECB':
            mode = modes.ECB()
            #Padding is required when using this mode.
            data = self.padding(algorithm.block_size, data)
        
        encryptor = Cipher(algorithm, mode).encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return encrypted_data, iv


    def padding(self, block_size, data):
        padder = padding.PKCS7(block_size).padder()
        padded_data = padder.update(data)
        return padded_data + padder.finalize()
    
    
    def unpadder(self, block_size, data):
        unpadder = padding.PKCS7(block_size).unpadder()
        return unpadder.update(data) + unpadder.finalize()


    def decrypt_data(self, session_id, derived_key, iv, data): 
        key = derived_key
        session = self.sessions[session_id]
        cipher = session[Session.CIPHER]
        ciphermode = session[Session.MODE]

        if cipher == 'ChaCha20':
            mode = None
            algorithm = algorithms.ChaCha20(key[:32], iv)
        elif cipher == 'AES':
            algorithm = algorithms.AES(key[:32])
        elif cipher == '3DES':
            algorithm = algorithms.TripleDES(key[:24])

        if ciphermode == 'CBC':
            mode = modes.CBC(iv)
        elif ciphermode == 'ECB':
            mode = modes.ECB()

        decryptor = Cipher(algorithm, mode).decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        if ciphermode in {'CBC', 'ECB'}:
            data = self.unpadder(algorithm.block_size, data)
        
        return data


    def encrypt_request(self, session_id, data, media_id=None, chunk_id=None):
        """Encrypt a request with integrity validation.
        
        The parameters ``media_id`` and ``chunk_id`` are used during
        chunk based key rotation.
        """       
        derived_key, hmac_key, salt = self.gen_derived_key(session_id, media_id, chunk_id)
        data, iv = self.encrypt_data(session_id, derived_key, data)
        data = self.gen_MAC(session_id, hmac_key, data)

        ret = {
            'salt': binascii.b2a_base64(salt).decode('latin').strip(),
            'iv': binascii.b2a_base64(iv).decode('latin').strip(),
            'data': binascii.b2a_base64(data).decode('latin').strip(),
        }
        if chunk_id is not None:
            ret.update({'media_id': media_id.decode('latin'), 'chunk_id': int(chunk_id.decode('latin'))})
            
        return json.dumps(ret).encode('latin')


    def decrypt_response(self, session_id, data):
        """Validate the response integrity and then decrypt the data."""

        salt = binascii.a2b_base64(data['salt'].encode('latin'))
        iv = binascii.a2b_base64(data['iv'].encode('latin'))
        content = binascii.a2b_base64(data['data'].encode('latin'))
        
        derived_key, hmac_key, _ = self.gen_derived_key(session_id, salt=salt)
        data = self.verify_MAC(session_id, hmac_key, content)

        if not data:
            logger.debug("Integrity or authenticity compromised.")
            return {'error': 'unknown'}
        
        return json.loads(self.decrypt_data(session_id, derived_key, iv, data))


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()