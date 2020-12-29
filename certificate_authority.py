import logging
import os
from os import scandir
from datetime import datetime

import cryptography
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
logger.setLevel(logging.WARNING)
logger.setLevel(logging.ERROR)
logger.setLevel(logging.DEBUG)

class CA:
    trusted_CA = '../rootCA/'
    intermediate = '../rootCA/intermediate'

    def __init__(self, crl_dir):
        self.ca_roots = {}
        self.ca_intermediate = {}
        
        # Certificates Revokation list Diretory
        self.crl_dir = crl_dir
        # Certificates Revokation list
        self.crl_certs = []

        self.load_certs(self.trusted_CA, trusted = True)
        self.load_certs(self.intermediate)


    def load_certs(self, certs_dir, trusted=False):
        for obj in scandir(certs_dir):
            if obj.is_dir() or not (any(x in obj.name for x in ['pem', 'cer', 'crt'])):
                continue
            cert, valid = self.load_cert(obj)
            if not valid:
                print(obj.name)
                continue
            if trusted:
                self.ca_roots[cert.subject.rfc4514_string()] = cert
            else:
                self.ca_intermediate[cert.subject.rfc4514_string()] = cert


    def load_cert(self, file): 
        logger.debug(f'Loading {file}')

        now = datetime.now()

        with open(file, 'rb') as fp:
            pem_data = fp.read()
            if '.cer' in file.name:
                cert = x509.load_der_x509_certificate(pem_data)
            else:
                cert = x509.load_pem_x509_certificate(pem_data)

        if cert.not_valid_after < now:
            # print(file, "EXPIRED (", cert.not_valid_after, ')') 
            return cert, False
        else:
            return cert, True   


    def validate_cert(self, cert):
        logger.debug(f'Validating {cert.subject.rfc4514_string()}')

        # load current crl
        self.crl_cert = []
        self.load_crl()

        chain = self.get_chain(cert, [])
        is_valid = self.validate_chain(chain)

        return is_valid


    def load_crl(self):
        for obj in scandir(self.crl_dir):
            if obj.is_dir() or not (any(ext in obj.name for ext in ['crl'])):
                continue
            crl_cert = self.load_crl_cert(obj)
            self.crl_certs.append(crl)


    def load_crl_cert(self, file):
        with open(file, 'rb') as fp:
            crl_cert_data = fp.read()
            crl_cert = x509.load_der_x509_crl(crl_cert_data, default_backend())
        return crl_cert


    def get_chain(self, cert, chain):
        chain.append(cert)
        
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        # Check if this certificate is self signed
        # if it is, then the chain is complete
        if issuer == subject and subject in self.ca_roots:
            return chain
        # check if the issuer is in the trusted certificates
        logger.debug(issuer)
        if issuer in self.ca_roots:
            return self.get_chain(self.ca_roots[issuer], chain)
        elif issuer in self.ca_intermediate:
            return self.get_chain(self.ca_intermediate[issuer], chain)
        # Couldn't find this Certificate so it's hardcoded here
        elif issuer == 'CN=ECRaizEstado,O=SCEE,C=PT' or 'CN=ECRaizEstado 002,O=Sistema de Certificação Eletrónica do Estado,C=PT':
            return chain


    def validate_chain(self, chain):
        if len(chain) == 1:
            return True

        cert = chain[0]
        cert_issuer = chain[1]

        try:
            # verify signature
            cert_issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except cryptography.exceptions.InvalidSignature:
            return False

        for crl in self.crl_certs:
            # verify cert in crl expiration
            if datetime.now() > crl.next_update:
                logger.debug(f"{cert.subject.rfc4514_string()} is expired")
                continue
            # verify if cert is revoked
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                logger.debug(f"{cert.subject.rfc4514_string()} has been revoked")
                return False

        return self.validate_chain(chain[1:])


    def validate_cert_signature(self, cert, issuer_cert):
        """Verify if the certificate signature belongs to the issuer."""
        
        cert_signature = cert.signature
        issuer_public_key = issuer_cert.public_key()

        try:
            issuer_public_key.verify(
                cert_signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except:
            return False

        return True
    

    def make_signature(self, private_key, message, digest):
        """Sign a message with a private key.
        
        :return: a signature
        """
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(digest),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            digest
        )
        

    def check_signature(self, public_key, message, signature, digest) -> bool:
        """Validate a signature given a private key and the original message."""
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(digest),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                digest
            )
        except InvalidSignature:
            return False
        return True
