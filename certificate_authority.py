import logging
import os
from os import scandir
from datetime import datetime

import cryptography
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
        #self.certs_path = certs_path
        self.ca_roots = {}
        self.ca_intermediate = {}
        
        # Certificates Revokation list Diretory
        self.crl_dir = crl_dir
        # Certificates Revokation list
        self.crl_certs = []

        self.load_certs(self.trusted_CA, trusted = True)
        self.load_certs(self.intermediate)
        
        # # server
        # self.validator = Certificate_Validator(['/etc/ssl/certs/'], ['certs/server/PTEID/'], 'certs/server/crls/')

        # # client
        # self.validator = Certificate_Validator(['/etc/ssl/certs/', 'certs/client/server_certs/'], [], 'certs/client/crls/')


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
        logger.debug(chain)
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
        if issuer in self.ca_roots:
            return self.get_chain(self.ca_roots[issuer], chain)
        elif issuer in self.ca_intermediate:
            return self.get_chain(self.ca_intermediate[issuer], chain)
        # Couldn't find this Certificate so it's hardcoded here
        elif issuer == 'CN=ECRaizEstado,O=SCEE,C=PT':
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







# ########################################   TOMAS   ################################################
# ########################################   TOMAS   ################################################
# ########################################   TOMAS   ################################################

#     def __init__(self, trusted_cert_list, cert_list, crls_path='certs/crls'):
#         self.roots = {}
#         self.intermediate_certs = {}
#         self.crls = []

#         self.crls_path = crls_path

#         for d in trusted_cert_list:
#             self.load_certificates(d, trusted=True)
#         for d in cert_list:
#             self.load_certificates(d)
#         # for d in crl_list:
#         #     self.load_crls(d)
#         #     print(f'Loaded {d}')

#     def load_certificate(self, file_name): 
#         now = datetime.datetime.now()

#         with open(file_name, 'rb') as f:
#             pem_data = f.read()
#             if '.cer' in file_name.name:
#                 cert = x509.load_der_x509_certificate(pem_data, default_backend())
#             else:
#                 cert = x509.load_pem_x509_certificate(pem_data, default_backend())
#             # cert = x509.load_pem_x509_certificate(pem_data, default_backend())

#         # print(f"Loaded {cert.subject} {cert.serial_number}")
#         # print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")

#         if cert.not_valid_after < now:
#             # print(file_name, "EXPIRED (", cert.not_valid_after, ')') 
#             return cert, False
#         else:
#             return cert, True       
            
#     def load_crl(self, file_name):
#         with open(file_name, 'rb') as f:
#             crl_data = f.read()
#             # crl = x509.load_pem_x509_crl(crl_data, default_backend())
#             crl = x509.load_der_x509_crl(crl_data, default_backend())
#         return crl

#     def build_chain(self, chain, cert):
#         chain.append(cert)

#         issuer = cert.issuer.rfc4514_string()
#         subject = cert.subject.rfc4514_string()

#         if issuer == subject and subject in self.roots:
#             return chain

#         if issuer in self.roots:
#             return self.build_chain(chain, self.roots[issuer])
#         elif issuer in self.intermediate_certs:
#             return self.build_chain(chain, self.intermediate_certs[issuer])

#     def validate_chain(self, chain):
#         if len(chain) == 1:
#             return True

#         cert = chain[0]
#         issuer = chain[1]

#         try:
#             issuer.public_key().verify(
#                 cert.signature,
#                 cert.tbs_certificate_bytes,
#                 padding.PKCS1v15(),
#                 cert.signature_hash_algorithm,
#             )
#         except cryptography.exceptions.InvalidSignature:
#             return False

#         now = datetime.datetime.now()
#         for crl in self.crls:
#             if now > crl.next_update:
#                 print(cert.subject.rfc4514_string(), 'is outdated')
#                 continue
#             if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
#                 print(cert.subject.rfc4514_string(), 'has been revoked')
#                 return False

#         return self.validate_chain(chain[1:])

#     def load_certificates(self, dir_name, trusted=False):
#         for entry in scandir(dir_name):
#             if entry.is_dir() or not (any(x in entry.name for x in ['pem', 'cer', 'crt'])):
#                 continue
#             c, valid = self.load_certificate(entry)
#             if not valid:
#                 continue
#             if trusted:
#                 self.roots[c.subject.rfc4514_string()] = c
#             else:
#                 self.intermediate_certs[c.subject.rfc4514_string()] = c

#     def load_crls(self, dir_name):
#         for entry in scandir(dir_name):
#             if entry.is_dir() or not (any(x in entry.name for x in ['crl'])):
#                 continue
#             crl = self.load_crl(entry)
#             self.crls.append(crl)
# ####################################333
#     def load_crls_cert(self, cert):
#         try:
#             for ext in cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
#                 for name in ext.full_name:
#                     fname = wget.download(name.value, self.crls_path)
#                     print(fname)
#         except:
#             print('No CRLs found')

#         try:
#             for ext in cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
#                 for name in ext.full_name:
#                     fname = wget.download(name.value, self.crls_path)
#                     print(fname)
#         except:
#             print('No Delta CRLs found.')

#         self.load_crls(self.crls_path)
#         self.clear_crls_cert()

#     def clear_crls_cert(self):
#         import glob

#         files = glob.glob(self.crls_path + '*')
#         for f in files:
#             print('Removing', f)
#             remove(f)
# ##################################################33
#     def validate_certificate(self, cert):
#         print(f'Validating certificate from {cert.subject.rfc4514_string()}')
#         self.crls = []
#         self.load_crls_cert(cert)

#         chain = self.build_chain([], cert)
#         is_valid = self.validate_chain(chain)

#         return is_valid




















# ########################################   VASCO   ################################################
# ########################################   VASCO   ################################################
# ########################################   VASCO   ################################################


#     def rsa_signing(message, private_key):
#         """
#         Function used to sign a message with a private key
#         :param message: The message to be signed
#         :param private_key: The private_key used to sign the message
#         :return: The result signature.
#         """
#         signature = private_key.sign(
#             message,
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256(),
#         )
#         return signature


#     def validate_rsa_signature(signature, message, public_key):
#         """
#         Function used to verify signature validation
#         :param signature: The signrature to be validated
#         :param message: The cypher algorithm used
#         :param public_key: The cypher mode used
#         :return: True if validation successfull, False if not
#         """
#         try:
#             public_key.verify(
#                 signature,
#                 message,
#                 padding.PSS(
#                     mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
#                 ),
#                 hashes.SHA256(),
#             )
#         except:
#             logger.error("Signature verification failed")
#             return False

#         return True


#     def get_issuer_common_name(cert):
#         """
#         Function used to retrieve the common name of the issuer of a given certificate.
#         :param cert: The certificate.
#         :return: If it exists, the common name. Otherwise, None.
#         """
#         try:
#             names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
#             return names[0].value
#         except x509.ExtensionNotFound:
#             return None


#     def get_common_name(cert):
#         """
#         Function used to retrieve the common name of a given certificate.
#         :param cert: The certificate.
#         :return: If it exists, the common name. Otherwise, None.
#         """
#         try:
#             names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
#             return names[0].value
#         except x509.ExtensionNotFound:
#             return None


#     def validate_certificate_common_name(cert, issuer):
#         """
#         Function used to check if the certificate's common name and the issuer's common name are equal.
#         :param cert: The certificate.
#         :param issuer: The issuer.
#         :return: True if are equal. False, otherwise.
#         """
#         return get_issuer_common_name(cert) == get_common_name(issuer)


#     def validate_certificate_signature(cert, issuer):
#         """
#         Function used to check if the signature of the certificate if correct.
#         :param cert: The certificate.
#         :param issuer: The issuer.
#         :return: True if is verified successfully. False, otherwise.
#         """
#         cert_signature = cert.signature
#         issuer_public_key = issuer.public_key()

#         try:
#             issuer_public_key.verify(
#                 cert_signature,
#                 cert.tbs_certificate_bytes,
#                 padding.PKCS1v15(),
#                 cert.signature_hash_algorithm,
#             )
#         except:
#             return False

#         return True


#     def load_private_from_pem(filename):
#         """
#         Function used to load a private key from a given file.
#         :param filename: The name of the file that contains the information.
#         :return: The private key object.
#         """
#         with open(filename, "rb") as f:
#             private_key = serialization.load_pem_private_key(
#                 f.read(), password=None, backend=default_backend()
#             )
#         return private_key


#     def load_public_from_pem(pem):
#         """
#         Function used to load a public key from a given file.
#         :param filename: The name of the file that contains the information.
#         :return: The public key object.
#         """
#         public_key = serialization.load_pem_public_key(pem, backend=default_backend())
#         return public_key


#     def validate_certificate(cert):
#         """
#         Function used to validate a given certificate.
#         :param cert: The ciphertext to decrypt
#         :return: True, if the current timestamp is between the limits of validity of the certificate. False, otherwise.
#         """
#         today = datetime.now().timestamp()
#         return (
#             cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()
#         )


#     def load_certificate(filename):
#         """
#         Function used to load a certificate from a given file (tries pem and der).
#         :param filename: The name of the file that contains the information.
#         :return: The certificate object.
#         """
#         try:
#             with open(filename, "rb") as pem_file:
#                 pem_data = pem_file.read()
#                 cert = x509.load_pem_x509_certificate(pem_data, default_backend())
#             return cert
#         except:
#             logger.warning("Not pem!")

#         try:
#             with open(filename, "rb") as pem_file:
#                 pem_data = pem_file.read()
#                 cert = x509.load_der_x509_certificate(pem_data, default_backend())
#             return cert
#         except:
#             logger.warning("Not der!")


#     def load_certificate_bytes(cert_bytes):
#         """
#         Function used to load a certificate in pem from the respective bytes.
#         :param cert_bytes: The certificate bytes.
#         :return: The certificate object.
#         """
#         return x509.load_pem_x509_certificate(cert_bytes, default_backend())


#     def get_certificate_bytes(cert):
#         """
#         Fuction used to convert a certificate object to it's respective bytes format.
#         :param cert: The certificate to convert.
#         :return: The certificate bytes.
#         """
#         return cert.public_bytes(crypto_serialization.Encoding.PEM)


#     def build_chain(chain, cert, intermediate_certs, roots):
#         """
#         Function used to build the chain of certificates from the base cert all the way to the root.
#         """
#         chain.append(cert)

#         issuer = cert.issuer.rfc4514_string()
#         subject = cert.subject.rfc4514_string()

#         if issuer == subject and subject in roots:
#             return

#         if issuer in intermediate_certs:
#             return build_chain(chain, intermediate_certs[issuer], intermediate_certs, roots)

#         if issuer in roots:
#             return build_chain(chain, roots[issuer], intermediate_certs, roots)

#         return


#     def validate_server_chain(base_cert, root_cert, intermediate_certs, roots, chain):
#         """
#         Function used to validate a chain of certificates.
#         For each certificate, we validate the certificate itself, it's purpose, the common name and if it is revoked.
#         :return: True if valid. False, otherwise.
#         """
#         roots[root_cert.subject.rfc4514_string()] = root_cert

#         build_chain(chain, base_cert, intermediate_certs, roots)

#         for idx, cert in enumerate(chain):
#             val_cert = validate_certificate(cert)
#             if not val_cert:
#                 return False

#             val_puprose = validate_server_purpose(cert, idx)
#             if not val_puprose:
#                 return False

#         for i in range(0, len(chain) - 1):
#             val_signature = validate_certificate_signature(chain[i], chain[i + 1])
#             if not val_signature:
#                 return False

#             val_common_name = validate_certificate_common_name(chain[i], chain[i + 1])
#             if not val_common_name:
#                 return False

#             val_revocation = validate_revocation(chain[i], chain[i + 1])
#             if val_revocation:
#                 return False

#         return val_cert and val_signature and val_common_name


#     def load_certificate_crl(filename):
#         """
#         Function used to load the crl of a certificate from a given file (tries pem and der).
#         :param filename: The name of the file that contains the information.
#         :return: The crl of the certificate.
#         """
#         try:
#             with open(filename, "rb") as pem_file:
#                 pem_data = pem_file.read()
#                 cert = x509.load_pem_x509_crl(pem_data, default_backend())
#             return cert
#         except:
#             logger.debug("Not pem!")

#         try:
#             with open(filename, "rb") as pem_file:
#                 pem_data = pem_file.read()
#                 cert = x509.load_der_x509_crl(pem_data, default_backend())
#             return cert
#         except:
#             logger.debug("Not der!")
#         return cert


#     def validate_revocation(cert, issuer):
#         """
#         Function used to check if a given certificate (or it's issuer) is revoked.
#         :return: True, if it's revoked. False, otherwise.
#         """
#         try:
#             builder = ocsp.OCSPRequestBuilder()

#             builder = builder.add_certificate(cert, issuer, SHA1())
#             req = builder.build()

#             for ext in cert.extensions.get_extension_for_class(
#                 x509.AuthorityInformationAccess
#             ).value:
#                 if ext.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
#                     data = req.public_bytes(serialization.Encoding.DER)

#                     ocsp_url = ext.access_location.value
#                     request = requests.post(
#                         ocsp_url,
#                         headers={"Content-Type": "application/ocsp-request"},
#                         data=data,
#                     )

#                     ocsp_resp = ocsp.load_der_ocsp_response(request.content)
#                     logger.warning(f"OCSP CERT STATUS: {ocsp_resp.certificate_status}")

#                     if (
#                         ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD
#                         or get_common_name(cert) == "ECRaizEstado"
#                     ):
#                         return False
#                     else:
#                         return True
#         except:
#             logger.debug("OCSP is not available for this certificate!")

#         try:
#             for ext in cert.extensions.get_extension_for_class(
#                 x509.CRLDistributionPoints
#             ).value:
#                 for name in ext.full_name:
#                     file_name = wget.download(name.value)

#                     revocation_list = load_certificate_crl(file_name)

#                     if revocation_list is None:
#                         return False

#                     cert_is_revoked = cert.serial_number in [
#                         l.serial_number for l in revocation_list
#                     ]
#             try:
#                 for ext in cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
#                     for name in ext.full_name:
#                         file_name = wget.download(name.value)

#                         revocation_list = load_certificate_crl(file_name)

#                         if revocation_list is None:
#                             return False

#                         cert_is_revoked = cert.serial_number in [
#                             l.serial_number for l in revocation_list
#                         ]
#             except:
#                 logger.debug("DELTA CRL is not available for this certificate!")

#             for ext in issuer.extensions.get_extension_for_class(
#                 x509.CRLDistributionPoints
#             ).value:
#                 for name in ext.full_name:
#                     file_name = wget.download(name.value)

#                     revocation_list = load_certificate_crl(file_name)

#                     if revocation_list is None:
#                         return False

#                     isser_is_revoked = issuer.serial_number in [
#                         l.serial_number for l in revocation_list
#                     ]

#             try:
#                 for ext in issuer.extensions.get_extension_for_class(
#                     x509.FreshestCRL
#                 ).value:
#                     for name in ext.full_name:
#                         file_name = wget.download(name.value)

#                         revocation_list = load_certificate_crl(file_name)

#                         if revocation_list is None:
#                             return False

#                         isser_is_revoked = issuer.serial_number in [
#                             l.serial_number for l in revocation_list
#                         ]
#             except:
#                 logger.debug("DELTA CRL is not available for this certificate!")

#             return cert_is_revoked or isser_is_revoked
#         except:
#             logger.debug("CRL is not available for this certificate!")

#         return True


#     def validate_server_purpose(cert, indx):
#         """
#         Function that checks if the given has the right purpose.
#         :return: True, if it has. False, otherwise.
#         """
        
#         if indx == 0:
#             for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
#                 if c.dotted_string == "1.3.6.1.5.5.7.3.1":
#                     return True
#             return False
#         else:
#             return cert.extensions.get_extension_for_class(
#                 x509.KeyUsage
#             ).value.key_cert_sign




    
















# ########################################   LARANJO   ################################################
# ########################################   LARANJO   ################################################
# ########################################   LARANJO   ################################################


#     def load_certificate(self, fname):
#         with open(fname, 'rb') as f:
#             cert_data = f.read()
#             cert = x509.load_pem_x509_certificate(cert_data, default_backend())
#         #print("Loaded : ", cert)
#         return cert

#     def load_cert(self, fname):
#         with open(fname, 'rb') as f:
#             cert_data = f.read()
#             cert = x509.load_pem_x509_certificate(cert_data, default_backend())

#         cert = cert.public_bytes(Encoding.PEM)
#         return cert

#     def load_crl(self, fname):
#         with open(fname, 'rb') as f:
#             crl_data = f.read()
#             crl = x509.load_der_x509_crl(crl_data, default_backend())

#         return crl

#     def get_certificate_dates(self, certificate):
#         dates = (certificate.not_valid_before.timestamp(),
#             certificate.not_valid_after.timestamp())
#         return dates

#     def validate_certificate(self, certificate):
#         dates = self.get_certificate_dates(certificate)
#         if datetime.now().timestamp() < dates[0] or datetime.now().timestamp() > dates[1]:
#             return False
#         else:	
#             return True

#     def validate_signatures(self, certificate, issuer_certificate):

#         issuer_public_key = issuer_certificate.public_key()

#         try:
#             issuer_public_key.verify(
#                 certificate.signature,
#                 certificate.tbs_certificate_bytes,
#                 # Depends on the algorithm used to create the certificate
#                 padding.PKCS1v15(),
#                 certificate.signature_hash_algorithm,
#             )
#             return True
#         except Exception as e:
#             print(e)
#             return False

#     def validate_common_name(self, certificate, issuer_certificate):

#         issuer_common_name = issuer_certificate.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value
#         certificate_issuer_common_name = certificate.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value

#         if issuer_common_name == certificate_issuer_common_name:
#             return True
#         return False

#     def validate_purpose(self, certificate):
#         key_cert_sign = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign
#         return key_cert_sign

#     def crl_validation(self, crl, certificate):
#         result = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
#         if result is None:
#             return True ## not in the list
#         else:
#             return False ## is revoked doesn't pass the verification 


#     def send_cert(self) -> bool:
#         self.server_cert = self.load_cert('Servidor.crt')
#         encoded_cert = base64.b64encode(self.server_cert).decode()
#         message = {'type': 'OK', 'subtype': 'CERT', 'certificate': encoded_cert}
#         self._send(message)
#         self.state = STATE_CERT

#         return True

# '''
#     def receive_hashed_challenge(self, message) -> bool:
#             client_auth = base64.b64decode(message.get('challenge'))

#             h = hmac.HMAC(self.user_pwd, hashes.SHA512(), backend=default_backend())
#             h.update(self.nonce)
#             hashed_challenge = h.finalize()

#             if hashed_challenge == client_auth:
#                 message = {'type': 'OK', 'subtype': 'AUTHENTICATION', 'value': True}
#                 self._send(message)
#                 self.state = STATE_OPEN	
#                 return True
#             else:
#                 message = {'type': 'OK', 'subtype': 'AUTHENTICATION', 'value': False}
#                 self.transport.close()
#                 return False
# '''          

#     def build_chain(self, certificate, chain=[]):
#         chain.append(certificate)

#         issuer = certificate.issuer.rfc4514_string()
#         subject = certificate.subject.rfc4514_string()

#         if issuer == subject and subject in self.roots:
#             #print("Chain complete")
#             return chain
    
#         if issuer in self.intermediates:
#             return self.build_chain(self.intermediates[issuer], chain)
#         elif issuer in self.roots:
#             return self.build_chain(self.roots[issuer], chain)

#         print("Unable to create the Trust Chain")
#         return chain

#     def load_dicts(self, cert):
#         for entry in os.scandir("/etc/ssl/certs"):
#             if not entry.is_dir():
#                 cert = self.load_certificate(entry)
#             if self.validate_certificate(cert):
#                self.roots[cert.subject.rfc4514_string()] = cert


#         for entry in os.scandir("/home/user/Desktop/projeto3/sio_p3/pem"):
#             if not entry.is_dir():
#                 cert = self.load_certificate(entry)
#             if self.validate_certificate(cert):
#                 self.intermediates[cert.subject.rfc4514_string()] = cert


#     def crl_validation(self, crl, certificate):
#         result = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
#         if result is None:
#             return True ## not in the list
#         else:
#             return False ## is revoked doesn't pass the verification

#     def validate_chain(self, chain):
#         dates_valid = True
#         purpose_valid = True
#         signature_valid = True
#         crl_valid = True
        
#         crl = self.load_crl('cc_ec_cidadao_crl004_crl.crl')

#         for cert in chain:
#             crl_result = self.crl_validation(crl, cert)
#             if not crl_result:
#                 crl_valid = False

#             dates = self.validate_certificate(cert)
#             if not dates:
#                 dates_valid = False
        
#         cc_base_cert = chain[0].extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.digital_signature

#         for i in range(1, len(chain)):     
#             purpose = self.validate_purpose(chain[i])
#             if not purpose:
#                 purpose_valid = False

#         for i in range(0, len(chain) -1):
#             signature_valid = self.validate_signatures(chain[i], chain[i+1])
#             if not signature_valid:
#                 signature_valid = False
        
#         if dates_valid and purpose_valid and cc_base_cert and signature_valid and crl_valid:
#             return True
#         else:
#             return False 

#     ## verify the client certificate
#     def validate_client_cert(self, message) -> bool:

#         encoded_cert = message.get('certificate')
#         cert = x509.load_pem_x509_certificate(base64.b64decode(encoded_cert), default_backend())
#         self.client_cert = cert
#         self.user_cc = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
#         print(self.user_cc)
#         #print(cert.issuer.rfc4514_string())
#         self.load_dicts(cert)
        
#         chain = self.build_chain(cert)
#         #print(chain)
#         validation_result = self.validate_chain(chain)
        
#         if validation_result:
#             self.nonce = os.urandom(32)
#             encoded_nonce = base64.b64encode(self.nonce).decode()
#             message = {'type': 'OK', 'subtype': 'NONCE_SV', 'nonce': encoded_nonce}
#             self._send(message)
#             self.state = STATE_CLIENT_CERT

#         else:
#             self.transport.close()
        
#         return True