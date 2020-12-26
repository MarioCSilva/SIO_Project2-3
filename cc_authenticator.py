import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

lib ='/usr/local/lib/libpteidpkcs11.so'

class CC_Authenticator():
    def __init__(self):
        # lib ='/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

        try:
            self.slots = self.pkcs11.getSlotList()

            for slot in self.slots:
                print(self.pkcs11.getTokenInfo(slot))

            self.all_attr = list(PyKCS11.CKA.keys())
            #Filter attributes
            self.all_attr = [e for e in self.all_attr if isinstance(e, int)]
            
            self.attr_list = {}
            self.session = self.pkcs11.openSession(slot)

            '''def get_attr_list(self):'''
            for obj in self.session.findObjects():
                # Get object attributes
                attr = self.session.getAttributeValue(obj, self.all_attr)

                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, self.all_attr), attr))

                print('Label:', attr['CKA_LABEL'])
                # if attr['CKA_LABEL'].decode() == 'CITIZEN AUTHENTICATION CERTIFICATE':
                #     print('EEEEEIIIIIIII')
                self.attr_list[attr['CKA_LABEL'].decode()] = attr
            '''end'''
        except:
            print('Smart Card Reader not found.')
            return False

        self._private_key = None

        '''def fetch_pk(self):'''
        # print(self.attr_list['CITIZEN AUTHENTICATION KEY'])
        # print(load_pem_private_key(bytes(self.attr_list['CITIZEN AUTHENTICATION KEY']), password=None, backend=default_backend()))
        self._private_key = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')]
            )[0]
        # self._private_key = self.attr_list['CITIZEN AUTHENTICATION KEY']['CKA_VALUE']
        # print(self._private_key)
        '''end'''

        self.cert = None

    def private_key(self):
        return self._private_key

    def sign_text(self, text):
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        # text = b'text to sign'

        signature = bytes(self.session.sign(self._private_key, text, mechanism))
        print(signature)
        return signature

    def get_certificate(self):
        if not self.cert:
            # self.cert = x509.load_der_x509_certificate(bytes(self.attr_list['CITIZEN AUTHENTICATION CERTIFICATE']['CKA_VALUE']), default_backend())
            self.cert = x509.load_der_x509_certificate(bytes(self.attr_list['CITIZEN AUTHENTICATION CERTIFICATE']['CKA_VALUE']), default_backend())
        # self.cert.public_key().verify(self.sign_text(b'ola'), b'ola', padding.PKCS1v15(),  hashes.SHA1())
        return self.cert