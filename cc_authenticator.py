import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

lib ='/usr/local/lib/opensc-pkcs11.so'

class CC_Authenticator():
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

        self.slots = self.pkcs11.getSlotList()

        for slot in self.slots:
            print(self.pkcs11.getTokenInfo(slot))
            self.all_attr = list(PyKCS11.CKA.keys())
            self.all_attr = [e for e in self.all_attr if isinstance(e, int)]
            
            self.attr_list = {}
            self.session = self.pkcs11.openSession(slot)

            for obj in self.session.findObjects():
                attr = self.session.getAttributeValue(obj, self.all_attr)

                attr = dict(zip(map(PyKCS11.CKA.get, self.all_attr), attr))

                print('Label:', attr['CKA_LABEL'])
                self.attr_list[attr['CKA_LABEL']] = attr
                if attr['CKA_LABEL']=='CITIZEN AUTHENTICATION CERTIFICATE':
                    self.cert = x509.load_der_x509_certificate(bytes(self.attr_list['CITIZEN AUTHENTICATION CERTIFICATE']['CKA_VALUE']), default_backend())
                    break
                
    def get_certificate(self):
        return self.cert