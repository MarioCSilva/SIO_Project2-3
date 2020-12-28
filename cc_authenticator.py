import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

# lib ='/usr/local/lib/opensc-pkcs11.so'
lib = '/usr/local/lib/libpteidpkcs11.so'

class CC_Authenticator():
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

        slots = self.pkcs11.getSlotList()

        for slot in slots:
            print(self.pkcs11.getTokenInfo(slot))
            
        self.session = self.pkcs11.openSession(slot)
        
        all_attributes = list(PyKCS11.CKA.keys())
        all_attributes = [e for e in all_attributes if isinstance(e, int)]
        
        obj = self.session.findObjects([(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0]
        
        attributes = self.session.getAttributeValue(obj, all_attributes)
        attributes = dict(zip(map(PyKCS11.CKA.get, all_attributes), attributes))
        
        self.cert = x509.load_der_x509_certificate(bytes(attributes['CKA_VALUE']))

        self.cert_priv_key = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
                
    def get_certificate(self):
        return self.cert
    
    def get_signature(self, token):
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None) 
        return bytes(self.session.sign(self.cert_priv_key,  token, mech))