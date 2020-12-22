from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CA:
    first_time = True

    def __init__(self)
        
        if self.first_time:
            # Generate our key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Write our key to disk for safe keeping
            with open("./key.pem", "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(b"x!Aj@^HxS04vx3GRAp@i"),
                ))
            # Various details about who we are. For a self-signed certificate the
            # subject and issuer are always the same.
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Aveiro"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DETI"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"SIO_ROOT_CA"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 1 year
                datetime.datetime.utcnow() + datetime.timedelta(days=30)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            # Sign our certificate with our private key
            ).sign(key, hashes.SHA256())
            # Write our certificate out to disk.
            with open("./certificate.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))  

        else:



##### SERVER
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write our key to disk for safe keeping
    with open("path/to/store/key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"{SERVER_URL}"),
    ]))  
    # Sign the CSR with our private key.
    .sign(key, hashes.SHA256())
    
    # Write our CSR out to disk.
    with open("path/to/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


    def __init__(self, trusted_cert_list, cert_list, crls_path='certs/crls'):
        self.roots = {}
        self.intermediate_certs = {}
        self.crls = []

        self.crls_path = crls_path

        for d in trusted_cert_list:
            self.load_certificates(d, trusted=True)
        for d in cert_list:
            self.load_certificates(d)
        # for d in crl_list:
        #     self.load_crls(d)
        #     print(f'Loaded {d}')

    def load_certificate(self, file_name): 
        now = datetime.datetime.now()

        with open(file_name, 'rb') as f:
            pem_data = f.read()
            if '.cer' in file_name.name:
                cert = x509.load_der_x509_certificate(pem_data, default_backend())
            else:
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            # cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        # print(f"Loaded {cert.subject} {cert.serial_number}")
        # print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")

        if cert.not_valid_after < now:
            # print(file_name, "EXPIRED (", cert.not_valid_after, ')') 
            return cert, False
        else:
            return cert, True       
            
    def load_crl(self, file_name):
        with open(file_name, 'rb') as f:
            crl_data = f.read()
            # crl = x509.load_pem_x509_crl(crl_data, default_backend())
            crl = x509.load_der_x509_crl(crl_data, default_backend())
        return crl

    def build_chain(self, chain, cert):
        chain.append(cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        if issuer == subject and subject in self.roots:
            return chain

        if issuer in self.roots:
            return self.build_chain(chain, self.roots[issuer])
        elif issuer in self.intermediate_certs:
            return self.build_chain(chain, self.intermediate_certs[issuer])

    def validate_chain(self, chain):
        if len(chain) == 1:
            return True

        cert = chain[0]
        issuer = chain[1]

        try:
            issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except cryptography.exceptions.InvalidSignature:
            return False

        now = datetime.datetime.now()
        for crl in self.crls:
            if now > crl.next_update:
                print(cert.subject.rfc4514_string(), 'is outdated')
                continue
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                print(cert.subject.rfc4514_string(), 'has been revoked')
                return False

        return self.validate_chain(chain[1:])

    def load_certificates(self, dir_name, trusted=False):
        for entry in scandir(dir_name):
            if entry.is_dir() or not (any(x in entry.name for x in ['pem', 'cer', 'crt'])):
                continue
            c, valid = self.load_certificate(entry)
            if not valid:
                continue
            if trusted:
                self.roots[c.subject.rfc4514_string()] = c
            else:
                self.intermediate_certs[c.subject.rfc4514_string()] = c

    def load_crls(self, dir_name):
        for entry in scandir(dir_name):
            if entry.is_dir() or not (any(x in entry.name for x in ['crl'])):
                continue
            crl = self.load_crl(entry)
            self.crls.append(crl)

    def load_crls_cert(self, cert):
        try:
            for ext in cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
                for name in ext.full_name:
                    fname = wget.download(name.value, self.crls_path)
                    print(fname)
        except:
            print('No CRLs found')

        try:
            for ext in cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
                for name in ext.full_name:
                    fname = wget.download(name.value, self.crls_path)
                    print(fname)
        except:
            print('No Delta CRLs found.')

        self.load_crls(self.crls_path)
        self.clear_crls_cert()

    def clear_crls_cert(self):
        import glob

        files = glob.glob(self.crls_path + '*')
        for f in files:
            print('Removing', f)
            remove(f)

    def validate_certificate(self, cert):
        print(f'Validating certificate from {cert.subject.rfc4514_string()}')
        self.crls = []
        self.load_crls_cert(cert)

        chain = self.build_chain([], cert)
        is_valid = self.validate_chain(chain)

        return is_valid