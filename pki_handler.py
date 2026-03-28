# pki_handler.py
import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from config import CERTS_DIR


class PKIHandler:
    def __init__(self):
        # Paths for the University's Master Key and Certificate
        self.ca_key_file = os.path.join(CERTS_DIR, "root_ca_key.pem")
        self.ca_cert_file = os.path.join(CERTS_DIR, "root_ca.crt")
        # Ensure Root CA exists on startup
        self.generate_root_ca()

    def generate_root_ca(self):
        """Generates the University's Master Key pair if it doesn't exist."""
        if os.path.exists(self.ca_key_file) and os.path.exists(self.ca_cert_file):
            return

        print("[PKI] Generating University Root CA...")

        # 1. Generate Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # 2. Build Self-Signed Certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"University Root CA"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Secure Exam System"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)  # Valid for 1 year
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())

        # 3. Save to Disk
        with open(self.ca_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(self.ca_cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def issue_certificate(self, student_id):
        """Generates a key pair for a student and signs it with the Root CA."""

        # 1. Generate Student Identity Key
        student_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # 2. Load CA Authority
        with open(self.ca_key_file, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(self.ca_cert_file, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # 3. Create Certificate signed by CA
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, f"Student {student_id}"),
            x509.NameAttribute(x509.NameOID.USER_ID, str(student_id)),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            student_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=90)  # Valid for semester
        ).sign(ca_key, hashes.SHA256(), default_backend())

        # 4. Save paths
        key_path = os.path.join(CERTS_DIR, f"{student_id}_key.pem")
        cert_path = os.path.join(CERTS_DIR, f"{student_id}.crt")

        with open(key_path, "wb") as f:
            f.write(student_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return key_path, cert_path

    def verify_certificate(self, cert_path):
        """Verifies that a certificate is valid and signed by the University Root CA."""
        if not os.path.exists(cert_path):
            return False

        try:
            # Load Root CA (The Trust Anchor)
            with open(self.ca_cert_file, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Load Student Cert
            with open(cert_path, "rb") as f:
                student_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Crypto Check: Verify Signature using CA's Public Key
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                student_cert.signature,
                student_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                student_cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False
