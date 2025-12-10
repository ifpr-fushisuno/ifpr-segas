from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import CertificateBuilder, Name, SubjectAlternativeName, KeyUsage
from datetime import datetime, timedelta
import os

def generate_ca(cert_path="certificado_RaizIFPR_teste.pem", key_path="private_key_RaizIFPR.pem"):
    # Gerar chave privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salvar chave privada
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Criar certificado autoassinado
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"PR"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"Cascavel"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"IFPR"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u"ifpr.cascavel@ifpr.edu.br"),
        x509.NameAttribute(x509.oid.NameOID.BUSINESS_CATEGORY, u"Educacao"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"ifpr.edu.br"),
    ])
    issuer = subject
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=365*2)

    certificate = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_until
    ).add_extension(
        SubjectAlternativeName([x509.DNSName(u"alternativo.ifpr.edu.br")]),
        critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Salvar certificado
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    return certificate, private_key

def generate_server_cert(ca_cert, ca_key, cert_path="certificado_ThiagoLo.pem", key_path="private_key_ThiagoLo.pem"):
    # Gerar chave privada do servidor
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Salvar chave privada
    with open(key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Criar certificado
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"PR"),
        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, u"Cascavel"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u"IFPR"),
        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, u"thiago.lol@ifpr.edu.br"),
        x509.NameAttribute(x509.oid.NameOID.BUSINESS_CATEGORY, u"Educacao"),
        x509.NameAttribute(x509.oid.NameOID.TITLE, u"Professor"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Thiago Berticelli Lo"),
    ])
    valid_from = datetime.utcnow()
    valid_until = valid_from + timedelta(days=365)

    key_usage = KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )

    server_cert = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_until
    ).add_extension(
        key_usage,
        critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Salvar certificado
    with open(cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    return server_cert, server_key

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert

def load_certificates(cert_paths):
    certificates = []
    for path in cert_paths:
        certificates.append(load_cert(path))
    return certificates

def validate_chain(certificates, expected_cn=None):
    for i in range(len(certificates) - 1):
        current_cert = certificates[i]
        issuer_cert = certificates[i + 1]

        if expected_cn:
            cn = current_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if cn != expected_cn:
                return False, f"CN esperado {expected_cn}, encontrado {cn}"

        key_usage = current_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        if key_usage:
            if not key_usage.value.digital_signature:
                return False, "Certificado não pode ser usado para assinatura digital"

        try:
            issuer_cert.public_key().verify(
                current_cert.signature,
                current_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                current_cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"Assinatura inválida: {str(e)}"

    return True, "Cadeia válida"


def encrypt_with_cert(cert, message: bytes):
    pub_key = cert.public_key()
    ciphertext = pub_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_private_key(private_key_path, ciphertext: bytes):

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
