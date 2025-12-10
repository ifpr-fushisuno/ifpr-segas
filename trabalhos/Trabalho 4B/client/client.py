import os
from secure_client import SecureClient

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certs")

CA_CERT = os.path.join(CERT_DIR, "certificado_Raiz.pem")

client = SecureClient(
    ca_cert_path= CA_CERT,
    server_url="http://127.0.0.1:8000",               
    expected_cn="Server"                               
)

resultado = client.authenticate_server()

if resultado:
    print("Autenticação realizada com sucesso")
else:
    print("Ocorreu uma falaha no processo de autenticação")

