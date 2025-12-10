import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

import requests
import base64
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from datetime import datetime

from modules.certs_module import load_cert, validate_chain

class SecureClient:

    def __init__(self, ca_cert_path, server_url, expected_cn="localhost"):
        self.server_url = server_url
        self.expected_cn = expected_cn
        self.ca_cert_path = ca_cert_path

    #busca certificado no servidor
    def fetch_server_certificate(self):
        print("\nBuscando certificado")

        url = f"{self.server_url}/certificado" #url de requisição para o sever
        r = requests.get(url)

        if r.status_code != 200:
            raise Exception(f"Erro: certificado não encontrado {r.status_code}")

        cert_b64 = r.json().get("certificado") 
        if not cert_b64:
            raise Exception("Resposta não contém campo 'certificado'.")

        cert_bytes = base64.b64decode(cert_b64)
        print("Certificado foi recebido e decodificado.")
        return cert_bytes

    #Processo de validação do certificado
    def validate_certificate(self, cert_bytes):
        try:
            server_cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        except:
            print("Certificado inválido")

        ca_cert = load_cert(self.ca_cert_path)

        chain = [server_cert, ca_cert]

        ok, msg = validate_chain(chain, expected_cn=self.expected_cn)

        if not ok:
            raise Exception(msg)
        return server_cert


    #quarto: extrair chave publica do certificado
    def extract_public_key(self, cert):
        print("Extraindo chave pública do certificado...")
        pub_key = cert.public_key()
        print("Processo concluído")
        return pub_key

    #quinto: gerar um desafio/challenge para enviar ao servidor
    def nonce_challeng(self, server_pubkey):
        print("Montando o desafio.")

        # Gerar nonce aleatório
        nonce = secrets.token_bytes(32)
        nonce_b64 = base64.b64encode(nonce).decode()

        print(f"Nonce client: {nonce_b64}")
        with open("nonces/client_nonce.txt", "w") as f:
            f.write(nonce_b64)
            
        # Criptografar com a chave pública do servidor
        encrypted_nonce = server_pubkey.encrypt(
            nonce,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Envio ao server
        url = f"{self.server_url}/challenge"
        r = requests.post(url, json={
            "ciphertext": base64.b64encode(encrypted_nonce).decode()
        })

        if r.status_code != 200:
            raise Exception("Falha ao enviar para o servidor, endpoint /challenge")

        resposta_b64 = r.json().get("nonce")
        resposta = base64.b64decode(resposta_b64)

        if resposta == nonce:
            print("Desafio realizado com sucesso, server autenticado")
            return True
        else:
            print("Desafio falhou, server não autenticado")
            return False

    #função para juntar todo processo
    def authenticate_server(self):
        print("\n---- Inicando o Processo de Autentificação do Servidor -----")

        cert_bytes = self.fetch_server_certificate()
        cert = self.validate_certificate(cert_bytes)
        pub_key = self.extract_public_key(cert)

        resultado = self.nonce_challeng(pub_key)

        print("\n------------------------------------------------------------")
        return resultado


