# main.py
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
import secrets
import base64

from modules import certs_module, tokens_module

app = FastAPI(title="Servidor FastAPI com Certificados + JWT")

SERVER_CERT = "certificado.pem"
SERVER_PRIVATE_KEY = "private_key.pem"
CERT_CHAIN = [
    SERVER_CERT,                   # Certificado do servidor
    "certificado_Raiz.pem"  # Certificado da CA
]
EXPECTED_CN = "Server"

SERVER_CERT_OBJ = certs_module.load_cert(SERVER_CERT)
CERT_CHAIN_OBJ = certs_module.load_certificates(CERT_CHAIN)

nonces = {}

@app.get("/certificado")
async def enviar_certificado():
    """Retorna o certificado do servidor em Base64"""
    with open(SERVER_CERT, "rb") as f:
        cert_data = f.read()
    cert_b64 = base64.b64encode(cert_data).decode()
    return {"certificado": cert_b64}


@app.get("/gerar_nonce")
async def gerar_nonce(client_id: str):
    """Gera um nonce aleatório para o client_id"""
    nonce = secrets.token_hex(16)
    nonces[client_id] = nonce
    return {"nonce": nonce}


@app.post("/challenge")
async def server_challenge(client_id: str, ciphertext: str):
    """
    Recebe o ciphertext enviado pelo cliente,
    decifra com a chave privada e valida o nonce.
    """
    try:
        # Decifrar com a chave privada
        plaintext = certs_module.decrypt_base64(SERVER_PRIVATE_KEY, ciphertext)
        nonce_received = plaintext.decode()

        # Validar nonce
        expected_nonce = nonces.get(client_id)
        if not expected_nonce:
            raise HTTPException(status_code=400, detail="Nenhum nonce gerado para este cliente")
        if nonce_received != expected_nonce:
            raise HTTPException(status_code=401, detail="Nonce incorreto")

        return {"message": "Servidor autenticado com sucesso!"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/login/{user_id}")
async def login(user_id: int):
    """Cria token JWT para o usuário"""
    try:
        token = tokens_module.criar_token(user_id)
        return {"token": token}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/rota_protegida")
async def rota_protegida(authorization: str = Header(...), role: str = None):
    """
    Exemplo de rota protegida:
    - Valida o token JWT
    - Verifica role, se fornecida
    """
    try:
        user = tokens_module.validar_token(authorization)
        if role and user["role"] != role:
            raise HTTPException(status_code=403, detail="Role insuficiente")
        return {"message": f"Acesso permitido para {user['username']}! Role: {user['role']}"}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
