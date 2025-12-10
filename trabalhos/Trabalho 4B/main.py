# main.py
import secrets
import time
import bcrypt
from fastapi import FastAPI, HTTPException, Header, Body
from fastapi.responses import JSONResponse
import base64

from modules import certs_module, tokens_module

app = FastAPI(title="Servidor FastAPI com Certificados + JWT")

@app.on_event("startup")
def startup_event():
    certs = certs_module.ensure_certificates()

    global SERVER_CERT
    global SERVER_PRIVATE_KEY
    global CERT_CHAIN

    SERVER_CERT = certs["server_cert"]
    SERVER_PRIVATE_KEY = certs["server_key"]

    CERT_CHAIN = [
        certs["server_cert"],
        certs["ca_cert"]
    ]

    print("[INFO] Certificados prontos para uso.")

@app.get("/certificado")
async def enviar_certificado():
    """Retorna o certificado do servidor em Base64"""
    with open(SERVER_CERT, "rb") as f:
        cert_data = f.read()
    cert_b64 = base64.b64encode(cert_data).decode()
    return {"certificado": cert_b64}


@app.post("/challenge")
async def server_challenge(ciphertext: str):
    """
    Prova de posse da chave privada do servidor.
    O servidor:
    - Recebe o nonce cifrado (Base64)
    - Decifra com sua chave privada
    - Devolve o nonce em Base64
    """
    try:
        ciphertext_bytes = base64.b64decode(ciphertext)

        plaintext_bytes = certs_module.decrypt_with_private_key(
            SERVER_PRIVATE_KEY,
            ciphertext_bytes
        )

        nonce_b64 = base64.b64encode(plaintext_bytes).decode()

        return {
            "nonce": nonce_b64
        }

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Erro no desafio criptográfico: {str(e)}"
        )


db_usuarios = {
    '1': {'id': '1', 'username': 'joao_silva', 'email': 'joao@exemplo.com', 'role': 'admin', 'password': bcrypt.hashpw(b"123456", bcrypt.gensalt()).decode()},
    '2': {'id': '2', 'username': 'maria_santos', 'email': 'maria@exemplo.com', 'role': 'user', 'password': bcrypt.hashpw(b"123456", bcrypt.gensalt()).decode()},
    '3': {'id': '3', 'username': 'magdiel', 'email': 'mag@exemplo.com', 'role': 'user', 'password': bcrypt.hashpw(b"123456", bcrypt.gensalt()).decode()},
}

db_tokens = {}

@app.post("/register")
async def register_user(
    username: str = Body(...),
    email: str = Body(...),
    password: str = Body(...),
    role: str = Body("user")
):
    """
    Cria um novo usuário no sistema (stateful e JWT)
    """
    for u in db_usuarios.values():
        if u['username'] == username:
            raise HTTPException(status_code=400, detail="Usuário já existe")
        if u['email'] == email:
            raise HTTPException(status_code=400, detail="Email já cadastrado")

    new_id = str((6364136223846793005 * int(time.time() * 1000)) % (2**32))
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db_usuarios[new_id] = {
        'id': new_id,
        'username': username,
        'email': email,
        'role': role,
        'password': password_hash,
    }

    return {"message": f"Usuário {username} registrado com sucesso!", "user_id": new_id}


@app.post("/login_banco")
async def login_banco(username: str = Body(...), password: str = Body(...)):
    """
    Login estilo token de banco.
    - Verifica usuário/senha
    - Gera token aleatório se válido
    """
    user = None
    for u in db_usuarios.values():
        if u['username'] == username:
            user = u
            break

    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = secrets.token_hex(32)
    db_tokens[token] = user['id']
    return {"token": token}

@app.get("/rota_protegida_banco")
async def rota_protegida_banco(token: str = Header(...)):
    """
    Rota protegida por token de banco
    """
    user_id = db_tokens.get(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

    user = db_usuarios.get(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")

    return {"message": f"Acesso concedido ao usuário {user['username']}"}

@app.post("/logout_banco")
async def logout_banco(token: str = Header(...)):
    """
    Logout do token de banco
    """
    if token in db_tokens:
        del db_tokens[token]
        return {"message": "Logout realizado com sucesso."}
    else:
        raise HTTPException(status_code=400, detail="Token inválido ou já expirado")


@app.post("/login_jwt")
async def login_jwt(username: str = Body(...), password: str = Body(...)):
    """Login com validação de usuário e senha, retorna JWT"""

    user = None
    for u in db_usuarios.values():
        if u['username'] == username:
            user = u
            break

    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = tokens_module.criar_token(user["id"], db_usuarios)
    return {"token": token}


@app.get("/rota_protegida_jwt")
async def rota_protegida_jwt(authorization: str = Header(...)):
    """
    Rota protegida JWT
    
    Recebe o token JWT no header 'authorization'.
    Decodifica usando a CHAVE_SECRETA.
    Retorna sucesso com usuário do payload ou 'Acesso negado'.
    """
    try:
        token = authorization
        if authorization.startswith("Bearer "):
            token = authorization[len("Bearer "):]
        payload = tokens_module.validar_token(token, db_usuarios)
        return {"message": f"Acesso concedido ao usuário {payload['username']}!"}

    except ValueError:
        raise HTTPException(status_code=401, detail="Acesso negado")


@app.get("/usuarios")
async def listar_usuarios():
    """
    Retorna todos os usuários cadastrados (sem expor senha)
    """
    usuarios = []
    for u in db_usuarios.values():
        usuarios.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "role": u["role"]
        })
    return {"usuarios": usuarios}
