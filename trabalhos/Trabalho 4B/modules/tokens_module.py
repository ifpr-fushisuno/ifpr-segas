import base64
import hmac
import hashlib
import json
import time
import jwt
from datetime import datetime, timedelta

SECRET_KEY = 'aiaiai carrpato nao tem pai'
TOKEN_EXPIRATION = 50

def criar_jwt_manual(payload, chave_secreta=SECRET_KEY):
    header = {"alg": "HS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(',', ':'))
    header_base64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b'=')

    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_base64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b'=')

    mensagem = header_base64 + b'.' + payload_base64
    assinatura = hmac.new(chave_secreta.encode(), mensagem, hashlib.sha256)
    assinatura_base64 = base64.urlsafe_b64encode(assinatura.digest()).rstrip(b'=')

    token = b'.'.join([header_base64, payload_base64, assinatura_base64])
    return token.decode()

def criar_jwt_biblioteca(payload, chave_secreta=SECRET_KEY):
    return jwt.encode(payload, chave_secreta, algorithm='HS256')


def criar_token(user_id, db):
    user = db.get(user_id)
    if not user:
        raise ValueError('Usuário não encontrado!')

    now = int(datetime.utcnow().timestamp())
    payload = {
        'sub': user_id,
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'iat': now,
        'exp': now + TOKEN_EXPIRATION
    }

    token = criar_jwt_biblioteca(payload)
    return token


def validar_token(token, db):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = payload['sub']
        user = db.get(user_id)
        if not user:
            raise jwt.InvalidTokenError('Usuário não encontrado')
        return user
    except jwt.ExpiredSignatureError:
        raise ValueError('Token expirado!')
    except jwt.InvalidTokenError:
        raise ValueError('Token inválido!')


def simular_requisicao_protegida(token, required_role=None):
    try:
        user = validar_token(token)
        if required_role and user['role'] != required_role:
            return f'Acesso negado! Role {required_role} necessária.'
        return f'Acesso permitido para {user["username"]}! Role: {user["role"]}.'
    except ValueError as e:
        return f'Erro: {str(e)}'


def criar_token_expirado(user_id):
    payload = {'sub': str(user_id), 'exp': int(datetime.utcnow().timestamp()) - 1}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def criar_token_invalido():
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.invalid'
