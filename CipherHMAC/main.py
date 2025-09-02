from dotenv import load_dotenv
import os
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import requests
import hashlib
import hmac
import asyncpg

load_dotenv()

app = FastAPI()

API_KEY = os.getenv("API_KEY")
CHAVE_SECRET = os.getenv("CHAVE_SECRET")
if not API_KEY:
    raise RuntimeError("API_KEY não encontrada no .env")


DATABASE_URL = os.getenv("DATABASE_URL")  # ex: postgres://user:pass@host/dbname


# Monta a pasta static para servir arquivos
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(DATABASE_URL)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()


@app.get("/")
def read_root():
    return FileResponse("static/home.html")

@app.get("/simular")
def read_simular():
    return FileResponse("static/simular.html")


@app.post("/simular/openweather")
def simular_openweather():
    print(API_KEY)
    url = f"http://api.openweathermap.org/data/2.5/weather?q=Cascavel&units=metric&appid={API_KEY}&lang=pt_br"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()

        temperatura = data['main']['temp']
        pressao = data['main']['pressure']
        umidade = data['main']['humidity']


        return {
            "temperatura": temperatura,
            "pressao": pressao,
            "umidade": umidade,
            "mensagem": f"Simulado com dados reais: {temperatura}°C, {umidade}%, {pressao} hPa"
        }
    else:
        return {"mensagem": "Erro ao buscar dados da OpenWeather"}

@app.post("/gerar-hmac")
async def gerar_hmac(request: Request):

    dados = await request.json()
    nome = dados.get("nome")
    temperatura = dados.get("temperatura")
    umidade = dados.get("umidade")
    pressao = dados.get("pressao")
    chave = dados.get("chave")

    mensagem = f"{nome}|{temperatura}|{umidade}|{pressao}"

    hmac_sha256 = hmac.new(chave.encode(), digestmod=hashlib.sha256)


    hmac_sha256.update(mensagem.encode())
    hash_value = hmac_sha256.hexdigest()

    return {"mensagem": mensagem, "hmac": hash_value}

@app.post("/validar-hmac")
async def validar_hmac(request: Request):
    dados = await request.json()
    
    nome = dados.get("nome")
    temperatura = dados.get("temperatura")
    umidade = dados.get("umidade")
    pressao = dados.get("pressao")
    hmac_recebido = dados.get("hmac")

    mensagem = f"{nome}|{temperatura}|{umidade}|{pressao}"

    hmac_sha256 = hmac.new(CHAVE_SECRET.encode(), mensagem.encode(), hashlib.sha256)
    hmac_calculado = hmac_sha256.hexdigest()

    if hmac_recebido != hmac_calculado:
        return {"mensagem": "HMAC inválido. A mensagem pode ter sido alterada."}

    async with app.state.db_pool.acquire() as connection:
        await connection.execute("""
            INSERT INTO mensagens (nome, temperatura, umidade, pressao, hmac, valido)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, nome, float(temperatura), float(umidade), float(pressao), hmac_recebido, True)

    return {"mensagem": "Dados validados e armazenados com sucesso."}

@app.get("/mensagens")
async def listar_mensagens():
    async with app.state.db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, nome, temperatura, umidade, pressao, hmac, valido, data
            FROM mensagens
            ORDER BY data DESC
        """)
        return [{
            "id": row["id"],
            "nome": row["nome"],
            "temperatura": row["temperatura"],
            "umidade": row["umidade"],
            "pressao": row["pressao"],
            "hmac": row["hmac"],
            "valido": row["valido"],
            "data": row["data"].isoformat()
        } for row in rows]
