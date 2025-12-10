
# Simulador de Dados com HMAC e Integração OpenWeather

## Descrição

Este projeto é uma aplicação FastAPI que simula o envio de dados meteorológicos com autenticação via HMAC (Hash-based Message Authentication Code). Também integra dados reais da API OpenWeather para a cidade de Cascavel.

A aplicação permite:

- Inserir dados simulados (nome, temperatura, umidade, pressão).
- Gerar o HMAC da mensagem usando uma chave fornecida.
- Validar o HMAC recebido no backend.
- Armazenar os dados validados em um banco PostgreSQL usando asyncpg.
- Simular dados reais da cidade de Cascavel via OpenWeather.
- Proteção contra ataques de replay pode ser implementada como extensão.

## Tecnologias

- Python 3.12+
- FastAPI
- asyncpg (conexão assíncrona com PostgreSQL)
- requests (para consumir API OpenWeather)
- dotenv (para variáveis de ambiente)
- Tailwind CSS + DaisyUI (para frontend)

## Estrutura do Projeto

- `main.py`: código principal da aplicação FastAPI.
- `static/`: arquivos estáticos (HTML, CSS, JS).
- `.env`: variáveis de ambiente com API keys e conexão DB.
- `README.md`: documentação do projeto.

## Variáveis de Ambiente (.env)

```env
API_KEY=your_openweather_api_key
CHAVE_SECRET=your_secret_key_for_hmac
DATABASE_URL=postgresql://user:password@host:port/dbname
```

## Endpoints

### GET /

Retorna a página inicial (`home.html`).

---

### GET /simular

Retorna a página do simulador de dados (`simular.html`).

---

### POST /simular/openweather

Consulta a API OpenWeather para a cidade Cascavel e retorna temperatura, pressão e umidade atuais.

Resposta JSON de exemplo:

```json
{
  "temperatura": 24.5,
  "pressao": 1013,
  "umidade": 78,
  "mensagem": "Simulado com dados reais: 24.5°C, 78%, 1013 hPa"
}
```

---

### POST /gerar-hmac

Recebe JSON com dados:

```json
{
  "nome": "Usuário",
  "temperatura": "24.5",
  "umidade": "78",
  "pressao": "1013",
  "chave": "chave_secreta"
}
```

Gera um HMAC SHA256 da mensagem formatada `nome|temperatura|umidade|pressao` com a chave fornecida.

Retorna JSON:

```json
{
  "mensagem": "Usuário|24.5|78|1013",
  "hmac": "assinatura_hmac_gerada"
}
```

---

### POST /validar-hmac

Recebe JSON com dados:

```json
{
  "nome": "Usuário",
  "temperatura": "24.5",
  "umidade": "78",
  "pressao": "1013",
  "hmac": "assinatura_hmac_recebida"
}
```

Valida o HMAC com a chave secreta do servidor (`CHAVE_SECRET`).

- Se válido, insere os dados na tabela `mensagens` do banco PostgreSQL com o campo `valido` marcado como `true`.
- Se inválido, retorna mensagem de erro.

Exemplo de retorno em caso de sucesso:

```json
{
  "mensagem": "Dados validados e armazenados com sucesso."
}
```

Em caso de HMAC inválido:

```json
{
  "mensagem": "HMAC inválido. A mensagem pode ter sido alterada."
}
```

## Banco de Dados

### Tabela: mensagens

| Coluna      | Tipo       | Observação              |
|-------------|------------|-------------------------|
| id          | SERIAL PK  | Identificador único     |
| nome        | TEXT       | Nome do usuário         |
| temperatura | REAL       | Temperatura em °C       |
| umidade     | REAL       | Umidade em %            |
| pressao     | REAL       | Pressão em hPa          |
| hmac        | TEXT       | Código HMAC da mensagem |
| valido      | BOOLEAN    | Indica se o HMAC foi válido |

### Exemplo de criação da tabela SQL:

```sql
CREATE TABLE mensagens (
    id SERIAL PRIMARY KEY,
    nome TEXT NOT NULL,
    temperatura REAL NOT NULL,
    umidade REAL NOT NULL,
    pressao REAL NOT NULL,
    hmac TEXT NOT NULL,
    valido BOOLEAN NOT NULL
);
```

## Proteção contra ataques de Replay (Sugestão)

Para prevenir reenvios de mensagens interceptadas:

- Incluir um timestamp na mensagem e validar se está dentro de um período aceitável (ex: últimos 5 minutos).
- Incluir um número único (nonce ou contador) armazenado no banco para garantir que cada mensagem seja única e nunca reutilizada.

## Como rodar

1. Clone o repositório
2. Configure o arquivo `.env` com as variáveis de ambiente
3. Crie a tabela `mensagens` no seu banco PostgreSQL
4. Instale dependências:

```bash
pip install fastapi uvicorn python-dotenv asyncpg requests
```

5. Execute a aplicação:

```bash
uvicorn main:app --reload
```

6. Acesse no navegador: `http://localhost:8000`

---

Se precisar de ajuda para mais alguma coisa, só pedir!

---
