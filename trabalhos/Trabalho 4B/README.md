# Servidor FastAPI – Autenticação com Certificados Digitais e Tokens

Este projeto implementa, de forma prática, **mecanismos de autenticação de servidor e autenticação de usuários**, integrando conceitos de **criptografia de chave pública**, **challenge-response**, **hashing de senhas** e **autenticação baseada em token**.

O sistema foi desenvolvido em **Python com FastAPI** e tem como objetivo principal consolidar os conteúdos estudados na disciplina de **Segurança e Auditoria de Sistemas**.

---

## 📌 Visão Geral do Projeto

O projeto é dividido em **duas grandes partes**:

1. **Autenticação do Servidor (Challenge-Response com Certificados Digitais)**
2. **Autenticação de Usuários Baseada em Token**

   * Token de Banco (Stateful)
   * JSON Web Token – JWT (Stateless)

Cada parte foi implementada de forma independente, mas integrada em um único servidor para facilitar testes e demonstrações.

---

## 🔐 Parte 1 – Autenticação do Servidor (Challenge-Response)

Nesta etapa, o foco é **garantir que o cliente tenha certeza de que está se comunicando com o servidor legítimo**, utilizando **certificados digitais e criptografia assimétrica**.

### 🔹 Geração de Certificados

O sistema gera automaticamente:

* **Certificado Raiz (CA – Autoridade Certificadora)**
* **Certificado do Servidor**, assinado pela CA

Caso os certificados já existam, eles são apenas carregados.

### 🔹 Fluxo de Autenticação do Servidor

O processo segue o modelo clássico de **Desafio–Resposta (Challenge-Response)**:

1. **Envio do Certificado**

   * O cliente solicita o certificado do servidor.
   * O servidor retorna seu certificado em Base64.

2. **Validação do Certificado (lado do cliente)**

   * Verificação da assinatura do certificado usando a chave pública da CA.
   * Verificação do período de validade.
   * Verificação do *Common Name (CN)* para confirmar a identidade do servidor.
   * Extração da chave pública do servidor.

3. **Prova de Posse da Chave Privada (Nonce Challenge)**

   * O cliente gera um **nonce aleatório**.
   * O nonce é cifrado com a **chave pública do servidor**.
   * O servidor decifra usando sua **chave privada**.
   * O servidor devolve o nonce em texto plano.
   * O cliente compara os valores e confirma a autenticidade do servidor.

Esse processo garante que **apenas o servidor legítimo**, que possui a chave privada correspondente, consiga responder corretamente ao desafio.

---

## 🔑 Parte 2 – Autenticação de Usuários Baseada em Token

Além da autenticação do servidor, o projeto implementa **controle de acesso de usuários**, simulando sistemas reais de login.

As senhas são armazenadas de forma segura utilizando **bcrypt**, nunca em texto plano.

---

## 🧩 Cenário 1 – Token de Banco (Stateful)

Neste cenário, o servidor mantém o **estado da sessão**, armazenando tokens ativos em memória.

### Funcionamento

* Após login bem-sucedido, o servidor gera um **token aleatório opaco**.
* O token é armazenado em um dicionário que associa token → usuário.
* A cada requisição protegida, o token é validado consultando o banco de tokens.

### Componentes Principais

* **Banco de usuários simulado** (`db_usuarios`)
* **Banco de tokens ativos** (`db_tokens`)

### Fluxo

1. Usuário envia login e senha.
2. O servidor valida a senha com `bcrypt`.
3. Um token aleatório é gerado.
4. O token é salvo no servidor.
5. O token deve ser enviado em requisições futuras.
6. No logout, o token é removido do banco.

Esse modelo representa sistemas **stateful**, semelhantes a sessões tradicionais.

---

## 🧩 Cenário 2 – JSON Web Token (JWT) (Stateless)

Neste cenário, o servidor **não armazena sessões**.

O próprio token carrega as informações do usuário e é validado criptograficamente.

### Funcionamento

* Após login válido, o servidor cria um **JWT**.
* O token contém:

  * Identificação do usuário
  * Papel (role)
  * Data de emissão (`iat`)
  * Data de expiração (`exp`)
* O token é assinado com **HMAC + SHA-256 (HS256)**.

### Fluxo

1. Usuário realiza login.
2. O servidor valida a senha com `bcrypt`.
3. Um JWT é gerado e retornado.
4. O cliente envia o JWT no header `Authorization`.
5. O servidor valida assinatura e expiração.
6. Se válido, o acesso é concedido.

Esse modelo representa sistemas **stateless**, amplamente usados em APIs modernas.

---

## 🧪 Rotas Implementadas

### Autenticação do Servidor

* `GET /certificado`
* `POST /challenge`

### Usuários

* `POST /register`
* `GET /usuarios`

### Token de Banco

* `POST /login_banco`
* `GET /rota_protegida_banco`
* `POST /logout_banco`

### JWT

* `POST /login_jwt`
* `GET /rota_protegida_jwt`

---

## 🛠️ Tecnologias Utilizadas

* **Python 3**
* **FastAPI**
* **bcrypt** (hashing de senhas)
* **PyJWT** (JWT)
* **cryptography** (certificados digitais)
* **HMAC / SHA-256**

---

## 🎯 Objetivos Educacionais

Este projeto permite:

* Compreender autenticação baseada em **certificados digitais**.
* Entender o funcionamento do **challenge-response**.
* Comparar autenticação **stateful vs stateless**.
* Aplicar boas práticas de **armazenamento seguro de senhas**.
* Entender a estrutura e validação de **JWTs**.

---

## ✅ Considerações Finais

O sistema implementa, de forma didática e funcional, os principais conceitos de segurança vistos em sala de aula, permitindo testes práticos e fácil explicação durante a arguição.

Todo o código foi estruturado para ser **legível, modular e extensível**, facilitando futuras melhorias ou adaptações.

---

📅 **Trabalho Acadêmico – Segurança e Auditoria de Sistemas**
👥 **Modalidade:** Em duplas
🎓 **Curso:** TADS
📍 **Instituição:** IFPR
