# Trabalho Prático – Implementação de Autenticação Baseada em Token

**Disciplina:** Segurança e Auditoria de Sistemas  
**Curso:** Tecnologia em Análise e Desenvolvimento de Sistemas (TADS)  
**Modalidade:** Em duplas  
**Data de Entrega e Arguição:** **26/11/2025**

---

## 1. Objetivo

Este trabalho tem como objetivo aplicar os conceitos de **autenticação** e **gerenciamento de sessão** discutidos em aula. Os alunos deverão implementar e comparar duas abordagens distintas de autenticação baseada em token:

- **Tokens de Banco (Stateful – estilo sessão/Django)**  
  Token opaco armazenado no servidor e validado a cada requisição.

- **JSON Web Token (JWT – Stateless)**  
  Token auto-contido, verificado criptograficamente, sem necessidade de armazenamento de sessão no servidor.

---

## 2. Descrição Geral

Os alunos deverão simular um **fluxo completo de login**, demonstrar o uso correto de **hashing de senhas com bcrypt** e implementar **rotas protegidas** para cada cenário de autenticação.

O sistema deve conter:

- Um **banco de dados simulado** (ex: dicionário em memória, lista de objetos ou arquivo JSON) para armazenamento de usuários.
- Uma função para **armazenar senhas de forma segura**, utilizando a biblioteca `bcrypt` (ou equivalente).
- Uma função de **login**, responsável por verificar as credenciais do usuário.
- Uma função que simula uma **rota protegida**, permitindo acesso apenas mediante token válido.
- Uma função de **logout** (apenas para o cenário 1 – token de banco).

O trabalho deve ser dividido em **dois cenários independentes**, podendo reutilizar a mesma base de usuários.

---

## 3. Requisitos de Implementação

### 3.1 Cenário 1 – Autenticação com Token de Banco (Stateful)

Neste cenário, o token é uma **string aleatória** gerada pelo servidor e armazenada em um banco de dados simulado.

#### Banco de Dados Simulado

- **Usuários:**  
  Dicionário contendo os usuários e suas senhas hasheadas.

  ```python
  db_usuarios = {
      'aluno1': b'$2b$12$...'
  }
  ```

* **Tokens Ativos:**
  Dicionário que associa tokens a usuários autenticados.

  ```python
  db_tokens = {
      'abc123xyz789': 'aluno1'
  }
  ```

---

#### Função `login_banco(usuario, senha)`

* Recebe o `usuario` e a `senha`.
* Busca o hash da senha no `db_usuarios`.
* Utiliza `bcrypt` para verificar a senha informada.
* Se a senha for válida:

  * Gera um token aleatório (ex: `uuid4()` ou `secrets.token_hex()`).
  * Armazena o token no `db_tokens`, associado ao usuário.
  * Retorna o token gerado.
* Se a senha for inválida:

  * Retorna uma mensagem de erro.

---

#### Função `rota_protegida_banco(token)`

* Recebe o `token`.
* Verifica se o token existe no `db_tokens`.
* Se existir:

  * Retorna uma mensagem de sucesso
    (ex: `"Acesso concedido ao usuário [nome do usuário]"`).
* Caso contrário:

  * Retorna `"Acesso negado"`.

---

#### Função `logout_banco(token)`

* Recebe o `token`.
* Verifica se o token existe no `db_tokens`.
* Se existir:

  * Remove o token do banco.
  * Retorna `"Logout realizado com sucesso"`.
* Se não existir:

  * Informa que o token já era inválido.

---

### 3.2 Cenário 2 – Autenticação com JSON Web Token (JWT) (Stateless)

Neste cenário, o token contém os dados do usuário (**payload**) e é validado criptograficamente, sem necessidade de armazenamento de sessão no servidor.

#### Banco de Dados Simulado

* Utilizar o mesmo `db_usuarios` definido no Cenário 1.

---

#### Constante

* Definir uma constante `CHAVE_SECRETA` (string), utilizada para assinar e verificar os tokens JWT.

---

#### Função `login_jwt(usuario, senha)`

* Recebe `usuario` e `senha`.
* Verifica as credenciais usando `bcrypt`.
* Se a senha for válida:

  * Cria o payload do JWT, por exemplo:

    ```python
    payload = {
        'usuario': 'aluno1',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    ```

  * Gera o token JWT, assinado com a `CHAVE_SECRETA` (algoritmo HS256).

  * Retorna o token JWT.
* Se a senha for inválida:

  * Retorna uma mensagem de erro.

---

#### Função `rota_protegida_jwt(token)`

* Recebe o token JWT.
* Tenta decodificar o token utilizando a `CHAVE_SECRETA`.

  * Deve verificar:

    * Assinatura do token.
    * Data de expiração (`exp`).
* Se a verificação for bem-sucedida:

  * Extrai o payload.
  * Retorna uma mensagem de sucesso
    (ex: `"Acesso concedido ao usuário [usuario]"`).
* Caso a verificação falhe:

  * Retorna `"Acesso negado"`.

---

## 4. Observações

* O foco do trabalho é **compreender as diferenças entre autenticação stateful e stateless**.
* Não é necessário implementar interface gráfica.
* O código deve ser **bem organizado, comentado e legível**.
* A implementação pode ser feita em **Python**, utilizando bibliotecas como:

  * `bcrypt`
  * `pyjwt`
  * `datetime`

---

## 5. Critérios de Avaliação (sugestão)

* Correto uso de hashing de senhas
* Funcionamento dos dois cenários de autenticação
* Clareza do código e organização do projeto
* Capacidade de explicar o funcionamento na arguição
