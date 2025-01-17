# API de Usuários e CEP

API REST para gerenciamento de usuários e consulta de CEPs desenvolvida com FastAPI.

## 🚀 Funcionalidades

- Autenticação JWT
- CRUD de usuários
- Consulta e validação de CEPs via API ViaCEP
- Cache Redis para consultas de CEP
- Banco de dados SQLite

## 📋 Requisitos

- Python 3.8+
- Redis
- Dependências Python listadas em `requirements.txt`

## 🔧 Instalação e Execução

1. Clone o repositório:
   ```bash
   git clone https://github.com/Joceleide/api-usuarios-cep.git
   cd api-usuarios-cep
   ```
A estrura do projeto deve ser:
api-usuario-cep/
├── .env                  # Arquivo de configuração
├── main.py
├── CEP_api.py
├── database.py
├── config.py
└── api.log

Não esqueça de gerar seu arquivo .env com as variáveis de ambiente.

2. Crie e ative um ambiente virtual:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # ou
   .\venv\Scripts\activate  # Windows
   ```

3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

4. Certifique-se de ter o Redis instalado e rodando;


5. Execute a aplicação:
   ```bash
   uvicorn main:app --reload
   ```

A API estará disponível em `http://localhost:8000`

6. Acesse a documentação automática da API:
    - Swagger UI: http://localhost:8000/docs
    - ReDoc: http://localhost:8000/redoc

7. Teste a API usando o Swagger UI ou usando curl/Postman:

    a) Primeiro, crie um primeiro usuário (POST /primeiro-usuario/):
   ```bash
   curl -X POST "http://localhost:8000/primeiro-usuario/" \
    -H "Content-Type: application/json" \
    -d '{
        "nome": "Admin",
        "email": "admin@exemplo.com",
        "senha": "Admin123@",
        "cep": "01001-000"
    }'
   ```

   b) Na sequência gere o token de acesso (POST /token):
   ```bash
   curl -X POST "http://localhost:8000/token" \
   -H "Content-Type: application/x-www-form-urlencoded" \
   -d "username=seu_email@exemplo.com&password=Senha123@"
   ```

   c) Use o token retornado para criar um novo usuário (POST /usuarios/):
   ```bash
   curl -X POST "http://localhost:8000/usuarios/" \
   -H "Authorization: Bearer {seu_token}" \
   -H "Content-Type: application/json" \
   -d '{
       "nome": "João Silva",
       "email": "joao@exemplo.com",
       "senha": "Senha123@",
       "cep": "01001-000"
   }'
   ```

   d) Liste os usuários (GET /usuarios/):
   ```bash
   curl -X GET "http://localhost:8000/usuarios/" \
   -H "Authorization: Bearer {seu_token}"
   ```

8. Estrutura de um usuário válido para testes:
   ```json
   {
       "nome": "João Silva",
       "email": "joao@exemplo.com",
       "senha": "Senha123@",
       "cep": "01001-000"
   }
   ```

   Requisitos para os campos:
   - **nome**: mínimo 3 caracteres
   - **email**: formato válido de email
   - **senha**: mínimo 8 caracteres, deve conter maiúscula, minúscula, número e caractere especial
   - **cep**: formato válido (00000-000 ou 00000000)

9. Para testar o cache Redis, faça múltiplas requisições com o mesmo CEP e verifique nos logs que apenas a primeira chamada acessa a API ViaCEP.

10. Monitoramento do Redis:
    ```bash
    redis-cli monitor
    ```
    Isso mostrará todas as operações sendo realizadas no Redis em tempo real.

11. Verificar dados no banco SQLite:
    ```bash
    sqlite3 usuarios.db
    ```

    Comandos úteis:
    ```sql
    .tables
    SELECT * FROM usuarios;
    SELECT * FROM enderecos;
    ```

### Dicas adicionais

- Use o Postman ou Insomnia para testes mais complexos
- Acompanhe o arquivo `api.log` para monitorar o comportamento da aplicação
- Para desenvolvimento, você pode usar o modo `--reload` do uvicorn para atualização automática do código
- Se encontrar problemas com CORS durante o desenvolvimento, você pode adicionar o middleware do FastAPI para permitir requisições de outras origens

