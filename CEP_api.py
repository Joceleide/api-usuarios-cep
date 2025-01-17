from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from typing import Dict, List, Optional
from security import verify_password, get_password_hash, create_access_token
from pydantic import field_validator
import logging
import re
import jwt
from datetime import datetime, timedelta, timezone 
import sqlite3
import requests
import redis
import json
import structlog
from config import settings

# Configuração de logging estruturado
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True
)

logger = structlog.get_logger()

# Criar um router em vez de um app
router = APIRouter(
    prefix="/api/v1",
    tags=["Usuários"],
    responses={404: {"description": "Item não encontrado"}}
)

# Configuração Redis
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
REDIS_EXPIRE_TIME: int = 60 * 60 * 24  # 24 horas em segundos

# Configuração OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class TokenRequest(BaseModel):
    username: str = Field(..., description="Email do usuário")
    password: str = Field(..., description="Senha do usuário")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="Token JWT de acesso")
    token_type: str = Field(..., description="Tipo do token (bearer)")

class UsuarioCreate(BaseModel):
    """
    Model para criação de usuário.
    
    Attributes:
        nome: Nome do usuário (mínimo 3 caracteres)
        email: Email válido do usuário
        senha: Senha forte com requisitos específicos
        cep: CEP no formato 00000-000
    """
    nome: str = Field(
        ..., 
        min_length=3,
        description="Nome do usuário (mínimo 3 caracteres)",
        example="João Silva"
    )
    email: EmailStr = Field(
        ...,
        description="Email válido do usuário",
        example="joao@exemplo.com"
    )
    senha: str = Field(
        ...,
        min_length=8,
        description="Senha (mínimo 8 caracteres, deve conter maiúscula, minúscula, número e caractere especial)",
        example="Senha123@"
    )
    cep: str = Field(
        ...,
        pattern=r'^\d{5}-?\d{3}$',
        description="CEP no formato 00000-000 ou 00000000",
        example="01001-000"
    )

    @field_validator('senha')
    def validate_password(cls, v: str) -> str:
        """
        Valida a força da senha.

        Args:
            cls: Classe do modelo
            v: Valor da senha a ser validado

        Returns:
            str: A senha validada

        Raises:
            ValueError: Se a senha não atender aos critérios de força
        """
        if not any(c.isupper() for c in v):
            raise ValueError('Senha deve conter pelo menos uma letra maiúscula')
        if not any(c.islower() for c in v):
            raise ValueError('Senha deve conter pelo menos uma letra minúscula')
        if not any(c.isdigit() for c in v):
            raise ValueError('Senha deve conter pelo menos um número')
        if not any(c in '@$!%*?&' for c in v):
            raise ValueError('Senha deve conter pelo menos um caractere especial (@$!%*?&)')
        return v
    
class EnderecoResponse(BaseModel):
    cep: str = Field(..., description="CEP no formato 00000-000")
    logradouro: str = Field(..., description="Nome da rua/avenida")
    bairro: str = Field(..., description="Nome do bairro")
    cidade: str = Field(..., description="Nome da cidade")
    estado: str = Field(..., description="Sigla do estado")

class UsuarioResponse(BaseModel):
    """
    Model para resposta de usuário.
    
    Attributes:
        id: ID único do usuário
        nome: Nome do usuário
        email: Email do usuário
        endereco: Objeto EnderecoBase com dados do endereço
    """
    id: int = Field(..., description="ID do usuário")
    nome: str = Field(..., description="Nome do usuário")
    email: str = Field(..., description="Email do usuário")
    endereco: EnderecoResponse = Field(..., description="Dados do endereço")


# Funções de autenticação
def create_access_token(data: dict) -> str:
    """
    Cria um token JWT de acesso.

    Args:
        data: Dicionário com dados a serem codificados no token

    Returns:
        str: Token JWT codificado
    """
    to_encode = data.copy()
    expire: datetime = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> int:
    """
    Valida o token JWT e retorna o ID do usuário.

    Args:
        token: Token JWT de autenticação

    Returns:
        int: ID do usuário autenticado

    Raises:
        HTTPException: Se o token for inválido ou expirado
    """
    try:
        logger.info("validating_token", token_preview=token[:20])  # Não logue o token inteiro em produção
        payload: dict = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            logger.warning("token_validation_failed", reason="missing_user_id")
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        logger.info("token_validated", user_id=user_id)
        return user_id
    except jwt.ExpiredSignatureError:
        logger.error("token_validation_failed", reason="expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError as e:
        logger.error("token_validation_failed", reason="jwt_error", error=str(e))
        raise HTTPException(status_code=401, detail="Could not validate credentials")


def validar_cep(cep: str) -> bool:
    """
    Valida o formato do CEP.

    Args:
        cep: CEP a ser validado

    Returns:
        bool: True se o CEP for válido, False caso contrário
    """
    padrao = re.compile(r'^\d{5}-?\d{3}$')
    return bool(padrao.match(cep))

async def buscar_cep(cep: str) -> Dict[str, str]:
    """
    Busca informações de um CEP na API ViaCEP com cache Redis.

    Args:
        cep: CEP a ser consultado

    Returns:
        Dict[str, str]: Dicionário com dados do endereço

    Raises:
        HTTPException: Se o CEP não for encontrado ou houver erro na consulta
    """
    try:
        # Remove hífen do CEP para padronização
        cep = cep.replace("-", "")
        
        # Tenta buscar do cache primeiro
        cached_data = redis_client.get(f"cep:{cep}")
        if cached_data:
            logger.info("cep_cache_hit", cep=cep)
            return json.loads(cached_data)
            
        # Se não estiver no cache, busca na API
        url: str = f'https://viacep.com.br/ws/{cep}/json/'
        response = requests.get(url)
        response.raise_for_status()
        
        data: dict = response.json()
        if 'erro' in data:
            logger.warning("cep_not_found", cep=cep)
            raise HTTPException(status_code=404, detail="CEP não encontrado")
            
        endereco: Dict[str, str] = {
            'cep': cep,
            'logradouro': data['logradouro'],
            'bairro': data['bairro'],
            'cidade': data['localidade'],
            'estado': data['uf']
        }
        
        # Salva no cache
        redis_client.setex(
            f"cep:{cep}",
            REDIS_EXPIRE_TIME,
            json.dumps(endereco)
        )
        logger.info("cep_cached", cep=cep)
            
        return endereco
        
    except requests.exceptions.RequestException as e:
        logger.error("cep_request_error", error=str(e), cep=cep)
        raise HTTPException(status_code=500, detail="Erro ao consultar serviço de CEP")
    except redis.RedisError as e:
        logger.error("redis_error", error=str(e), cep=cep)
        # Em caso de erro no Redis, continua com o resultado da API
        return endereco

# Rotas da API
@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Autenticação de usuário",
    description="""
    Autentica um usuário e retorna um token JWT.
    
    - Requer email e senha válidos
    - Retorna um token de acesso JWT
    - O token deve ser usado no header Authorization para outras requisições
    """,
    responses={
        200: {
            "description": "Login bem sucedido",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        401: {"description": "Credenciais inválidas"},
        500: {"description": "Erro interno do servidor"}
    }
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """
    Autentica um usuário e retorna um token JWT.

    Args:
        form_data: Dados do formulário de login (username/password)

    Returns:
        TokenResponse: Token de acesso e tipo do token

    Raises:
        HTTPException: Se as credenciais forem inválidas
    """
    try:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        # Busca o usuário pelo email
        cursor.execute(
            "SELECT id, senha FROM usuarios WHERE email = ? AND status = 'ativo'", 
            (form_data.username,)
        )
        result = cursor.fetchone()
        
        if not result:
            logger.warning(f"Tentativa de login com email não cadastrado: {form_data.username}")
            raise HTTPException(
                status_code=401,
                detail="Email ou senha incorretos"
            )
            
        user_id, stored_password = result
        
        # Verifica a senha usando a função de verificação de hash
        if not verify_password(form_data.password, stored_password):
            logger.warning(f"Senha incorreta para o email: {form_data.username}")
            raise HTTPException(
                status_code=401,
                detail="Email ou senha incorretos"
            )
            
        # Gera o token
        access_token: str = create_access_token({"sub": user_id})
        return {"access_token": access_token, "token_type": "bearer"}
        
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")
    finally:
        conn.close()

@router.post(
    "/primeiro-usuario/",
    response_model=UsuarioResponse,
    summary="Criar primeiro usuário do sistema",
    description="""
    Cria o primeiro usuário administrador do sistema.
    
    Esta rota só funciona quando não há nenhum usuário cadastrado no sistema.
    Após o primeiro usuário ser criado, esta rota não poderá mais ser utilizada.
    
    Requer:
    - Nome (mínimo 3 caracteres)
    - Email válido
    - Senha forte (mínimo 8 caracteres, deve conter maiúscula, minúscula, número e caractere especial)
    - CEP válido (formato: 00000-000 ou 00000000)
    
    O endereço será preenchido automaticamente com base no CEP fornecido.
    """,
    responses={
        200: {
            "description": "Primeiro usuário criado com sucesso",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "nome": "Admin",
                        "email": "admin@exemplo.com",
                        "endereco": {
                            "cep": "01001-000",
                            "logradouro": "Praça da Sé",
                            "bairro": "Sé",
                            "cidade": "São Paulo",
                            "estado": "SP"
                        }
                    }
                }
            }
        },
        400: {
            "description": "Erro de validação ou usuário já existe",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Já existe um usuário cadastrado. Use a rota normal de criação."
                    }
                }
            }
        },
        422: {
            "description": "Erro de validação dos dados",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "loc": ["body", "email"],
                                "msg": "value is not a valid email address",
                                "type": "value_error.email"
                            }
                        ]
                    }
                }
            }
        },
        500: {
            "description": "Erro interno do servidor",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Erro interno do servidor"
                    }
                }
            }
        }
    }
)
async def criar_primeiro_usuario(usuario: UsuarioCreate) -> UsuarioResponse:
    """
    Cria o primeiro usuário administrador do sistema.
    
    Args:
        usuario: Dados do usuário a ser criado
        
    Returns:
        UsuarioResponse: Dados do usuário criado com seu endereço
        
    Raises:
        HTTPException: 
            - 400: Se já existir um usuário cadastrado
            - 400: Se o CEP for inválido
            - 500: Em caso de erro interno
    """
    try:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        # Verifica se já existe algum usuário
        cursor.execute("SELECT COUNT(*) FROM usuarios")
        count: int = cursor.fetchone()[0]
        
        if count > 0:
            raise HTTPException(
                status_code=400,
                detail="Já existe um usuário cadastrado. Use a rota normal de criação."
            )
            
        # Valida e busca o endereço pelo CEP
        if not validar_cep(usuario.cep):
            raise HTTPException(status_code=400, detail="CEP inválido")
            
        endereco: Dict[str, str] = await buscar_cep(usuario.cep)
        
        # Hash da senha
        senha_hash: str = get_password_hash(usuario.senha)
        
        # Insere o usuário
        cursor.execute('''
            INSERT INTO usuarios (nome, email, senha, data_criacao, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            usuario.nome,
            usuario.email,
            senha_hash,
            datetime.now().isoformat(),
            'ativo'
        ))
        
        usuario_id: int = cursor.lastrowid
        
        # Insere o endereço
        cursor.execute('''
            INSERT INTO enderecos (usuario_id, cep, logradouro, bairro, cidade, estado)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            usuario_id,
            endereco['cep'],
            endereco['logradouro'],
            endereco['bairro'],
            endereco['cidade'],
            endereco['estado']
        ))
        
        conn.commit()
        logger.info(f"Primeiro usuário criado: ID {usuario_id}")
        
        return {
            "id": usuario_id,
            "nome": usuario.nome,
            "email": usuario.email,
            "endereco": endereco
        }
        
    except sqlite3.IntegrityError:
        logger.error(f"Tentativa de criar usuário com email duplicado: {usuario.email}")
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    except Exception as e:
        logger.error(f"Erro ao criar primeiro usuário: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro interno do servidor")
    finally:
        conn.close()

@router.post(
    "/usuarios/",
    response_model=UsuarioResponse,
    summary="Criar novo usuário",
    description="""
    Cria um novo usuário no sistema.
    
    Requer:
    - Nome (mínimo 3 caracteres)
    - Email válido
    - Senha forte
    - CEP válido
    
    O endereço será preenchido automaticamente com base no CEP fornecido.
    """,
    responses={
        200: {
            "description": "Usuário criado com sucesso",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "nome": "João Silva",
                        "email": "joao@exemplo.com",
                        "endereco": {
                            "cep": "01001-000",
                            "logradouro": "Praça da Sé",
                            "bairro": "Sé",
                            "cidade": "São Paulo",
                            "estado": "SP"
                        }
                    }
                }
            }
        },
        400: {"description": "Dados inválidos"},
        401: {"description": "Não autorizado"},
        500: {"description": "Erro interno do servidor"}
    }
)
async def criar_usuario(
    usuario: UsuarioCreate,
    current_user: int = Depends(get_current_user)
) -> UsuarioResponse:
    """
    Cria um novo usuário no sistema.

    Args:
        usuario: Dados do usuário a ser criado
        current_user: ID do usuário autenticado (via token)

    Returns:
        UsuarioResponse: Dados do usuário criado

    Raises:
        HTTPException: Se houver erro na criação ou dados inválidos
    """
    try:
        if not validar_cep(usuario.cep):
            logger.warning("user_creation_failed", reason="invalid_cep", cep=usuario.cep)
            raise HTTPException(status_code=400, detail="CEP inválido")
            
        endereco: Dict[str, str] = await buscar_cep(usuario.cep)
        senha_hash: str = get_password_hash(usuario.senha)
        
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO usuarios (nome, email, senha, data_criacao, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            usuario.nome,
            usuario.email,
            senha_hash,  # Usa o hash da senha
            datetime.now().isoformat(),
            'ativo'
        ))
        
        usuario_id: int = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO enderecos (usuario_id, cep, logradouro, bairro, cidade, estado)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            usuario_id,
            endereco['cep'],
            endereco['logradouro'],
            endereco['bairro'],
            endereco['cidade'],
            endereco['estado']
        ))
        
        conn.commit()
        logger.info("user_created", user_id=usuario_id)
        
        return {
            "id": usuario_id,
            "nome": usuario.nome,
            "email": usuario.email,
            "endereco": endereco
        }
        
    except sqlite3.IntegrityError:
        logger.warning("user_creation_failed", reason="email_exists", email=usuario.email)
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    except Exception as e:
        logger.error("user_creation_error", error=str(e))
        raise HTTPException(status_code=500, detail="Erro interno do servidor")
    finally:
        conn.close()


@router.get(
    "/usuarios/",
    response_model=List[UsuarioResponse],
    summary="Listar usuários",
    description="Lista todos os usuários ativos do sistema.",
    responses={
        200: {
            "description": "Lista de usuários",
            "content": {
                "application/json": {
                    "example": [{
                        "id": 1,
                        "nome": "João Silva",
                        "email": "joao@exemplo.com",
                        "endereco": {
                            "cep": "01001-000",
                            "logradouro": "Praça da Sé",
                            "bairro": "Sé",
                            "cidade": "São Paulo",
                            "estado": "SP"
                        }
                    }]
                }
            }
        },
        401: {"description": "Não autorizado"},
        500: {"description": "Erro interno do servidor"}
    }
)
async def listar_usuarios(
    current_user: int = Depends(get_current_user)
) -> List[UsuarioResponse]:
    """
    Lista todos os usuários ativos do sistema.

    Args:
        current_user: ID do usuário autenticado (via token)

    Returns:
        List[UsuarioResponse]: Lista de usuários com seus respectivos endereços

    Raises:
        HTTPException: Se houver erro ao buscar os usuários
    """
    try:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.nome, u.email, e.cep, e.logradouro, e.bairro, e.cidade, e.estado
            FROM usuarios u
            LEFT JOIN enderecos e ON u.id = e.usuario_id
            WHERE u.status = 'ativo'
        ''')
        
        usuarios = cursor.fetchall()
        
        return [{
            "id": u[0],
            "nome": u[1],
            "email": u[2],
            "endereco": {
                "cep": u[3],
                "logradouro": u[4],
                "bairro": u[5],
                "cidade": u[6],
                "estado": u[7]
            }
        } for u in usuarios]
        
    except Exception as e:
        logger.error("list_users_error", error=str(e))
        raise HTTPException(status_code=500, detail="Erro interno do servidor")
    finally:
        conn.close()
