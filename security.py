from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import jwt
from config import settings

# Configuração do contexto de hash de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """
    Gera um hash seguro para a senha.

    Args:
        password (str): A senha em texto plano a ser hasheada.

    Returns:
        str: O hash da senha gerado.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha fornecida corresponde ao hash armazenado.

    Args:
        plain_password (str): A senha em texto plano a ser verificada.
        hashed_password (str): O hash da senha armazenado.

    Returns:
        bool: True se a senha corresponder ao hash, False caso contrário.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    """
    Cria um token JWT de acesso.

    Args:
        data (dict): Os dados a serem incluídos no token.

    Returns:
        str: O token JWT gerado.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)