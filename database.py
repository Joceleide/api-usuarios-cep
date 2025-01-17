import sqlite3
from fastapi import HTTPException
from datetime import datetime
from typing import Dict, List
from config import settings
import logging

logger = logging.getLogger(__name__)

def get_database_connection() -> sqlite3.Connection:
    """
    Cria uma conexão com o banco de dados usando a URL configurada.

    Returns:
        sqlite3.Connection: A conexão com o banco de dados.

    Raises:
        HTTPException: Se houver erro ao conectar ao banco de dados.
    """
    try:
        conn = sqlite3.connect(settings.DATABASE_URL.replace("sqlite:///", ""))
        return conn
    except Exception as e:
        logger.error(f"Erro ao conectar ao banco de dados: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro de conexão com banco de dados")

def criar_tabelas() -> None:
    """
    Cria as tabelas necessárias no banco de dados SQLite.

    Raises:
        Exception: Se houver erro ao criar as tabelas.
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                data_criacao TIMESTAMP NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enderecos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                cep TEXT NOT NULL,
                logradouro TEXT NOT NULL,
                bairro TEXT NOT NULL,
                cidade TEXT NOT NULL,
                estado TEXT NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
            )
        ''')
        
        conn.commit()
        logger.info("Tabelas criadas com sucesso")
    except Exception as e:
        logger.error(f"Erro ao criar tabelas: {str(e)}")
        raise
    finally:
        conn.close()
        
def inserir_usuario(nome: str, email: str, senha: str, endereco: Dict[str, str]) -> Dict:
    """
    Insere um novo usuário e seu endereço no banco de dados.

    Args:
        nome (str): Nome do usuário.
        email (str): Email do usuário.
        senha (str): Senha do usuário.
        endereco (Dict[str, str]): Dicionário contendo os dados do endereço (cep, logradouro, bairro, cidade, estado).

    Returns:
        Dict: Dados do usuário inserido.

    Raises:
        HTTPException: Se o email já estiver cadastrado.
    """
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO usuarios (nome, email, senha, data_criacao, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            nome,
            email,
            senha,
            datetime.now().isoformat(),
            'ativo'
        ))
        
        usuario_id = cursor.lastrowid
        
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
        
        return buscar_usuario(usuario_id)
    
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    finally:
        conn.close()

def listar_usuarios() -> List[Dict]:
    """
    Lista todos os usuários cadastrados no banco de dados.

    Returns:
        List[Dict]: Lista contendo os dados de todos os usuários e seus endereços.
    """
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT u.*, e.*
        FROM usuarios u
        LEFT JOIN enderecos e ON u.id = e.usuario_id
    ''')
    
    resultados = cursor.fetchall()
    conn.close()
    
    usuarios = []
    for resultado in resultados:
        usuarios.append({
            'id': resultado[0],
            'nome': resultado[1],
            'email': resultado[2],
            'data_criacao': resultado[3],
            'status': resultado[4],
            'endereco': {
                'id': resultado[5],
                'cep': resultado[7],
                'logradouro': resultado[8],
                'bairro': resultado[9],
                'cidade': resultado[10],
                'estado': resultado[11]
            }
        })
    
    return usuarios

def buscar_usuario(usuario_id: int) -> Dict:
    """
    Busca um usuário específico pelo ID.

    Args:
        usuario_id (int): ID do usuário a ser buscado.

    Returns:
        Dict: Dados do usuário e seu endereço.

    Raises:
        HTTPException: Se o usuário não for encontrado.
    """
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT u.*, e.*
        FROM usuarios u
        LEFT JOIN enderecos e ON u.id = e.usuario_id
        WHERE u.id = ?
    ''', (usuario_id,))
    
    resultado = cursor.fetchone()
    conn.close()
    
    if resultado is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
    return {
        'id': resultado[0],
        'nome': resultado[1],
        'email': resultado[2],
        'data_criacao': resultado[3],
        'status': resultado[4],
        'endereco': {
            'id': resultado[5],
            'cep': resultado[7],
            'logradouro': resultado[8],
            'bairro': resultado[9],
            'cidade': resultado[10],
            'estado': resultado[11]
        }
    }

def atualizar_usuario(usuario_id: int, nome: str, email: str, endereco: Dict[str, str]) -> Dict:
    """
    Atualiza os dados de um usuário existente.

    Args:
        usuario_id (int): ID do usuário a ser atualizado.
        nome (str): Novo nome do usuário.
        email (str): Novo email do usuário.
        endereco (Dict[str, str]): Dicionário com os novos dados do endereço.

    Returns:
        Dict: Dados atualizados do usuário.

    Raises:
        HTTPException: Se o usuário não for encontrado ou se o email já estiver em uso.
    """
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE usuarios 
            SET nome = ?, email = ?
            WHERE id = ?
        ''', (nome, email, usuario_id))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
        cursor.execute('''
            UPDATE enderecos 
            SET cep = ?, logradouro = ?, bairro = ?, cidade = ?, estado = ?
            WHERE usuario_id = ?
        ''', (
            endereco['cep'],
            endereco['logradouro'],
            endereco['bairro'],
            endereco['cidade'],
            endereco['estado'],
            usuario_id
        ))
            
        conn.commit()
        
        return buscar_usuario(usuario_id)
        
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email já cadastrado")
    finally:
        conn.close()

def deletar_usuario(usuario_id: int) -> Dict[str, str]:
    """
    Remove um usuário e seu endereço do banco de dados.

    Args:
        usuario_id (int): ID do usuário a ser removido.

    Returns:
        Dict[str, str]: Mensagem de sucesso.

    Raises:
        HTTPException: Se o usuário não for encontrado.
    """
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('DELETE FROM enderecos WHERE usuario_id = ?', (usuario_id,))
        cursor.execute('DELETE FROM usuarios WHERE id = ?', (usuario_id,))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
            
        conn.commit()
        
        return {"message": "Usuário deletado com sucesso"}
    finally:
        conn.close()
