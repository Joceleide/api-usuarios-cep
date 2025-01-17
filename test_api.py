# test_api.py
from fastapi.testclient import TestClient
from main import app
import pytest
from typing import Dict, Any

client = TestClient(app)

def test_criar_usuario() -> None:
    """
    Testa a criação do primeiro usuário do sistema através da rota /primeiro-usuario/.
    
    Verifica se:
    - A requisição retorna status code 200
    - O email do usuário criado corresponde ao enviado
    
    Returns:
        None
        
    Raises:
        AssertionError: Se os testes falharem
    """
    response = client.post(
        "/primeiro-usuario/",
        json={
            "nome": "Test User",
            "email": "test@example.com",
            "senha": "Test123@",
            "cep": "01001-000"
        }
    )
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"