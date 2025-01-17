from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from CEP_api import router as cep_api  
from database import criar_tabelas
import logging
import json
from datetime import datetime
import structlog

# Configuração do logging estruturado
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

# Cria uma nova instância do FastAPI
app = FastAPI(
    title="API de Usuários e CEP",
    description="",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Inclui as rotas da API de CEP
app.include_router(cep_api)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="API de Usuários e CEP",
        version="1.0.0",
        description="""
    API para gerenciamento de usuários e consulta de CEPs.
    
    ## Funcionalidades
    
    * Autenticação de usuários
    * Criação e listagem de usuários
    * Consulta automática de endereços via CEP
    
    ## Autenticação
    
    Para usar a API, você precisa:
    1. Criar um usuário
    2. Fazer login para obter um token
    3. Usar o token no header Authorization
    """,
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Evento de inicialização
@app.on_event("startup")
async def startup_event():
    """
    Executa ações necessárias na inicialização do servidor
    """
    logger.info("server_startup", status="initializing")
    try:
        # Cria as tabelas do banco de dados
        criar_tabelas()
        logger.info("database_tables_created", status="success")
    except Exception as e:
        logger.error("database_tables_creation_failed", 
                    error=str(e),
                    error_type=type(e).__name__,
                    status="failed")
        raise

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)