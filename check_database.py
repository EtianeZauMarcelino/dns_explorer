#!/usr/bin/env python3
"""
Script para verificar tabelas e dados do banco de dados
"""

import os
from report.modules.database import DBManager

def check_database():
    """
    Verifica se existem dados nas tabelas do banco de dados
    """
    # Verificar possíveis caminhos para o banco de dados
    possible_paths = [
        "./dns_explorer.db",
        "./dns_explorer_v6.db",
        "./dns_explorer_v5.db",
        "./dns_explorer_v4.db",
        "./dns_explorer_v3.db",
        "./dns_explorer_v2.db",
        "./dns_explorer_v1.db",
        "./teste_dns.db",
        "./dados.db",
        "./data/dados.db",
        "./database/dados.db",
        "./report/data/dados.db",
        "./db/dados.db"
    ]
    
    db_path = None
    for path in possible_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if db_path is None:
        print("Arquivo de banco de dados não encontrado!")
        # Listar arquivos .db no diretório atual e subdiretorios
        print("\nProcurando arquivos .db:")
        for root, _, files in os.walk(".", topdown=True):
            for file in files:
                if file.endswith(".db"):
                    print(f"- {os.path.join(root, file)}")
        return
    
    print(f"Usando banco de dados: {db_path}")
    db = DBManager(db_path)
    
    # Listar todas as tabelas
    tables_query = """
                    SELECT name FROM sqlite_master WHERE type='table'
                    UNION 
                    SELECT name FROM sqlite_master WHERE type='view'
    """
    tables = db.execute_query(tables_query)
    
    print("\nTabelas disponíveis:")
    for _, row in tables.iterrows():
        print(f"- {row['name']}")
    
    # Verificar a estrutura de tabelas importantes para depuração
    print("\nVERIFICANDO ESTRUTURA DE TABELAS IMPORTANTES:")
    
    # Estrutura da tabela dominios
    try:
        dominios_schema = db.execute_query("PRAGMA table_info(dominios);")
        print("\nEstrutura da tabela dominios:")
        for _, row in dominios_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
    except Exception as e:
        print(f"\nErro ao consultar estrutura da tabela dominios: {str(e)}")
    
    # Verificar se a tabela web_avaliacao existe
    try:
        web_avaliacao_schema = db.execute_query("PRAGMA table_info(web_avaliacao);")
        print("\nEstrutura da tabela web_avaliacao:")
        for _, row in web_avaliacao_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
    except Exception as e:
        print(f"\nErro ao consultar estrutura da tabela web_avaliacao: {str(e)}")
    
    # Verificar se a tabela web_seguranca existe
    try:
        web_seguranca_schema = db.execute_query("PRAGMA table_info(web_seguranca);")
        print("\nEstrutura da tabela web_seguranca:")
        for _, row in web_seguranca_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
    except Exception as e:
        print(f"\nErro ao consultar estrutura da tabela web_seguranca: {str(e)}")
    
    # Verificar estrutura da tabela email_avaliacao
    try:
        email_avaliacao_schema = db.execute_query("PRAGMA table_info(email_avaliacao);")
        print("\nEstrutura da tabela email_avaliacao:")
        for _, row in email_avaliacao_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
    except Exception as e:
        print(f"\nErro ao consultar estrutura da tabela email_avaliacao: {str(e)}")
    
    # Verificar a tabela registros
    try:
        registros_schema = db.execute_query("PRAGMA table_info(registros);")
        print("\nEstrutura da tabela registros:")
        for _, row in registros_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
        
        # Verificar amostra de dados da tabela registros
        registros_sample = db.execute_query("SELECT * FROM registros LIMIT 5;")
        print("\nAmostra de dados da tabela registros:")
        print(registros_sample)
    except Exception as e:
        print(f"\nErro ao consultar tabela registros: {str(e)}")
    
    # Verificar a tabela registro_validacoes
    try:
        validacoes_schema = db.execute_query("PRAGMA table_info(registro_validacoes);")
        print("\nEstrutura da tabela registro_validacoes:")
        for _, row in validacoes_schema.iterrows():
            print(f"- {row['name']} ({row['type']})")
        
        # Verificar amostra de dados da tabela registro_validacoes
        validacoes_sample = db.execute_query("SELECT * FROM registro_validacoes LIMIT 5;")
        print("\nAmostra de dados da tabela registro_validacoes:")
        print(validacoes_sample)
    except Exception as e:
        print(f"\nErro ao consultar tabela registro_validacoes: {str(e)}")

if __name__ == "__main__":
    check_database() 