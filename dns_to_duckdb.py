#!/usr/bin/env python3
"""
Módulo para importar resultados de consultas DNS para o DuckDB
"""

import json
import duckdb
import os
import sys
import argparse
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# Configuração de logging
# Criar pasta de logs se não existir
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(logs_dir, exist_ok=True)

# Configurar o logger
logger = logging.getLogger("dns_to_duckdb")
logger.setLevel(logging.INFO)

# Configurar formato para ambos os handlers
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Handler para console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)
logger.addHandler(console_handler)

# Handler para arquivo com rotação diária
log_file = os.path.join(logs_dir, 'dns_to_duckdb.log')
file_handler = TimedRotatingFileHandler(log_file, when='midnight', interval=1, backupCount=30)
file_handler.setFormatter(log_format)
file_handler.suffix = "%Y-%m-%d.log"
logger.addHandler(file_handler)

def criar_tabelas(conn):
    """
    Cria as tabelas necessárias no banco de dados DuckDB
    """
    # Apagar tabelas existentes
    conn.execute("DROP TABLE IF EXISTS registro_validacoes")
    conn.execute("DROP TABLE IF EXISTS email_avaliacao")
    conn.execute("DROP TABLE IF EXISTS registros")
    conn.execute("DROP TABLE IF EXISTS consultas")
    conn.execute("DROP TABLE IF EXISTS dominios")
    
    # Criação da tabela de domínios
    conn.execute("""
    CREATE TABLE dominios (
        id INTEGER PRIMARY KEY,
        nome VARCHAR,
        data_consulta TIMESTAMP
    )
    """)
    
    # Criação da tabela de consultas
    conn.execute("""
    CREATE TABLE consultas (
        id INTEGER PRIMARY KEY,
        dominio_id INTEGER,
        dominio VARCHAR,
        tipo_registro VARCHAR,
        status VARCHAR,
        tempo_consulta FLOAT
    )
    """)
    
    # Criação da tabela de registros
    conn.execute("""
    CREATE TABLE registros (
        id INTEGER PRIMARY KEY,
        consulta_id INTEGER,
        dominio VARCHAR,
        tipo_consulta VARCHAR,
        tipo_registro VARCHAR,
        valor VARCHAR,
        ttl INTEGER,
        flags INTEGER,
        protocol INTEGER,
        algorithm INTEGER,
        key_tag INTEGER,
        digest_type INTEGER,
        digest VARCHAR,
        tag VARCHAR,
        secure BOOLEAN,
        dnskey_value TEXT,
        selector VARCHAR,
        status VARCHAR,
        categoria VARCHAR,
        valid BOOLEAN,
        issuer VARCHAR,
        subject VARCHAR,
        valid_from TIMESTAMP,
        valid_until TIMESTAMP,
        days_remaining INTEGER,
        signature_algorithm VARCHAR,
        sans TEXT,
        redirect_from VARCHAR,
        redirect_to VARCHAR,
        redirect_status_code INTEGER,
        certificate_usage INTEGER,
        matching_type INTEGER,
        certificate_association_data TEXT
    )
    """)
    
    # Criação da tabela de validações de registros
    conn.execute("""
    CREATE TABLE registro_validacoes (
        id INTEGER PRIMARY KEY,
        registro_id INTEGER,
        dominio VARCHAR,
        tipo_registro VARCHAR,
        security_level VARCHAR,
        issues TEXT,
        recommendation TEXT
    )
    """)
    
    # Criação da tabela de avaliação geral de email
    conn.execute("""
    CREATE TABLE email_avaliacao (
        id INTEGER PRIMARY KEY,
        dominio_id INTEGER,
        dominio VARCHAR,
        security_score INTEGER,
        max_score INTEGER,
        security_level VARCHAR,
        issues TEXT,
        recommendations TEXT
    )
    """)
    
    # Criar sequências para auto incremento
    conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_dominios START WITH 1")
    conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_consultas START WITH 1")
    conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_registros START WITH 1")
    conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_validacoes START WITH 1")
    conn.execute("CREATE SEQUENCE IF NOT EXISTS seq_email_avaliacao START WITH 1")
    
    logger.info("Tabelas criadas com sucesso")

def importar_resultados(conn, json_file: str):
    """
    Importa os resultados de consultas DNS de um arquivo JSON para o DuckDB
    """
    try:
        # Carregar dados do arquivo JSON
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        data_consulta = datetime.fromisoformat(data['metadata']['timestamp'])
        
        # Para cada domínio nos resultados
        for dominio_data in data['domains']:
            nome_dominio = dominio_data['domain']
            #logger.debug(f"Processando domínio: {nome_dominio}")
            
            # Inserir domínio e gerar ID
            next_id = conn.execute("SELECT nextval('seq_dominios')").fetchone()[0]
            
            conn.execute("""
            INSERT INTO dominios (id, nome, data_consulta)
            VALUES (?, ?, ?)
            """, (next_id, nome_dominio, data_consulta))
            
            dominio_id = next_id
            
            # Para cada consulta no domínio
            for tipo_registro, consulta_data in dominio_data['queries'].items():
                # logger.debug(f"Processando consulta: {tipo_registro}")
                
                # Categorizar o tipo de registro (WEB ou EMAIL)
                categoria = "WEB"
                if tipo_registro.lower() in ["dmarc", "spf", "dkim", "email"]:
                    categoria = "EMAIL"
                
                # Para o caso especial de email com subchaves
                if tipo_registro.lower() == "email":
                    # Se tiver avaliação geral, processa primeiro
                    if "overall_assessment" in consulta_data:
                        _processar_avaliacao_email(conn, consulta_data["overall_assessment"], nome_dominio, dominio_id)
                    
                    # Processar cada subchave (spf, dmarc, dkim, dnssec)
                    for sub_tipo, sub_data in consulta_data.items():
                        if sub_tipo in ["spf", "dmarc", "dkim", "dnssec"]:
                            status = sub_data.get('status', 'unknown')
                            tempo_consulta = sub_data.get('query_time', 0)
                            
                            # Gerar ID para consulta
                            next_id = conn.execute("SELECT nextval('seq_consultas')").fetchone()[0]
                            
                            # Inserir consulta
                            conn.execute("""
                            INSERT INTO consultas (id, dominio_id, dominio, tipo_registro, status, tempo_consulta)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """, (next_id, dominio_id, nome_dominio, sub_tipo, status, tempo_consulta))
                            
                            consulta_id = next_id
                            
                            # Se for DNSSEC, verifica se é seguro
                            is_secure = None
                            if sub_tipo.lower() == 'dnssec':
                                is_secure = sub_data.get('secure', False)
                            
                            # Processar os registros desta subconsulta
                            _processar_registros(conn, sub_data, nome_dominio, sub_tipo, consulta_id, is_secure, status, categoria)
                    
                    continue  # Pular o processamento padrão para "email"
                
                status = consulta_data.get('status', 'unknown')
                tempo_consulta = consulta_data.get('query_time', 0)
                
                # Gerar ID para consulta
                next_id = conn.execute("SELECT nextval('seq_consultas')").fetchone()[0]
                
                # Inserir consulta
                conn.execute("""
                INSERT INTO consultas (id, dominio_id, dominio, tipo_registro, status, tempo_consulta)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (next_id, dominio_id, nome_dominio, tipo_registro, status, tempo_consulta))
                
                consulta_id = next_id
                
                # Se for DNSSEC, verifica se é seguro
                is_secure = None
                if tipo_registro.lower() == 'dnssec':
                    is_secure = consulta_data.get('secure', False)
                
                # Processar os registros desta consulta
                _processar_registros(conn, consulta_data, nome_dominio, tipo_registro, consulta_id, is_secure, status, categoria)
                
        logger.info(f"Importação concluída com sucesso: {json_file}")
        return True
    
    except Exception as e:
        logger.error(f"Erro ao importar dados: {str(e)}")
        raise
        return False

def _processar_registros(conn, consulta_data, nome_dominio, tipo_registro, consulta_id, is_secure, status, categoria):
    """
    Processa os registros de uma consulta e os insere no banco de dados
    """
    # Para cada registro na consulta ou inserir um registro vazio se não houver
    records = consulta_data.get('records', [])
    
    if len(records) > 0:
        # Processar registros normalmente se tiver dados
        for registro in records:
            tipo = registro.get('type', '')
            valor = registro.get('value', None)
            ttl = registro.get('ttl', None)
            flags = registro.get('flags', None)
            protocol = registro.get('protocol', None)
            algorithm = registro.get('algorithm', None)
            key_tag = registro.get('key_tag', None)
            digest_type = registro.get('digest_type', None)
            digest = registro.get('digest', None)
            tag = registro.get('tag', None)
            dnskey_value = registro.get('key', None)
            selector = registro.get('selector', None)
            is_valid = registro.get('valid', None)
            
            # Dados para REDIRECT
            redirect_from = None
            redirect_to = None
            redirect_status_code = None
            
            if tipo == "REDIRECT" and valor and isinstance(valor, list) and len(valor) > 0:
                redirect_info = valor[0]  # Pega o primeiro redirecionamento
                redirect_from = redirect_info.get('from', None)
                redirect_to = redirect_info.get('to', None)
                redirect_status_code = redirect_info.get('status_code', None)
                # Converte valor para string para armazenar no banco
                valor = json.dumps(valor)
            
            # Dados para DANE
            certificate_usage = None
            matching_type = None
            certificate_association_data = None
            
            if tipo == "DANE" and valor and isinstance(valor, list) and len(valor) > 0:
                dane_info = valor[0]  # Pega o primeiro registro TLSA
                certificate_usage = dane_info.get('certificate_usage', None)
                matching_type = dane_info.get('matching_type', None)
                certificate_association_data = dane_info.get('certificate_association_data', None)
                # Converte valor para string para armazenar no banco
                valor = json.dumps(valor)
            
            # Gerar ID para o registro
            next_id = conn.execute("SELECT nextval('seq_registros')").fetchone()[0]
            
            # Inserir registro com o status da consulta
            try:
                # Preparar valores para sans (converter lista para texto se necessário)
                sans_text = None
                if registro.get('sans') is not None:
                    if isinstance(registro.get('sans'), list):
                        sans_text = "; ".join(registro.get('sans'))
                    else:
                        sans_text = registro.get('sans')
                
                conn.execute("""
                INSERT INTO registros (
                    id, consulta_id, dominio, tipo_consulta, tipo_registro, valor, ttl, 
                    flags, protocol, algorithm, key_tag, digest_type, digest, 
                    tag, secure, dnskey_value, selector, status, categoria, valid,
                    issuer, subject, valid_from, valid_until, days_remaining, signature_algorithm, sans,
                    redirect_from, redirect_to, redirect_status_code,
                    certificate_usage, matching_type, certificate_association_data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    next_id, consulta_id, nome_dominio, tipo_registro, tipo, valor, ttl, 
                    flags, protocol, algorithm, key_tag, digest_type, digest, 
                    tag, is_secure, dnskey_value, selector, status, categoria, registro.get('is_valid', is_valid) ,
                    registro.get('issuer', None), registro.get('subject', None), 
                    registro.get('valid_from', None), registro.get('valid_until', None), 
                    registro.get('days_remaining', None), registro.get('signature_algorithm', None), 
                    sans_text,
                    redirect_from, redirect_to, redirect_status_code,
                    certificate_usage, matching_type, certificate_association_data
                ))
                
                # Se tiver informações de validação, insere na tabela de validações
                if categoria == "EMAIL" and any(k in registro for k in ['security_level', 'issues', 'recommendation']):
                    _processar_validacao(conn, next_id, nome_dominio, tipo, registro)
                
                # Processar também validações para cabeçalhos de segurança e outros
                if tipo in ["CERTIFICATE", "REDIRECT", "DANE", "CONTENT-SECURITY-POLICY", 
                           "X-FRAME-OPTIONS", "X-XSS-PROTECTION", "X-CONTENT-TYPE-OPTIONS",
                           "X-PERMITTED-CROSS-DOMAIN-POLICIES", "X-CACHE-STATUS",
                           "STRICT-TRANSPORT-SECURITY"] and any(k in registro for k in ['security_level', 'issues', 'recommendations']):
                    _processar_validacao(conn, next_id, nome_dominio, tipo, registro)
                
            except Exception as e:
                logger.warning(f"Erro ao inserir registro {tipo}: {e}")
                continue
    else:
        # Inserir um registro vazio com o status da consulta (no_records, no_answer, etc.)
        next_id = conn.execute("SELECT nextval('seq_registros')").fetchone()[0]
        
        try:
            conn.execute("""
            INSERT INTO registros (
                id, consulta_id, dominio, tipo_consulta, tipo_registro, valor, ttl, 
                flags, protocol, algorithm, key_tag, digest_type, digest, 
                tag, secure, dnskey_value, selector, status, categoria, valid,
                issuer, subject, valid_from, valid_until, days_remaining, signature_algorithm, sans,
                redirect_from, redirect_to, redirect_status_code,
                certificate_usage, matching_type, certificate_association_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                next_id, consulta_id, nome_dominio, tipo_registro, None, None, None, 
                None, None, None, None, None, None, 
                None, is_secure, None, None, status, categoria, False,
                None, None, None, None, None, None, None,
                None, None, None, None, None, None
            ))
        except Exception as e:
            logger.warning(f"Erro ao inserir registro vazio para {tipo_registro}: {e}")
    
    # Processa avaliação geral de email se for o caso
    if tipo_registro.lower() == "email" and "overall_assessment" in consulta_data:
        # Recuperar o dominio_id da consulta
        try:
            dominio_id = conn.execute("""
            SELECT dominio_id FROM consultas WHERE id = ?
            """, [consulta_id]).fetchone()[0]
            _processar_avaliacao_email(conn, consulta_data["overall_assessment"], nome_dominio, dominio_id)
        except Exception as e:
            logger.warning(f"Erro ao recuperar dominio_id para consulta {consulta_id}: {e}")

def _processar_validacao(conn, registro_id, dominio, tipo_registro, registro):
    """
    Processa e insere informações de validação para registros de email e certificados
    """
    security_level = registro.get('security_level', 'unknown')
    
    # Para registros de certificado, cabeçalhos e outros, usamos 'recommendations' ao invés de 'recommendation'
    if tipo_registro in ["CERTIFICATE", "REDIRECT", "DANE", "CONTENT-SECURITY-POLICY", 
                         "X-FRAME-OPTIONS", "X-XSS-PROTECTION", "X-CONTENT-TYPE-OPTIONS",
                         "X-PERMITTED-CROSS-DOMAIN-POLICIES", "X-CACHE-STATUS",
                         "STRICT-TRANSPORT-SECURITY"]:
        issues = registro.get('issues', [])
        recommendation = "; ".join(registro.get('recommendations', [])) if 'recommendations' in registro else None
    else:
        issues = registro.get('issues', [])
        recommendation = registro.get('recommendation', None)
    
    # Converte a lista de issues para texto
    issues_text = "; ".join(issues) if issues else None
    
    # Gerar ID para a validação
    next_id = conn.execute("SELECT nextval('seq_validacoes')").fetchone()[0]
    
    try:
        conn.execute("""
        INSERT INTO registro_validacoes (
            id, registro_id, dominio, tipo_registro, security_level, issues, recommendation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            next_id, registro_id, dominio, tipo_registro, security_level, issues_text, recommendation
        ))
    except Exception as e:
        logger.warning(f"Erro ao inserir validação para registro {registro_id}: {e}")

def _processar_avaliacao_email(conn, avaliacao, dominio, dominio_id):
    """
    Processa e insere a avaliação geral de segurança de email
    """
    # logger.debug(f"Processando avaliação de email para domínio {dominio}")
    # logger.debug(f"Avaliação recebida: {avaliacao}")
    
    # Verificar o tipo de 'avaliacao'
    if not isinstance(avaliacao, dict):
        logger.error(f"Erro: avaliacao não é um dicionário, é um {type(avaliacao)}")
        return
    
    security_score = avaliacao.get('security_score', 0)
    max_score = avaliacao.get('max_score', 10)
    security_level = avaliacao.get('security_level', 'low')
    issues = avaliacao.get('issues', [])
    recommendations = avaliacao.get('recommendations', [])
    
    # Converte as listas para texto
    issues_text = "; ".join(issues) if issues else None
    recommendations_text = "; ".join(recommendations) if recommendations else None
    
    # Gerar ID para a avaliação
    next_id = conn.execute("SELECT nextval('seq_email_avaliacao')").fetchone()[0]
    
    try:
        conn.execute("""
        INSERT INTO email_avaliacao (
            id, dominio_id, dominio, security_score, max_score, security_level, issues, recommendations
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            next_id, dominio_id, dominio, security_score, max_score, security_level, issues_text, recommendations_text
        ))
        logger.debug(f"Avaliação de email inserida com sucesso para domínio {dominio}")
    except Exception as e:
        logger.warning(f"Erro ao inserir avaliação de email para domínio {dominio}: {e}")

def criar_visualizacoes(conn):
    """
    Cria views úteis para análise dos dados
    """
    try:
        # Views existentes
        conn.execute("""
        CREATE OR REPLACE VIEW nameservers AS
        SELECT DISTINCT
            dominio, 
            valor AS nameserver
        FROM 
            registros
        WHERE 
            tipo_consulta = 'ns'
        AND 
            tipo_registro = 'NS'
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW enderecos_ip AS
        SELECT DISTINCT
            dominio, 
            tipo_registro,
            valor AS endereco_ip
        FROM 
            registros
        WHERE 
            tipo_registro IN ('A', 'AAAA')
        """)

        conn.execute("""
        CREATE OR REPLACE VIEW dnssec_status AS
        SELECT DISTINCT
            dominio,
            secure AS dnssec_seguro
        FROM 
            registros
        WHERE 
            tipo_consulta = 'dnssec'
        GROUP BY 
            dominio, secure
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW dnskeys AS
        SELECT DISTINCT
            dominio,
            flags,
            protocol,
            algorithm,
            dnskey_value
        FROM 
            registros
        WHERE 
            tipo_registro = 'DNSKEY'
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW spf_records AS
        SELECT DISTINCT
            r.dominio,
            r.valor AS spf_record,
            r.ttl,
            r.valid AS is_valid,
            v.security_level,
            v.issues,
            v.recommendation
        FROM 
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE 
            r.tipo_registro = 'SPF'
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW dmarc_records AS
        SELECT DISTINCT
            r.dominio,
            r.valor AS dmarc_record,
            r.ttl,
            r.valid AS is_valid,
            v.security_level,
            v.issues,
            v.recommendation
        FROM 
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE 
            r.tipo_registro = 'DMARC'
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW dkim_records AS
        SELECT DISTINCT
            r.dominio,
            r.selector,
            r.valor AS dkim_record,
            r.ttl,
            r.valid AS is_valid,
            v.security_level,
            v.issues,
            v.recommendation
        FROM 
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE 
            r.tipo_registro = 'DKIM'
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW status_estatisticas AS
        SELECT DISTINCT
            tipo_consulta,
            status,
            COUNT(*) AS quantidade
        FROM 
            registros
        GROUP BY 
            tipo_consulta, status
        ORDER BY 
            tipo_consulta, quantidade DESC
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW categoria_estatisticas AS
        SELECT DISTINCT
            categoria,
            tipo_consulta,
            COUNT(DISTINCT dominio) AS dominios_count
        FROM 
            registros
        GROUP BY 
            categoria, tipo_consulta
        ORDER BY 
            categoria, dominios_count DESC
        """)
        
        # View atualizada com informações de validação
        conn.execute("""
        CREATE OR REPLACE VIEW email_seguranca AS
        SELECT DISTINCT
            d.nome AS dominio,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'SPF') AS tem_spf,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'DMARC') AS tem_dmarc,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'DKIM') AS tem_dkim,
            (SELECT secure FROM registros WHERE dominio = d.nome AND tipo_consulta = 'dnssec' LIMIT 1) AS dnssec_seguro,
            (SELECT security_level FROM registro_validacoes 
              WHERE dominio = d.nome AND tipo_registro = 'SPF' LIMIT 1) AS spf_security_level,
            (SELECT security_level FROM registro_validacoes 
              WHERE dominio = d.nome AND tipo_registro = 'DMARC' LIMIT 1) AS dmarc_security_level,
            (SELECT security_level FROM registro_validacoes 
              WHERE dominio = d.nome AND tipo_registro = 'DKIM' LIMIT 1) AS dkim_security_level,
            (SELECT security_level FROM email_avaliacao 
              WHERE dominio = d.nome LIMIT 1) AS overall_security_level,
            (SELECT security_score FROM email_avaliacao 
              WHERE dominio = d.nome LIMIT 1) AS security_score
        FROM 
            dominios d
        """)
        
        # Nova view para análise detalhada de segurança de email
        conn.execute("""
        CREATE OR REPLACE VIEW email_seguranca_detalhada AS
        SELECT DISTINCT
            e.dominio,
            e.security_score,
            e.max_score,
            e.security_level,
            e.issues,
            e.recommendations,
            spf.spf_record,
            spf.security_level AS spf_security_level,
            spf.issues AS spf_issues,
            spf.recommendation AS spf_recommendation,
            dmarc.dmarc_record,
            dmarc.security_level AS dmarc_security_level,
            dmarc.issues AS dmarc_issues,
            dmarc.recommendation AS dmarc_recommendation,
            (SELECT GROUP_CONCAT(selector || ': ' || dkim_record, '; ') 
             FROM dkim_records WHERE dominio = e.dominio) AS dkim_records,
            (SELECT security_level FROM dkim_records WHERE dominio = e.dominio LIMIT 1) AS dkim_security_level,
            (SELECT issues FROM dkim_records WHERE dominio = e.dominio LIMIT 1) AS dkim_issues,
            (SELECT recommendation FROM dkim_records WHERE dominio = e.dominio LIMIT 1) AS dkim_recommendation,
            dns.dnssec_seguro
        FROM 
            email_avaliacao e
        LEFT JOIN 
            spf_records spf ON e.dominio = spf.dominio
        LEFT JOIN 
            dmarc_records dmarc ON e.dominio = dmarc.dominio
        LEFT JOIN 
            dnssec_status dns ON e.dominio = dns.dominio
        """)
        
        # Nova view para relatório de conformidade de email
        conn.execute("""
        CREATE OR REPLACE VIEW email_conformidade AS
        SELECT DISTINCT
            dominio,
            CASE 
                WHEN tem_spf AND tem_dmarc AND tem_dkim AND dnssec_seguro THEN 'Completa'
                WHEN tem_spf AND tem_dmarc AND tem_dkim THEN 'Boa'
                WHEN tem_spf AND tem_dmarc THEN 'Básica'
                WHEN tem_spf OR tem_dmarc OR tem_dkim THEN 'Parcial'
                ELSE 'Nenhuma'
            END AS conformidade,
            CASE 
                WHEN overall_security_level = 'high' THEN 'Alta'
                WHEN overall_security_level = 'medium' THEN 'Média'
                WHEN overall_security_level = 'low' THEN 'Baixa'
                ELSE 'Desconhecida'
            END AS seguranca,
            security_score,
            spf_security_level,
            dmarc_security_level,
            dkim_security_level
        FROM 
            email_seguranca
        ORDER BY 
            security_score DESC
        """)
        
        conn.execute("""
        CREATE OR REPLACE VIEW certificates AS
        SELECT DISTINCT
            r.dominio,
            issuer,
            subject,
            valid_from,
            valid_until,
            days_remaining,
            signature_algorithm,
            sans,
            valid AS is_valid,
            security_level,
            v.issues,
            v.recommendation
        FROM 
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE 
            r.tipo_registro = 'CERTIFICATE'
        """)
        
        # Nova view para análise de redirecionamentos
        conn.execute("""
        CREATE OR REPLACE VIEW redirects AS
        SELECT
            r.dominio,
            redirect_from,
            redirect_to,
            redirect_status_code,
            v.security_level,
            v.issues,
            v.recommendation
        FROM
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE
            r.tipo_registro = 'REDIRECT'
        """)
        
        # Nova view para análise DANE
        conn.execute("""
        CREATE OR REPLACE VIEW dane_records AS
        SELECT
            r.dominio,
            certificate_usage,
            matching_type,
            certificate_association_data,
            v.security_level,
            v.issues,
            v.recommendation
        FROM
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE
            r.tipo_registro = 'DANE'
        """)
        
        # Nova view para análise de cabeçalhos HTTP
        conn.execute("""
        CREATE OR REPLACE VIEW security_headers AS
        SELECT
            r.dominio,
            r.tipo_registro AS header,
            r.valor AS value,
            v.security_level,
            v.issues,
            v.recommendation
        FROM
            registros r
        LEFT JOIN
            registro_validacoes v ON r.id = v.registro_id
        WHERE
            r.tipo_registro IN (
                'CONTENT-SECURITY-POLICY',
                'X-FRAME-OPTIONS',
                'X-XSS-PROTECTION',
                'X-CONTENT-TYPE-OPTIONS',
                'X-PERMITTED-CROSS-DOMAIN-POLICIES',
                'X-CACHE-STATUS',
                'STRICT-TRANSPORT-SECURITY'
            )
        ORDER BY
            r.dominio, r.tipo_registro
        """)
        
        # View para avaliação de segurança web
        conn.execute("""
        CREATE OR REPLACE VIEW web_seguranca AS
        SELECT DISTINCT
            d.nome AS dominio,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'CERTIFICATE' AND valid = TRUE) AS tem_certificado_valido,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'REDIRECT' AND valor LIKE '%https://%') AS tem_redirect_https,
            (SELECT COUNT(*) > 0 FROM registro_validacoes WHERE tipo_registro = 'DANE' AND security_level != 'none' AND dominio = d.nome) AS tem_dane,
            (SELECT COUNT(*) > 0 FROM registros WHERE dominio = d.nome AND tipo_registro = 'STRICT-TRANSPORT-SECURITY') AS tem_hsts,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE r.dominio = d.nome AND tipo_registro = 'CONTENT-SECURITY-POLICY') AS tem_csp,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE dominio = d.nome AND tipo_registro = 'X-FRAME-OPTIONS') AS tem_x_frame_options,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE dominio = d.nome AND tipo_registro = 'X-XSS-PROTECTION') AS tem_x_xss_protection,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE dominio = d.nome AND tipo_registro = 'X-CONTENT-TYPE-OPTIONS') AS tem_x_content_type_options,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE dominio = d.nome AND tipo_registro = 'X-PERMITTED-CROSS-DOMAIN-POLICIES') AS tem_x_permitted_cross_domain_policies,
            (SELECT COUNT(r.valor) > 0 FROM registros r WHERE dominio = d.nome AND tipo_registro = 'X-CACHE-STATUS') AS tem_x_cache_status,
            (SELECT secure FROM registros WHERE dominio = d.nome AND tipo_consulta = 'dnssec' LIMIT 1) AS dnssec_seguro,
            (SELECT 
                CASE 
                    WHEN COUNT(*) >= 5 THEN 'high'
                    WHEN COUNT(*) >= 3 THEN 'medium'
                    ELSE 'low'
                END
            FROM registros 
            WHERE dominio = d.nome 
            AND tipo_registro IN (
                'CONTENT-SECURITY-POLICY',
                'X-FRAME-OPTIONS',
                'X-XSS-PROTECTION',
                'X-CONTENT-TYPE-OPTIONS',
                'STRICT-TRANSPORT-SECURITY',
                'X-PERMITTED-CROSS-DOMAIN-POLICIES',
                'X-CACHE-STATUS'
            )
            AND valor IS NOT NULL) AS headers_security_level
        FROM 
            dominios d

        """)
        
        logger.info("Views criadas com sucesso")
    except Exception as e:
        logger.error(f"Erro ao criar views: {e}")

def executar_consultas(conn):
    """
    Executa algumas consultas de exemplo para mostrar os dados
    """
    try:
        # Consultas existentes
        logger.info("Domínios com DNSSEC habilitado:")
        result = conn.execute("""
        SELECT dominio 
        FROM consultas 
        WHERE tipo_registro = 'dnssec' 
        AND status = 'success' 
        LIMIT 5
        """).fetchall()
        
        for row in result:
            logger.info(f"- {row[0]}")
        
        # Estatísticas de segurança de email atualizadas
        logger.info("Estatísticas de segurança de email:")
        result = conn.execute("""
        SELECT 
            COUNT(*) AS total_dominios,
            SUM(CASE WHEN tem_spf THEN 1 ELSE 0 END) AS com_spf,
            SUM(CASE WHEN tem_dmarc THEN 1 ELSE 0 END) AS com_dmarc,
            SUM(CASE WHEN tem_dkim THEN 1 ELSE 0 END) AS com_dkim,
            SUM(CASE WHEN dnssec_seguro THEN 1 ELSE 0 END) AS com_dnssec_seguro,
            SUM(CASE WHEN overall_security_level = 'high' THEN 1 ELSE 0 END) AS alta_seguranca,
            SUM(CASE WHEN overall_security_level = 'medium' THEN 1 ELSE 0 END) AS media_seguranca,
            SUM(CASE WHEN overall_security_level = 'low' THEN 1 ELSE 0 END) AS baixa_seguranca,
            AVG(security_score) AS media_pontuacao
        FROM 
            email_seguranca
        """).fetchone()
        
        total, spf, dmarc, dkim, dnssec, alta, media, baixa, score_medio = result
        if total > 0:
            logger.info(f"- Total de domínios: {total}")
            logger.info(f"- Com SPF: {spf} ({spf/total*100:.1f}%)")
            logger.info(f"- Com DMARC: {dmarc} ({dmarc/total*100:.1f}%)")
            logger.info(f"- Com DKIM: {dkim} ({dkim/total*100:.1f}%)")
            logger.info(f"- Com DNSSEC seguro: {dnssec} ({dnssec/total*100:.1f}%)")
            logger.info(f"- Segurança alta: {alta} ({alta/total*100:.1f}%)")
            logger.info(f"- Segurança média: {media} ({media/total*100:.1f}%)")
            logger.info(f"- Segurança baixa: {baixa} ({baixa/total*100:.1f}%)")
            logger.info(f"- Pontuação média: {score_medio:.1f}/10")
        
        # Nova consulta: Relatório de conformidade
        logger.info("\nRelatório de conformidade de email:")
        result = conn.execute("""
        SELECT conformidade, COUNT(*) as count
        FROM email_conformidade
        GROUP BY conformidade
        ORDER BY 
            CASE 
                WHEN conformidade = 'Completa' THEN 1
                WHEN conformidade = 'Boa' THEN 2
                WHEN conformidade = 'Básica' THEN 3
                WHEN conformidade = 'Parcial' THEN 4
                ELSE 5
            END
        """).fetchall()
        
        for conformidade, count in result:
            logger.info(f"- {conformidade}: {count} domínios")
        
        # Nova consulta: Top 5 domínios mais seguros
        logger.info("\nTop 5 domínios mais seguros:")
        result = conn.execute("""
        SELECT 
            dominio, 
            security_score, 
            seguranca
        FROM 
            email_conformidade
        ORDER BY 
            security_score DESC
        LIMIT 5
        """).fetchall()
        
        for dominio, score, nivel in result:
            logger.info(f"- {dominio}: {score}/10 (Segurança {nivel})")
        
        # Problemas mais comuns
        logger.info("\nProblemas mais comuns:")
        result = conn.execute("""
        SELECT issues, COUNT(*) as count
        FROM (
            SELECT DISTINCT dominio, issues FROM registro_validacoes
            WHERE issues IS NOT NULL
        ) t
        GROUP BY issues
        ORDER BY count DESC
        LIMIT 5
        """).fetchall()
        
        for issue, count in result:
            logger.info(f"- {issue}: {count} domínios")
        
        # Nova consulta: Estatísticas de cabeçalhos de segurança
        try:
            logger.info("\nEstatísticas de cabeçalhos de segurança HTTP:")
            result = conn.execute("""
            SELECT 
                header, 
                COUNT(*) as total,
                SUM(CASE WHEN value IS NOT NULL THEN 1 ELSE 0 END) as implementados,
                ROUND(SUM(CASE WHEN value IS NOT NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as porcentagem
            FROM 
                security_headers
            GROUP BY 
                header
            ORDER BY 
                implementados DESC
            """).fetchall()
            
            for header, total, implementados, porcentagem in result:
                logger.info(f"- {header}: {implementados}/{total} ({porcentagem}%)")
        except Exception as e:
            logger.warning(f"Erro ao consultar estatísticas de cabeçalhos: {e}")
        
        # Nova consulta: Estatísticas de redirecionamentos
        try:
            logger.info("\nEstatísticas de redirecionamentos:")
            result = conn.execute("""
            SELECT 
                COUNT(*) as total_dominios,
                SUM(CASE WHEN redirect_to LIKE 'https://%' THEN 1 ELSE 0 END) as redirecionam_para_https,
                SUM(CASE WHEN redirect_status_code = 301 THEN 1 ELSE 0 END) as redirecionamento_permanente
            FROM 
                redirects
            """).fetchone()
            
            total, https, permanente = result
            if total > 0:
                logger.info(f"- Total de domínios com redirecionamento: {total}")
                logger.info(f"- Redirecionam para HTTPS: {https} ({https/total*100:.1f}%)")
                logger.info(f"- Usam redirecionamento permanente (301): {permanente} ({permanente/total*100:.1f}%)")
        except Exception as e:
            logger.warning(f"Erro ao consultar estatísticas de redirecionamentos: {e}")
        
        # Nova consulta: DANE
        try:
            logger.info("\nEstatísticas de DANE:")
            result = conn.execute("""
            SELECT COUNT(*) FROM dane_records
            """).fetchone()[0]
            
            logger.info(f"- Domínios com DANE configurado: {result}")
        except Exception as e:
            logger.warning(f"Erro ao consultar estatísticas de DANE: {e}")
        
        # Avaliação geral de segurança web
        logger.info("\nAvaliação geral de segurança web:")
        result = conn.execute("""
        SELECT 
            COUNT(*) AS total_dominios,
            SUM(CASE WHEN tem_certificado_valido THEN 1 ELSE 0 END) AS com_certificado_valido,
            SUM(CASE WHEN tem_redirect_https THEN 1 ELSE 0 END) AS com_redirect_https,
            SUM(CASE WHEN tem_dane THEN 1 ELSE 0 END) AS com_dane,
            SUM(CASE WHEN tem_hsts THEN 1 ELSE 0 END) AS com_hsts,
            SUM(CASE WHEN tem_csp THEN 1 ELSE 0 END) AS com_csp,
            SUM(CASE WHEN tem_x_frame_options THEN 1 ELSE 0 END) AS com_x_frame_options,
            SUM(CASE WHEN tem_x_xss_protection THEN 1 ELSE 0 END) AS com_x_xss_protection,
            SUM(CASE WHEN tem_x_content_type_options THEN 1 ELSE 0 END) AS com_x_content_type_options,
            SUM(CASE WHEN tem_x_permitted_cross_domain_policies THEN 1 ELSE 0 END) AS com_x_permitted_policies,
            SUM(CASE WHEN tem_x_cache_status THEN 1 ELSE 0 END) AS com_x_cache_status,
            SUM(CASE WHEN dnssec_seguro THEN 1 ELSE 0 END) AS com_dnssec_seguro,
            SUM(CASE WHEN headers_security_level = 'high' THEN 1 ELSE 0 END) AS alta_seguranca_headers,
            SUM(CASE WHEN headers_security_level = 'medium' THEN 1 ELSE 0 END) AS media_seguranca_headers,
            SUM(CASE WHEN headers_security_level = 'low' THEN 1 ELSE 0 END) AS baixa_seguranca_headers
        FROM 
            web_seguranca
        """).fetchone()
        
        total, cert, redirect, dane, hsts, csp, x_frame, x_xss, x_content, x_permitted, x_cache, dnssec, alta, media, baixa = result
        if total > 0:
            logger.info(f"- Total de domínios: {total}")
            logger.info(f"- Com certificado válido: {cert} ({cert/total*100:.1f}%)")
            logger.info(f"- Com redirecionamento para HTTPS: {redirect} ({redirect/total*100:.1f}%)")
            logger.info(f"- Com DANE: {dane} ({dane/total*100:.1f}%)")
            logger.info(f"- Com HSTS: {hsts} ({hsts/total*100:.1f}%)")
            logger.info(f"- Com CSP: {csp} ({csp/total*100:.1f}%)")
            logger.info(f"- Com X-Frame-Options: {x_frame} ({x_frame/total*100:.1f}%)")
            logger.info(f"- Com X-XSS-Protection: {x_xss} ({x_xss/total*100:.1f}%)")
            logger.info(f"- Com X-Content-Type-Options: {x_content} ({x_content/total*100:.1f}%)")
            logger.info(f"- Com X-Permitted-Cross-Domain-Policies: {x_permitted} ({x_permitted/total*100:.1f}%)")
            logger.info(f"- Com X-Cache-Status: {x_cache} ({x_cache/total*100:.1f}%)")
            logger.info(f"- Com DNSSEC seguro: {dnssec} ({dnssec/total*100:.1f}%)")
            logger.info(f"- Segurança de cabeçalhos alta: {alta} ({alta/total*100:.1f}%)")
            logger.info(f"- Segurança de cabeçalhos média: {media} ({media/total*100:.1f}%)")
            logger.info(f"- Segurança de cabeçalhos baixa: {baixa} ({baixa/total*100:.1f}%)")
        
    except Exception as e:
        logger.error(f"Erro ao executar consultas: {e}")

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Importador de resultados DNS para DuckDB")
    parser.add_argument("json_file", help="Arquivo JSON com resultados de consultas DNS")
    parser.add_argument("--db", default="dns_explorer.db", help="Arquivo de banco de dados DuckDB (padrão: dns_explorer.db)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Modo verboso")
    
    args = parser.parse_args()
    
    # Configurar nível de log baseado em verbose
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Verificar se o arquivo JSON existe
    if not os.path.isfile(args.json_file):
        logger.error(f"Arquivo não encontrado: {args.json_file}")
        return 1
    
    # Conectar ao banco de dados DuckDB
    try:
        # Verificar se o arquivo existe antes de tentar removê-lo
        if os.path.exists(args.db):
            try:
                os.remove(args.db)
                logger.info(f"Arquivo de banco de dados antigo removido: {args.db}")
            except PermissionError:
                logger.warning(f"Não foi possível remover o arquivo de banco de dados: {args.db}. Arquivo pode estar em uso por outro processo.")
                logger.warning("Tentando conectar mesmo assim...")
        
        conn = duckdb.connect(args.db)
        
        # Criar tabelas
        criar_tabelas(conn)
        
        # Importar resultados
        if importar_resultados(conn, args.json_file):
            # Criar visualizações úteis
            criar_visualizacoes(conn)
            
            # Mostrar alguns dados
            registro_count = conn.execute("SELECT COUNT(*) FROM registros").fetchone()[0]
            dominio_count = conn.execute("SELECT COUNT(*) FROM dominios").fetchone()[0]
            consulta_count = conn.execute("SELECT COUNT(*) FROM consultas").fetchone()[0]
            
            logger.info(f"Total de domínios importados: {dominio_count}")
            logger.info(f"Total de consultas: {consulta_count}")
            logger.info(f"Total de registros importados: {registro_count}")
            
            # Executar algumas consultas de exemplo
            executar_consultas(conn)
            
            conn.close()
            logger.info(f"Dados importados com sucesso para {args.db}")
            return 0
        else:
            conn.close()
            return 1
    
    except Exception as e:
        logger.error(f"Erro ao processar: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 